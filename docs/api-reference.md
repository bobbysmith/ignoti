# API reference

---

## Setup

### `new Ignoti(options)`

Creates a Ignoti instance. One instance per app.

```ts
const ignoti = new Ignoti({
  backendUrl: 'https://your-ignoti-server.example.com',
});
```

**Parameters**

| Name                | Type     | Required | Description                                                                                       |
|---------------------|----------|----------|---------------------------------------------------------------------------------------------------|
| `backendUrl`        | `string` | yes      | Base URL of your Ignoti server                                                                   |
| `defaultDeviceName` | `string` | no       | Human-readable name for newly registered devices. If omitted, the SDK guesses from the user agent |
| `apiClientOptions`  | `object` | no       | Low-level HTTP client options: `timeout` (ms), `retryAttempts`                                    |

---

### `ignoti.init()`

Marks the instance as initialized. Must be called before any method that touches identity or session state; those throw `NOT_INITIALIZED` if called first. The exception is `onSessionChange()`, which is designed to be registered before `init()` so you do not miss the initial session transition.

```ts
ignoti.init();
```

Returns: `void`

---

### `ignoti.onSessionChange(callback)`

Registers a callback that fires on every session transition. The callback is **not** invoked on registration with the current state - it only fires on subsequent transitions. Register it before your first `restoreSession()`/`login()` call so you do not miss that first transition.

Only one callback is held: calling `onSessionChange` again replaces the previous callback rather than adding a second subscriber. Register it once.

```ts
ignoti.onSessionChange(session => {
  if (session) {
    // logged in
  } else {
    // logged out
  }
});
```

Fires on: `login()` (on success), `logout()`, `restoreSession()` (on success only - a failed restore throws 
`NO_KEYS` and does not fire), `revokeAllSessions()`, the silent session refresh after a 401 (which runs `restoreSession()` internally), `revokeSession()`/`revokeDevice()` when the revoked session or device is the current one, and lazily with `null` the first time `getSession()` is called after the in-memory session has passed its expiry.

**Parameters**

| Name       | Type                                     | Description                       |
|------------|------------------------------------------|-----------------------------------|
| `callback` | `(session: SessionInfo \| null) => void` | Called with the new session state |

Returns: `void`

---

## Identity

### `ignoti.createIdentity()`

Creates a new user identity. Generates a 12-word mnemonic, derives a root keypair, and registers a passkey on the current device. Does not create a session - call `login()` afterward to authenticate.

```ts
const { mnemonic, userId, deviceId } = await ignoti.createIdentity();
// show mnemonic to user - it will not be shown again
```

Returns: `Promise<CreateIdentityResult>`

Throws:
- `NOT_INITIALIZED` - `init()` was not called
- `INVALID_INPUT` - WebAuthn is not supported, or the user cancelled the passkey prompt
- `CRYPTOGRAPHY_ERROR` - passkey creation failed
- `API_ERROR` - server error (check `httpStatus`)

---

### `ignoti.recoverIdentity(mnemonic)`

Recovers an existing identity on a new device using the 12-word recovery phrase. Registers the current device's passkey under the existing account. Does not create a session - call `login()` after.

```ts
await ignoti.recoverIdentity(words.join(' '));
const session = await ignoti.login();
```

**Parameters**

| Name       | Type     | Description                  |
|------------|----------|------------------------------|
| `mnemonic` | `string` | 12 words separated by spaces |

Returns: `Promise<RecoverIdentityResult>`

Throws:
- `NOT_INITIALIZED`
- `INVALID_INPUT` - invalid mnemonic phrase, no account matches the mnemonic, WebAuthn is not supported, or the user cancelled the passkey prompt
- `CRYPTOGRAPHY_ERROR` - passkey creation failed
- `API_ERROR` - server error

A wrong or unknown recovery phrase throws `INVALID_INPUT` before any passkey prompt, so no orphan credential is created in the authenticator.

---

### `ignoti.recoverAndLogin(mnemonic)`

Convenience method that calls `recoverIdentity()` then `login()` in sequence.

**Parameters**

| Name       | Type     | Description                  |
|------------|----------|------------------------------|
| `mnemonic` | `string` | 12 words separated by spaces |

Returns: `Promise<SessionInfo>`

Throws: same as `recoverIdentity()` and `login()`

---

## Authentication

### `ignoti.login()`

Authenticates with the registered passkey on this device. Prompts the user to verify with biometric or PIN, generates an ephemeral session keypair, and binds it to the server.

```ts
const session = await ignoti.login();
```

Returns: `Promise<SessionInfo>`

Throws:
- `NOT_INITIALIZED`
- `INVALID_INPUT` - WebAuthn is not supported, or the user cancelled the passkey prompt
- `CRYPTOGRAPHY_ERROR` - passkey assertion failed
- `API_ERROR` - challenge request or login request failed

---

### `ignoti.logout()`

Revokes the current session on the server, then clears local state and fires `onSessionChange(null)`. Local state is cleared **only after** the server confirms revocation. If the server call fails, the error is thrown and the session is left intact — the user stays logged in. Nothing is hidden: handle the error and decide whether to retry (calling `logout()` again). Await success before showing a logged-out UI.

No-op if not logged in.

```ts
try {
  await ignoti.logout();
  // logged out — server session revoked, cookie cleared
} catch (err) {
  // still logged in — revocation did not complete; surface and offer retry
}
```

Returns: `Promise<void>`

Throws:
- `NOT_INITIALIZED`
- `API_ERROR` - server revocation failed; the session is unchanged (still logged in)

---

### `ignoti.restoreSession()`

Restores a session after a page reload using the httpOnly session cookie. Generates a fresh ephemeral keypair and binds it to the server. Concurrent calls within a page are single-flighted (they share one attempt), so calling it more than once is safe.

In React, a `useRef` guard is optional — it avoids a redundant second call under Strict Mode double-invocation:

```ts
const restored = useRef(false);

useEffect(() => {
  if (restored.current) return;
  restored.current = true;
  ignoti.restoreSession().catch(() => {});
}, []);
```

Returns: `Promise<void>`

Throws:
- `NOT_INITIALIZED`
- `NO_KEYS` - no active session cookie, or session was expired or revoked
- `API_ERROR` - network failure or non-401 server error

---

## Session

### `ignoti.getSession()`

Returns the current session info, or `null` if not authenticated. Synchronous. If the in-memory session has passed its expiry, it is cleared on this call: `getSession()` returns `null` and `onSessionChange` fires once with `null`.

```ts
const session = ignoti.getSession();
if (session) {
  console.log(session.userId);
}
```

Returns: `SessionInfo | null`

---

### `ignoti.isSessionExpired()`

Returns `true` if the current session has passed its expiry time, or if there is no session. Synchronous.

Returns: `boolean`

---

### `ignoti.getSessionHeaders(method, path)`

Returns signed headers to attach to an authenticated request to your backend. The method and path must match the request exactly.

```ts
const headers = await ignoti.getSessionHeaders('GET', '/api/feed');
const res = await fetch('https://api.example.com/api/feed', { headers });
```

If the session is expired, automatically attempts to restore it before signing. Do not cache the result - each call generates a fresh signature with a unique nonce.

Your backend validates these headers by forwarding them to the Ignoti server's `POST /api/sessions/verify` endpoint, which returns the authenticated `userId` on success. See [getting started, section 7](./getting-started.md#7-make-authenticated-requests) for a full example.

**Parameters**

| Name     | Type     | Description                                                  |
|----------|----------|--------------------------------------------------------------|
| `method` | `string` | HTTP method of the request (`GET`, `POST`, etc.)             |
| `path`   | `string` | Path of the request, exactly as your backend will receive it |

Returns: `Promise<Record<string, string>>`

Throws:
- `NOT_INITIALIZED`
- `NO_KEYS` - no active session (also if the automatic restore of an expired session fails)
- `API_ERROR` - network failure or server error during the automatic restore of an expired session

---

## Devices

### `ignoti.getDevices()`

Returns the list of active devices registered to the current user.

Returns: `Promise<DeviceInfo[]>`

Throws:
- `NOT_INITIALIZED`
- `NO_KEYS` - not logged in
- `CLOCK_SKEW` - device clock is too far off the server's
- `API_ERROR` - network failure or server error

---

### `ignoti.revokeDevice(deviceId, mnemonic, userId, credentialId)`

Revokes a device and all its active sessions atomically. Authorized entirely by the recovery mnemonic (a root-key signature), so it does **not** require an active session - a user who has lost access to all their sessions can still revoke a device. Revoking the current device clears local state and fires `onSessionChange`.

```ts
await ignoti.revokeDevice(device.id, mnemonic, session.userId, device.credentialId);
```

**Parameters**

| Name           | Type     | Description                                                     |
|----------------|----------|-----------------------------------------------------------------|
| `deviceId`     | `string` | From `getDevices()`                                             |
| `mnemonic`     | `string` | 12 words separated by spaces                                    |
| `userId`       | `string` | From `getSession()`, `createIdentity()`, or `recoverIdentity()` |
| `credentialId` | `string` | From `getDevices()`                                             |

Returns: `Promise<void>`

Throws:
- `NOT_INITIALIZED`
- `INVALID_INPUT` - invalid mnemonic phrase
- `INVALID_SIGNATURE` - the mnemonic does not match this account (root signature rejected)
- `API_ERROR` - device not found or other server error

---

## Sessions

### `ignoti.getSessions()`

Returns the list of active sessions for the current user across all devices.

Returns: `Promise<SessionListItem[]>`

Throws:
- `NOT_INITIALIZED`
- `NO_KEYS` - not logged in
- `CLOCK_SKEW` - device clock is too far off the server's
- `API_ERROR` - network failure or server error

---

### `ignoti.revokeSession(sessionId)`

Revokes a single session without affecting the device's passkey. Revoking the current session clears local state and fires `onSessionChange`.

**Parameters**

| Name        | Type     | Description          |
|-------------|----------|----------------------|
| `sessionId` | `string` | From `getSessions()` |

Returns: `Promise<void>`

Throws:
- `NOT_INITIALIZED`
- `NO_KEYS` - not logged in
- `CLOCK_SKEW` - device clock is too far off the server's
- `API_ERROR` - network failure or server error

---

### `ignoti.revokeAllSessions()`

Revokes every active session for the current user across all devices, including this one. Devices remain registered so the user can log back in with any of their passkeys. Clears local state and fires `onSessionChange` with `null`.

```ts
await ignoti.revokeAllSessions();
```

Returns: `Promise<void>`

Throws:
- `NOT_INITIALIZED`
- `NO_KEYS` - not logged in
- `CLOCK_SKEW` - device clock is too far off the server's
- `API_ERROR` - network failure or server error

---

## Types

Types are exported from the main entry or the dedicated types entry:

```ts
import type { SessionInfo, DeviceInfo, SessionListItem } from '@ignoti/sdk';
// or
import type { SessionInfo, DeviceInfo, SessionListItem } from 'ignoti/types';
```

### `IgnotiOptions`

```ts
type IgnotiOptions = {
  backendUrl: string;
  defaultDeviceName?: string;
  apiClientOptions?: {
    timeout?: number;
    retryAttempts?: number;
  };
};
```

### `SessionInfo`

```ts
type SessionInfo = {
  sessionId: string;
  userId: string;
  deviceId: string;
  expiresAt: number; // Unix timestamp (ms)
};
```

### `CreateIdentityResult`

```ts
type CreateIdentityResult = {
  mnemonic: string[];
  userId: string;
  deviceId: string;
};
```

### `RecoverIdentityResult`

```ts
type RecoverIdentityResult = {
  userId: string;
  deviceId: string;
};
```

### `DeviceInfo`

```ts
type DeviceInfo = {
  id: string;
  credentialId: string;
  deviceName: string | null;
  createdAt: string; // ISO 8601
  lastUsedAt: string | null; // ISO 8601
};
```

### `SessionListItem`

```ts
type SessionListItem = {
  id: string;
  deviceId: string;
  createdAt: string; // ISO 8601
  lastUsedAt: string | null; // ISO 8601
  expiresAt: number; // Unix timestamp (ms)
  isCurrent: boolean;
};
```

### `IgnotiError`

All SDK methods throw `IgnotiError` on failure.

```ts
class IgnotiError extends Error {
  code: ErrorCode;
  httpStatus?: number; // populated for API_ERROR only
}
```

### `ErrorCodes`

| Code                 | When it is thrown                                                                                                           |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------|
| `NOT_INITIALIZED`    | Any method called before `init()`                                                                                           |
| `INVALID_INPUT`      | Invalid argument: unsupported WebAuthn, invalid mnemonic, no account matches the mnemonic, or a cancelled passkey prompt    |
| `CRYPTOGRAPHY_ERROR` | Key generation or signing failed                                                                                            |
| `NO_KEYS`            | No active session - not logged in, session expired, or revoked                                                              |
| `INVALID_SIGNATURE`  | The server rejected a signature: session, root-key (e.g. a mnemonic that does not match the account), or session binding    |
| `INVALID_CHALLENGE`  | The server rejected a challenge as invalid, expired, or already consumed                                                    |
| `API_ERROR`          | Server returned an error not covered by a more specific code - check `httpStatus`                                           |
| `CLOCK_SKEW`         | Device clock is more than 60s off the server's - signed requests are rejected until the user fixes their date/time settings |
