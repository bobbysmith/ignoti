# Getting Started

This guide walks through deploying the GhostID server and integrating the client SDK into a web app. By the end you 
will have working registration, login, and account recovery.

## Prerequisites

- Docker and Docker Compose
- A web app with a build step, ex. Vite, Next.js, etc.
- A modern browser with WebAuthn support (Chrome, Safari, Firefox, Edge)

---

## 1. Deploy the server

Download the Docker Compose file and configure it for your domain:

```bash
curl -O https://raw.githubusercontent.com/dipsettheory/ghostid/main/docker-compose.yml
curl -O https://raw.githubusercontent.com/dipsettheory/ghostid/main/packages/server/.env.example
mv .env.example .env
```

Open `.env` and set at minimum:

```bash
# The hostname your frontend is served from, no scheme, no port
RP_ID=myapp.com

# The full origin your frontend is served from
RP_ORIGIN=https://myapp.com
```

Start the stack:

```bash
docker compose up -d
```

The server starts on port `8787`. Database migrations run automatically on first boot.

> For a full list of configuration options see the [environment variable reference](../README.md#self-hosting).

---

## 2. Install the SDK

```bash
npm install ghostid
```

---

## 3. Initialize

Create a single `GhostID` instance for your app and call `init()` before using any other method.

```ts
import { GhostID } from 'ghostid';

export const ghost = new GhostID({
  backendUrl: 'https://myapp.com:8787',
});

ghost.init();
```

`init()` is synchronous. The session private key stays in memory only — nothing is written to disk or localStorage.

---

## 4. Register a new user

`createIdentity()` generates a root keypair from a new mnemonic, registers it with the server, and prompts the user 
to create a passkey.

```ts
const { userId, deviceId, mnemonic } = await ghost.createIdentity();
```

**The mnemonic is the user's only recovery path.** Present it to the user immediately and prompt them to store it 
somewhere safe. GhostID never stores it - once this screen is dismissed, it cannot be retrieved.

```ts
// Example: show the mnemonic to the user before continuing
showMnemonicScreen(mnemonic); // your UI
```

---

## 5. Log in

`login()` requests a WebAuthn challenge from the server, prompts the user to authenticate with their passkey, and 
establishes an in-memory session.

```ts
const { sessionId, expiresAt } = await ghost.login();
```

The session private key exists only in memory. Call `restoreSession()` on page load to re-establish the session from the httpOnly cookie — no passkey prompt needed. If the session has expired or been revoked, `restoreSession()` throws and `getSession()` returns `null`.

---

## 6. Handle returning users

On page load, call `restoreSession()` before rendering any authenticated UI. It sends a fresh keypair binding to the
server, which validates the session cookie and re-establishes the in-memory session — no passkey prompt needed.

```ts
ghost.init();

try {
  await ghost.restoreSession();
} catch {
  // no active session cookie, or session expired/revoked
}

const session = ghost.getSession();

if (session) {
  renderApp(session.userId);
} else {
  renderLoginScreen();
}
```

`getSession()` returns `null` if there is no active session. This happens when:
- The user has never logged in on this device
- The session has expired
- The user logged out

---

## 7. Make authenticated requests

All requests to your backend that require authentication must include a session signature. Use `getSessionHeaders()`
to get pre-built headers to attach to each request.

```ts
const headers = await ghost.getSessionHeaders();

const response = await fetch('https://myapp.com/api/protected', {
  headers,
});
```

The session key signs a short-lived timestamp on every call. A stolen session ID alone cannot be replayed - the 
attacker would also need the in-memory private key.

---

## 8. Recover an account

If a user loses access to their device, they can register a new one using their mnemonic.

```ts
const mnemonic = promptUserForMnemonic(); // your UI

const { userId, deviceId } = await ghost.recoverIdentity(mnemonic);
```

Recovery registers a new passkey for the existing account. The `userId` returned is the same as the original - the 
account is preserved.

---

## 9. Manage devices

List all active devices for the authenticated user:

```ts
const devices = await ghost.getDevices();
// [{ id, credentialId, deviceName, createdAt, lastUsedAt }, ...]
```

Revoke a device using the mnemonic. This immediately invalidates all sessions on that device:

```ts
await ghost.revokeDevice(deviceId, mnemonic, userId, credentialId);
```

`userId` and `credentialId` are available from `createIdentity()`, `recoverIdentity()`, or a prior `getDevices()` call.

---

## 10. Manage sessions

List all active sessions for the authenticated user:

```ts
const sessions = await ghost.getSessions();
// [{ id, deviceId, createdAt, lastUsedAt, expiresAt, isCurrent }, ...]
```

Revoke a specific session without revoking the device:

```ts
await ghost.revokeSession(targetSessionId);
```

Revoking the current session is equivalent to logging out - the in-memory session is cleared automatically.

---

## 11. Logout

```ts
await ghost.logout();
```

The session is revoked server-side (clearing the httpOnly cookie) and the in-memory key is wiped. If the server call fails, the local key is still wiped but the error is rethrown — the server session remains active. The user will need to authenticate again on success.

When your app is shutting down (e.g. a single-page app unmounting its root component), call `destroy()` to wipe all 
in-memory keys:

```ts
ghost.destroy();
```

---

## Error handling

All SDK methods throw a `GhostIDError` on failure. Each error has a `code` property for programmatic handling.

```ts
import { GhostIDError, ErrorCodes } from 'ghostid';

try {
  await ghost.login();
} catch (err) {
  if (err instanceof GhostIDError) {
    switch (err.code) {
      case ErrorCodes.NO_KEYS:
        // no active session
        break;
      case ErrorCodes.EXPIRED_CHALLENGE:
        // session expired
        break;
      default:
        // unexpected error
    }
  }
}
```