# Getting Started

This guide walks through deploying the Ignoti server and integrating the client SDK into a web app. By the end you 
will have working registration, login, and account recovery.

## Prerequisites

- Docker and Docker Compose
- A web app with a build step, ex. Vite, Next.js, etc.
- A modern browser with WebAuthn support (Chrome, Safari, Firefox, Edge)

---

## 1. Deploy the server

Download the Docker Compose file and configure it for your domain:

```bash
curl -O https://raw.githubusercontent.com/dipsettheory/ignoti/main/docker-compose.yml
curl -O https://raw.githubusercontent.com/dipsettheory/ignoti/main/packages/server/.env.example
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

> **WebAuthn requires a secure context.** Your frontend must be served over HTTPS (the sole
> exception is `localhost` during development). Over plain HTTP on any other host the browser
> refuses to create or use passkeys. For the same reason the session cookie is `Secure` by
> default; if you are developing over plain `http://localhost`, set `COOKIE_SECURE=false` so the
> browser will send the cookie, and never do this in a deployed environment.

> For a full list of configuration options see the [environment variable reference](https://github.com/dipsettheory/ignoti#self-hosting).

---

## 2. Install the SDK

```bash
npm install @ignoti/sdk
```

---

## 3. Initialize

Create a single `Ignoti` instance for your app and call `init()` before using any other method.

```ts
import { Ignoti } from '@ignoti/sdk';

export const ignoti = new Ignoti({
  backendUrl: 'https://myapp.com:8787',
});

ignoti.init();
```

`init()` is synchronous. The session private key stays in memory only, nothing is written to disk or localStorage.

---

## 4. Register a new user

`createIdentity()` generates a root keypair from a new mnemonic, registers it with the server, and prompts the user 
to create a passkey.

```ts
const { userId, deviceId, mnemonic } = await ignoti.createIdentity();
```

**The mnemonic is the user's only recovery path.** Present it to the user immediately and prompt them to store it 
somewhere safe. Ignoti never stores it - once this screen is dismissed, it cannot be retrieved.

```ts
// Example: show the mnemonic to the user before continuing
showMnemonicScreen(mnemonic); // your UI
```

---

## 5. Log in

`login()` requests a WebAuthn challenge from the server, prompts the user to authenticate with their passkey, and 
establishes an in-memory session.

```ts
const { sessionId, expiresAt } = await ignoti.login();
```

The session private key exists only in memory. Call `restoreSession()` on page load to re-establish the session from 
the httpOnly cookie, no passkey prompt needed. If the session has expired or been revoked, `restoreSession()` throws and `getSession()` returns `null`.

---

## 6. Handle returning users

On page load, call `restoreSession()` before rendering any authenticated UI. It sends a fresh keypair binding to the
server, which validates the session cookie and re-establishes the in-memory session, no passkey prompt needed.

```ts
ignoti.init();

try {
  await ignoti.restoreSession();
} catch {
  // no active session cookie, or session expired/revoked
}

const session = ignoti.getSession();

if (session) {
  renderApp(session.userId);
} else {
  renderLoginScreen();
}
```

Concurrent `restoreSession()` calls within a page are single-flighted by the SDK: they share one attempt and one keypair, so a React StrictMode double-invoke cannot race two bindings against each other. The `useRef` guard below is therefore optional — it just avoids issuing a second, redundant call. (Separate tabs are separate SDK instances and do not share this latch; two tabs restoring the same session at the same instant can still trip cookie-rotation reuse detection and force a re-login, which fails safe.)

```tsx
const restored = useRef(false);

useEffect(() => {
  if (restored.current) return;
  restored.current = true;
  ignoti.restoreSession().catch(() => {});
}, []);
```

`getSession()` returns `null` if there is no active session. This happens when:
- The user has never logged in on this device
- The session has expired
- The user logged out
- The session cookie was cleared (browser storage wiped, incognito tab closed, device reset)

The last case is worth handling explicitly. The session cookie is `httpOnly` and stored by the browser. If the user 
clears site data, switches browsers, or wipes the device, the cookie is gone and `restoreSession()` will throw 
`NO_KEYS`. The user is not logged out from the server's perspective until that session expires or is revoked, but 
from the user's perspective they need to authenticate again. Show your login UI and let them tap their passkey. No 
mnemonic needed unless they've lost the device entirely.

```ts
try {
  await ignoti.restoreSession();
} catch (err) {
  if (err instanceof IgnotiError && err.code === ErrorCodes.NO_KEYS) {
    // session cookie missing or invalid, prompt for passkey
    renderLoginScreen();
    return;
  }
  throw err;
}
```

---

## 7. Make authenticated requests

All requests to your backend that require authentication must include a session signature. Use `getSessionHeaders()`
to get pre-built headers to attach to each request.

```ts
const headers = await ignoti.getSessionHeaders('GET', '/api/protected');

const response = await fetch('https://myapp.com/api/protected', {
  headers,
});
```

The session key signs a short-lived timestamp on every call. A stolen session ID alone cannot be replayed - the 
attacker would also need the in-memory private key.

The `method` and `path` you pass to `getSessionHeaders()` are baked into the signature. They must match what your
backend forwards for verification below, character for character.

### Verify on your backend

Your backend validates the headers with the `@ignoti/verify` package, which forwards them to your Ignoti
server's verification endpoint. Ignoti runs the full check - signature, session state, timestamp window, and
nonce replay - and tells you who the request came from.

```bash
npm install @ignoti/verify
```

```ts
import { IgnotiVerifier } from '@ignoti/verify';

const verifier = new IgnotiVerifier({
  serverUrl: 'https://your-ignoti-server.example.com',
});

// Express: protect routes with one line
app.use('/api', verifier.expressMiddleware());

app.get('/api/feed', (req, res) => {
  // req.ignoti = { sessionId, userId, deviceId, expiresAt }
  res.json({ feed: loadFeedFor(req.ignoti.userId) });
});
```

Fastify users get a preHandler instead:

```ts
app.get('/feed', { preHandler: [verifier.fastifyPreHandler()] }, async req => {
  return { feed: await loadFeedFor(req.ignoti.userId) };
});
```

For other frameworks, call `verifier.verify({ method, path, headers })` directly - it returns
`{ valid: true, userId, deviceId, sessionId, expiresAt }` or `{ valid: false, error }`.

Under the hood this is one POST to your Ignoti server's `POST /api/sessions/verify` endpoint
(RFC 7662-style introspection), so it works from any language - forward `{ method, path, authorization,
nonce, timestamp, signature }` and read the same JSON back.

Two rules:

- **Verify each request exactly once.** The nonce is consumed on verification; a second verify of the same
  headers returns `session_nonce_used`. Don't retry a verification call that already returned a result.
- **Do not cache a `valid: true` result across requests.** Every request carries a fresh signature; the
  verification is per-request by design.

---

## 8. Recover an account

If a user loses access to their device, they can register a new one using their mnemonic.

```ts
const mnemonic = promptUserForMnemonic(); // your UI

const { userId, deviceId } = await ignoti.recoverIdentity(mnemonic);
```

Recovery registers a new passkey for the existing account. The `userId` returned is the same as the original - the 
account is preserved.

---

## 9. Manage devices

List all active devices for the authenticated user:

```ts
const devices = await ignoti.getDevices();
// [{ id, credentialId, deviceName, createdAt, lastUsedAt }, ...]
```

Revoke a device using the mnemonic. This immediately invalidates all sessions on that device:

```ts
await ignoti.revokeDevice(deviceId, mnemonic, userId, credentialId);
```

`userId` and `credentialId` are available from `createIdentity()`, `recoverIdentity()`, or a prior `getDevices()` call.

---

## 10. Manage sessions

List all active sessions for the authenticated user:

```ts
const sessions = await ignoti.getSessions();
// [{ id, deviceId, createdAt, lastUsedAt, expiresAt, isCurrent }, ...]
```

Revoke a specific session without revoking the device:

```ts
await ignoti.revokeSession(targetSessionId);
```

Revoking the current session is equivalent to logging out - the in-memory session is cleared automatically.

---

## 11. Logout

```ts
try {
  await ignoti.logout();
  renderLoginScreen();
} catch (err) {
  // logout did not complete — the user is still logged in
  showLogoutFailed(); // your UI: surface it, let them retry
}
```

The session is revoked server-side (which clears the httpOnly cookie), and only then is the in-memory key wiped and 
`onSessionChange(null)` fired. If the server call fails, the error is thrown and the session is left intact — the 
user stays logged in. Ignoti does not hide the failure or clear state optimistically; handle the error and retry if 
you want. Only treat the user as logged out after `logout()` resolves.

---

## Error handling

All SDK methods throw a `IgnotiError` on failure. Each error has a `code` property for programmatic handling.

```ts
import { IgnotiError, ErrorCodes } from '@ignoti/sdk';

try {
  await ignoti.login();
} catch (err) {
  if (err instanceof IgnotiError) {
    switch (err.code) {
      case ErrorCodes.NO_KEYS:
        // no active session
        break;
      case ErrorCodes.API_ERROR:
        // server rejected the challenge or login (check err.httpStatus)
        break;
      default:
        // unexpected error
    }
  }
}
```