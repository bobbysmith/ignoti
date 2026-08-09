# @ignoti/verify

Server-side session verification for [Ignoti](https://github.com/dipsettheory/ignoti). Validates the signed
session headers produced by the client SDK's `getSessionHeaders()` against your self-hosted Ignoti server.

Zero runtime dependencies. Node 18+.

## Usage

```ts
import { IgnotiVerifier } from '@ignoti/verify';

const verifier = new IgnotiVerifier({
  serverUrl: 'https://your-ignoti-server.example.com',
});
```

**Express**

```ts
app.use('/api', verifier.expressMiddleware());

app.get('/api/feed', (req, res) => {
  // req.ignoti = { sessionId, userId, deviceId, expiresAt }
  res.json({ feed: loadFeedFor(req.ignoti.userId) });
});
```

**Fastify**

```ts
app.get('/feed', { preHandler: [verifier.fastifyPreHandler()] }, async req => {
  return { feed: await loadFeedFor(req.ignoti.userId) };
});
```

**Any framework**

```ts
const result = await verifier.verify({
  method: req.method,
  path: req.path, // must match the path the client signed
  headers: req.headers,
});

if (result.valid) {
  // result.userId, result.deviceId, result.sessionId, result.expiresAt
} else {
  // result.error - e.g. 'session_not_found', 'session_expired', 'session_nonce_used'
}
```

## How it works

Each call forwards the four session headers plus the method and path to your Ignoti server's
`POST /api/sessions/verify` endpoint (RFC 7662-style introspection). The server runs the full check -
Ed25519 signature, session revocation and expiry, timestamp window, and single-use nonce - and returns the
authenticated identity. Verification is centralized by design: instant revocation and replay prevention
require the Ignoti server's state, so sessions cannot be verified offline.

Rules:

- **Verify each request exactly once.** The nonce is consumed on verification; verifying the same headers
  twice returns `session_nonce_used`.
- **Never cache a `valid: true` result across requests.** Every request carries a fresh signature.

`verify()` only throws (`IgnotiVerifyError`) when introspection itself fails - server unreachable, timeout,
or a malformed response. An invalid session is a *successful* introspection and comes back as
`{ valid: false, error }`.

## Options

| Option      | Default | Description                                             |
|-------------|---------|---------------------------------------------------------|
| `serverUrl` | -       | Base URL of your self-hosted Ignoti server. Required.  |
| `timeoutMs` | `5000`  | Abort the verification request after this many ms.      |
| `fetch`     | global  | Custom fetch implementation (tests, edge runtimes).     |

## License

MIT
