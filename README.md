# GhostID

[![CI](https://github.com/dipsettheory/ghostid/actions/workflows/ci.yml/badge.svg)](https://github.com/dipsettheory/ghostid/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE) [![npm](https://img.shields.io/npm/v/ghostid)](https://www.npmjs.com/package/ghostid)

**A free, open-source, self-hosted authentication platform. A privacy-first alternative to auth that treats your users as the product.**

GhostID gives builders complete auth without writing it and gives their users complete control without surrendering 
their identity to a third party. No email. No phone number. No OAuth middleman. No PII stored anywhere.

---

## What it is

GhostID is two things working together:

- **A backend server** - pre-built and ready to deploy. You host it, you own it. Your users' data never leaves your 
  infrastructure.
- **A client SDK** (`ghostid`) - drop it into your app, point it at your server, and you have full auth.

The result is the same experience your users expect from "Sign in with Google" - one tap to register, one tap to log 
back in, but built on passkeys and cryptographic keys instead of a social account. No passwords. No email 
verification. Nothing to phish.

---

## How it works

GhostID uses a three-layer identity system:

**Root identity (your mnemonic)**
A 12-word phrase derived into an Ed25519 keypair. Never stored anywhere - not on the server, not in the SDK. Used 
only for account recovery and high-stakes operations like revoking a device. Lose the phrase, lose the account. Keep 
it like a private key.

**Device identity (your passkey)**
A WebAuthn passkey bound to the user's authenticator - Touch ID, Face ID, Windows Hello, a hardware key. 
Hardware-backed, phishing-resistant. This is how users log in day to day.

**Session identity (ephemeral)**
An Ed25519 keypair generated in memory at login. Every subsequent API request is signed with the session private key.
A stolen session ID alone cannot be replayed - the attacker would also need the in-memory private key. The session 
survives page reloads via an httpOnly cookie, the private key is never persisted, only a session token that 
JavaScript cannot read.

The server stores only opaque public keys and UUIDs. No email, no phone, no OAuth token, no PII of any kind.

---

## Who it's for

Builders whose users care about privacy. If you're building for people who use Signal instead of WhatsApp, Proton 
instead of Gmail, or who just don't want to hand their identity to Google to use your app, GhostID is the auth you want.

---

## Getting started

For a full walkthrough see [docs/getting-started.md](./docs/getting-started.md).

**1. Deploy the server**

GhostID ships as a Docker image. The included `docker-compose.yml` starts the server and a Postgres database 
together and runs migrations automatically on first boot.

```bash
curl -O https://raw.githubusercontent.com/dipsettheory/ghostid/main/docker-compose.yml

# Set RP_ID and RP_ORIGIN for your domain - see Environment variables below
cp .env.example .env

docker compose up -d
```

The server listens on port `8787` by default.

**2. Install the client SDK**

```bash
npm install ghostid
```

**3. Initialize in your app**

```ts
import { GhostID } from 'ghostid';

const ghost = new GhostID({
  backendUrl: 'https://your-ghostid-server.example.com',
});

// Register a new user
const { userId, deviceId, mnemonic } = await ghost.createIdentity();

// Log in
const { sessionId, expiresAt } = await ghost.login();

// Sign authenticated requests
const headers = await ghost.getSessionHeaders('GET', '/api/feed');
```

---

## Architecture

```
Your app (browser)      GhostID server (you host this)      Your Postgres DB
──────────────────      ──────────────────────────────      ────────────────
ghostid SDK        -->  Fastify and auth routes        -->  users
                          WebAuthn verification               devices
                          Ed25519 session signing             sessions
                          Rate limiting and CORS              challenges
```

The SDK handles all cryptography client-side. The server handles verification, challenge issuance, and session 
management. Your database stores only public keys and opaque identifiers.

---

## Self-hosting

GhostID is designed to be self-hosted. User identity data lives in your Postgres database, under your control, in 
your infrastructure. GhostID never has access to it.

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/dipsettheory/ghostid) [![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/new/template?template=https://github.com/dipsettheory/ghostid)

**Environment variables:**

| Variable                | Required | Default                 | Description                                                                                                           |
|-------------------------|----------|-------------------------|-----------------------------------------------------------------------------------------------------------------------|
| `DATABASE_URL`          | Yes      | -                       | Postgres connection string.                                                                                           |
| `RP_ID`                 | Yes      | `localhost`             | WebAuthn relying party ID - the hostname of your app, no scheme or port, ex. `mycoolapp.com`.                         |
| `RP_NAME`               | No       | `GhostID`               | Display name shown to users in passkey dialogs.                                                                       |
| `RP_ORIGIN`             | Yes      | `http://localhost:5173` | Allowed origin(s). Must match your frontend exactly (scheme and host and port). Comma-separated for multiple origins. |
| `CHALLENGE_TTL_SECONDS` | No       | `300` (5 min)           | How long a WebAuthn challenge stays valid. Min: 30, max: 3600.                                                        |
| `SESSION_TTL_SECONDS`   | No       | `86400` (24 hr)         | How long a session token stays valid. Min: 60, max: 2592000 (30 days).                                                |
| `DB_PREPARE`            | No       | `true`                  | Set to `false` when using a transaction pooler that does not support prepared statements.                             |
| `PORT`                  | No       | `8787`                  | Port the server listens on.                                                                                           |
| `HOST`                  | No       | `0.0.0.0`               | Network interface to bind to.                                                                                         |
| `LOG_LEVEL`             | No       | `info`                  | Log verbosity. One of: `fatal`, `error`, `warn`, `info`, `debug`, `trace`.                                            |
| `COOKIE_SECURE`         | No       | `true`                  | Set to `false` in local development when not using HTTPS.                                                             |
| `RATE_LIMIT_DISABLED`   | No       | `false`                 | Set to `true` to disable rate limiting. For testing only — never disable in production.                               |

**Database:**

GhostID requires Postgres 14 or later. When using Docker Compose, a Postgres container is included and migrations 
run automatically on startup. To run migrations manually against an external database:

```bash
docker run --rm -e DATABASE_URL=postgres://... ghostid/server:latest node dist/db/migrate.js
```

The server image is published to Docker Hub as `ghostid/server`. You can also build it yourself from the repo root with `docker build -t ghostid/server .`

**Database maintenance:**

GhostID includes a `ghostid_gc()` function that deletes expired challenges and old sessions. Schedule it to run at 
least daily using your database's job scheduler.

```sql
select cron.schedule('ghostid-gc', '0 3 * * *', 'select ghostid_gc()');
```

---

## Security

GhostID's cryptographic design is documented in [docs/threat-model.md](./docs/threat-model.md). Key properties:

- **No passwords** - nothing to steal from the server
- **No PII stored** - a breached database reveals no real world identities
- **Phishing-resistant** - WebAuthn origin binding means passkeys only work on the registered domain
- **Replay-resistant** - all challenges are single-use, scoped, and short-lived
- **Signed requests** - session keys sign every API call; a stolen session ID alone cannot be replayed
- **Private keys never stored** - sessions survive page reloads via an httpOnly cookie; the private key stays ephemeral

---

## License

MIT