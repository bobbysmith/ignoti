# Ignoti

[![CI](https://github.com/dipsettheory/ignoti/actions/workflows/ci.yml/badge.svg)](https://github.com/dipsettheory/ignoti/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE) [![npm](https://img.shields.io/npm/v/@ignoti/sdk)](https://www.npmjs.com/package/@ignoti/sdk)

**A free, open-source, self-hosted authentication platform. A privacy-first alternative to auth that treats your users as the product.**

Ignoti gives builders complete auth without writing it and gives their users complete control without surrendering 
their identity to a third party. No email. No phone number. No OAuth middleman. No PII stored anywhere.

---

## What it is

Ignoti is two things working together:

- **A backend server** - pre-built and ready to deploy. You host it, you own it. Your users' data never leaves your 
  infrastructure.
- **A client SDK** (`ignoti`) - drop it into your app, point it at your server, and you have full auth.

The result is the same experience your users expect from "Sign in with Google" - one tap to register, one tap to log 
back in, but built on passkeys and cryptographic keys instead of a social account. No passwords. No email 
verification. Nothing to phish.

---

## How it works

Ignoti uses a three-layer identity system:

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
instead of Gmail, or who just don't want to hand their identity to Google to use your app, Ignoti is the auth you want.

---

## Getting started

For a full walkthrough see [docs/getting-started.md](./docs/getting-started.md).

**1. Deploy the server**

Ignoti ships as a Docker image. The included `docker-compose.yml` starts the server and a Postgres database 
together and runs migrations automatically on first boot.

```bash
curl -O https://raw.githubusercontent.com/dipsettheory/ignoti/main/docker-compose.yml

# Set RP_ID and RP_ORIGIN for your domain - see Environment variables below
cp .env.example .env

docker compose up -d
```

The server listens on port `8787` by default.

**2. Install the client SDK**

```bash
npm install @ignoti/sdk
```

**3. Initialize in your app**

```ts
import { Ignoti } from '@ignoti/sdk';

const ignoti = new Ignoti({
  backendUrl: 'https://your-ignoti-server.example.com',
});

// Register a new user
const { userId, deviceId, mnemonic } = await ignoti.createIdentity();

// Log in
const { sessionId, expiresAt } = await ignoti.login();

// Sign authenticated requests
const headers = await ignoti.getSessionHeaders('GET', '/api/feed');
```

---

## Architecture

```
Your app (browser)      Ignoti server (you host this)      Your Postgres DB
──────────────────      ──────────────────────────────      ────────────────
ignoti SDK        -->  Fastify and auth routes        -->  users
                          WebAuthn verification               devices
                          Ed25519 session signing             sessions
                          Rate limiting and CORS              challenges
```

The SDK handles all cryptography client-side. The server handles verification, challenge issuance, and session 
management. Your database stores only public keys and opaque identifiers.

---

## Self-hosting

Ignoti is designed to be self-hosted. User identity data lives in your Postgres database, under your control, in 
your infrastructure. Ignoti never has access to it.

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/dipsettheory/ignoti) [![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/new/template?template=https://github.com/dipsettheory/ignoti)

**Environment variables:**

| Variable                | Required | Default                 | Description                                                                                                                                                   |
|-------------------------|----------|-------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `DATABASE_URL`          | Yes      | -                       | Postgres connection string.                                                                                                                                   |
| `RP_ID`                 | Yes      | `localhost`             | WebAuthn relying party ID - the hostname of your app, no scheme or port, ex. `mycoolapp.com`.                                                                 |
| `RP_NAME`               | No       | `Ignoti`               | Display name shown to users in passkey dialogs.                                                                                                               |
| `RP_ORIGIN`             | Yes      | `http://localhost:5173` | Allowed origin(s). Must match your frontend exactly (scheme and host and port). Comma-separated for multiple origins.                                         |
| `CHALLENGE_TTL_SECONDS` | No       | `300` (5 min)           | How long a WebAuthn challenge stays valid. Min: 30, max: 3600.                                                                                                |
| `SESSION_TTL_SECONDS`   | No       | `86400` (24 hr)         | How long a session token stays valid. Min: 60, max: 2592000 (30 days).                                                                                        |
| `DB_PREPARE`            | No       | `true`                  | Set to `false` when using a transaction pooler that does not support prepared statements.                                                                     |
| `PORT`                  | No       | `8787`                  | Port the server listens on.                                                                                                                                   |
| `HOST`                  | No       | `0.0.0.0`               | Network interface to bind to.                                                                                                                                 |
| `LOG_LEVEL`             | No       | `info`                  | Log verbosity. One of: `fatal`, `error`, `warn`, `info`, `debug`, `trace`.                                                                                    |
| `COOKIE_SECURE`         | No       | `true`                  | Set to `false` in local development when not using HTTPS.                                                                                                     |
| `GC_INTERVAL_SECONDS`   | No       | `3600` (1 hr)           | Interval for the in-process cleanup of expired challenges, nonces, and old sessions. `0` disables it (use an external scheduler instead). Max: 86400.         |
| `TRUST_PROXY`           | No       | `1`                     | X-Forwarded-For hops to trust for client-IP rate limiting. Integer hop count, `false` (no proxy), `true` (trust all), or a comma-separated IP/CIDR allowlist. |
| `RATE_LIMIT_DISABLED`   | No       | `false`                 | Set to `true` to disable rate limiting. For testing only, never disable in production.                                                                        |

**Cross-subdomain auth:**

To share auth across multiple subdomains of the same registrable domain, set `RP_ID` to the parent domain and list every subdomain origin in `RP_ORIGIN`:

```bash
RP_ID=example.com
RP_ORIGIN=https://app.example.com,https://admin.example.com,https://staging.example.com
```

A passkey registered on one subdomain works on every subdomain listed in `RP_ORIGIN`. WebAuthn requires `RP_ID` to 
be either the exact hostname or a registrable suffix of every origin. The server enforces this match at verification 
time.

**Session signature timing:**

Every authenticated request includes a signed timestamp. The server accepts signatures within a 60-second window to absorb normal clock skew. If your deployment has clients with persistently skewed clocks (more than a minute off), authenticated requests will fail with `SESSION_TIMESTAMP_OUT_OF_RANGE`. This window is currently a server-side constant in `src/constants.ts`; surface it as an env var if you need a different tolerance.

**Database:**

Ignoti requires Postgres 14 or later. When using Docker Compose, a Postgres container is included and migrations 
run automatically on startup. To run migrations manually against an external database:

```bash
docker run --rm -e DATABASE_URL=postgres://... ignoti/server:latest node dist/db/migrate.js
```

The server image is published to Docker Hub as `ignoti/server`. You can also build it yourself from the repo root with `docker build -t ignoti/server .`

**Database maintenance:**

The server prunes expired challenges, nonces, and old sessions itself, running the `ignoti_gc()` function 
in-process every `GC_INTERVAL_SECONDS` (default 3600). Only one instance sweeps at a time, coordinated by a Postgres 
advisory lock, so this is safe to run with multiple replicas. No setup is required.

If you would rather drive cleanup from an external scheduler, set `GC_INTERVAL_SECONDS=0` to disable the in-process 
timer and call the function on a schedule your database supports:

```sql
select cron.schedule('ignoti-gc', '0 3 * * *', 'select ignoti_gc()');
```

**Backups:**

Ignoti stores no PII, but losing the database means every registered user loses access to their account. The mnemonic alone is not enough to recover without a server record of the root public key. Back up regularly.

A nightly `pg_dump` is the minimum:

```bash
pg_dump "$DATABASE_URL" --no-owner --no-privileges -Fc -f ignoti-$(date +%F).dump
```

For production, use your platform's native point-in-time recovery (Supabase, RDS, and most managed Postgres 
providers include this) and verify a restore at least once before going live. Back up at least hourly so you never lose more than an hour of new registrations, and test your restore process so you know how long it takes to come back online. Until the database is restored, users cannot log in.

---

## Security

Ignoti's cryptographic design is documented in [docs/threat-model.md](./docs/threat-model.md). Key properties:

- **No passwords** - nothing to steal from the server
- **No PII stored** - a breached database reveals no real world identities
- **Phishing-resistant** - WebAuthn origin binding means passkeys only work on the registered domain
- **Replay-resistant** - all challenges are single-use, scoped, and short-lived
- **Signed requests** - session keys sign every API call; a stolen session ID alone cannot be replayed
- **Private keys never stored** - sessions survive page reloads via an httpOnly cookie; the private key stays ephemeral

---

## License

MIT