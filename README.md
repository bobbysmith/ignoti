# GhostID

**A free, open-source, self-hosted authentication platform. A privacy-first alternative to Sign in with Google.**

GhostID gives builders complete auth without writing it — and gives their users complete control without surrendering their identity to a third party. No email. No phone number. No OAuth middleman. No PII stored anywhere.

---

## What it is

GhostID is two things working together:

- **A backend server** — pre-built and ready to deploy. You host it, you own it. Your users' data never leaves your infrastructure.
- **A client SDK** (`ghostid`) — drop it into your app, point it at your server, and you have full auth.

The result is the same experience your users expect from "Sign in with Google" — one tap to register, one tap to log back in — but built on passkeys and cryptographic keys instead of a social account. No passwords. No email verification. Nothing to phish.

---

## How it works

GhostID uses a three-layer identity system:

**Root identity (your mnemonic)**
A 12-word phrase derived into an Ed25519 keypair. Never stored anywhere — not on the server, not in the SDK. Used only for account recovery and high-stakes operations like revoking a device. Lose the phrase, lose the account. Keep it like a private key.

**Device identity (your passkey)**
A WebAuthn passkey bound to the user's authenticator — Touch ID, Face ID, Windows Hello, a hardware key. Hardware-backed, phishing-resistant. This is how users log in day to day.

**Session identity (ephemeral)**
An Ed25519 keypair generated in memory at login. Every subsequent API request is signed with the session private key. A stolen session ID alone cannot be replayed — the attacker would also need the in-memory private key.

The server stores only opaque public keys and UUIDs. No email, no phone, no OAuth token, no PII of any kind.

---

## Who it's for

Builders whose users care about privacy. If you're building for people who use Signal instead of WhatsApp, Proton instead of Gmail, or who just don't want to hand their identity to Google to log into your app — GhostID is the auth layer for that audience.

---

## Getting started

> **Note:** GhostID is under active development and not yet recommended for production use. The security hardening phase is in progress. Watch this repo for the v1 release.

**1. Deploy the server**

```bash
# Coming soon: one-click deploy to Railway, Render, and Fly.io
# Docker image and docker-compose.yml in progress
```

**2. Run migrations**

```bash
DATABASE_URL=postgres://... pnpm db:migrate
```

**3. Install the client SDK**

```bash
npm install ghostid
```

**4. Initialize in your app**

```ts
import { GhostID } from 'ghostid';

const ghost = new GhostID({
  backendUrl: 'https://your-ghostid-server.example.com',
});

// Register a new user
const { userId, deviceId, mnemonic } = await ghost.createIdentity();

// Log in
const { sessionId, expiresAt } = await ghost.login();

// Make authenticated requests (session key signs automatically)
const headers = await ghost.getSessionHeaders();
```

---

## Architecture

```
Your app (browser)          GhostID server (you host this)     Your Postgres DB
──────────────────          ──────────────────────────────     ────────────────
ghostid SDK         ──────▶  Fastify + auth routes        ──▶  users
                             WebAuthn verification              devices
                             Ed25519 session signing            sessions
                             Rate limiting + CORS               challenges
```

The SDK handles all cryptography client-side. The server handles verification, challenge issuance, and session management. Your database stores only public keys and opaque identifiers.

---

## Self-hosting

GhostID is designed to be self-hosted. Your users' identity data lives in your Postgres database, under your control, in your infrastructure. GhostID (the project) never sees it.

**Required environment variables:**

| Variable | Description | Default |
|---|---|---|
| `DATABASE_URL` | Postgres connection string | required |
| `RP_ID` | WebAuthn relying party ID (your domain) | `localhost` |
| `RP_NAME` | Display name shown in passkey dialogs | `GhostID` |
| `RP_ORIGIN` | Allowed origin(s), comma-separated | `http://localhost:5173` |
| `CHALLENGE_TTL_SECONDS` | How long challenges stay valid | `300` |
| `SESSION_TTL_SECONDS` | How long sessions stay valid | `86400` |
| `PORT` | Server port | `8787` |
| `HOST` | Server host | `0.0.0.0` |

**Database maintenance:**

GhostID includes a cleanup function `ghostid_gc()` that prunes expired challenges and old sessions. Schedule it to run daily (or hourly at scale) via pg_cron or Supabase Cron Jobs:

```sql
-- pg_cron
select cron.schedule('ghostid-gc', '0 3 * * *', 'select ghostid_gc()');
```

---

## Security

GhostID's cryptographic design is documented in [THREAT_MODEL.md](./THREAT_MODEL.md). Key properties:

- No passwords — nothing to steal from the server
- No PII stored — a breached database reveals no real-world identities
- Phishing-resistant — WebAuthn origin binding means passkeys only work on the registered domain
- Replay-resistant — all challenges are single-use, scoped, and short-lived
- Signed requests — session keys sign every API call; a stolen session ID alone cannot be replayed

---

## Status

GhostID is under active development. Current state:

- ✅ Core auth flows (register, login, recover)
- ✅ Device management (list, revoke)
- ✅ Session signing middleware
- ✅ Versioned database migrations
- 🔧 Security hardening (in progress)
- ⏳ Session management API
- ⏳ Docker image and one-click deploy
- ⏳ Full documentation and getting-started guide

See [temp/TODO.md](./temp/TODO.md) for the full roadmap.

---

## License

MIT