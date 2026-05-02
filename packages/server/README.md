# @ghostid/server

Reference backend for the GhostID protocol. Stateless and PII-free. Stores only opaque public keys, opaque IDs, and 
ephemeral challenges/sessions.

## Quickstart

```bash
cp .env.example .env       # fill in DATABASE_URL
pnpm db:migrate            # apply schema.sql
pnpm dev                   # http://localhost:8787/health
```

## Database

Works with any Postgres 14+. Schema lives in `src/db/schema.sql`.

## Endpoints

See `src/routes/auth.ts` and `src/routes/devices.ts`. All bodies are JSON. Authenticated requests carry signatures 
verified server-side; no cookies, no bearer tokens.

## Logging

We never log private keys, signatures, mnemonics, IPs, or anything that could deanonymize a user. If you add a log 
line near auth code, double-check.
