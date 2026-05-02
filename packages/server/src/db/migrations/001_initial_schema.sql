-- GhostID server schema
-- Apply on Supabase: paste into the SQL editor, OR run `pnpm db:migrate` against DATABASE_URL.
-- All identifiers are opaque; no PII is stored.
--
-- Note on RLS: every table enables Row Level Security with NO policies. This means:
--   - The Supabase anon/authenticated keys (PostgREST) cannot read or write anything. Good.
--   - Our server connects with the postgres role via the connection string, which bypasses RLS.
-- If you ever want to expose data to a Supabase client SDK directly, add explicit policies.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------------
-- users: one row per identity. Keyed by the user's root public key.
-- ---------------------------------------------------------------------------
create table if not exists users (
  id              uuid primary key default gen_random_uuid(),
  root_public_key text not null unique,
  created_at      timestamptz not null default now()
);

alter table users enable row level security;

-- ---------------------------------------------------------------------------
-- devices: passkeys registered to a user. credential_id is the WebAuthn
-- credential ID (base64url). passkey_public_key is the COSE-encoded key
-- returned from attestation, base64url.
-- ---------------------------------------------------------------------------
create table if not exists devices (
  id                  uuid primary key default gen_random_uuid(),
  user_id             uuid not null references users(id) on delete cascade,
  credential_id       text not null unique,
  passkey_public_key  text not null,
  sign_count          bigint not null default 0,
  transports          text[],
  device_name         text,
  created_at          timestamptz not null default now(),
  last_used_at        timestamptz,
  revoked_at          timestamptz
);

create index if not exists devices_user_id_idx on devices(user_id) where revoked_at is null;
create index if not exists devices_credential_id_idx on devices(credential_id);

alter table devices enable row level security;

-- ---------------------------------------------------------------------------
-- challenges: one-shot nonces for register/login/recover/session flows.
-- expires_at and consumed_at together prevent replay.
-- ---------------------------------------------------------------------------
create table if not exists challenges (
  id          uuid primary key default gen_random_uuid(),
  value       text not null unique,
  purpose     text not null check (purpose in ('register', 'login', 'recover', 'session')),
  device_id   uuid references devices(id) on delete cascade,
  user_id     uuid references users(id) on delete cascade,
  expires_at  timestamptz not null,
  consumed_at timestamptz,
  created_at  timestamptz not null default now()
);

create index if not exists challenges_value_idx on challenges(value);
create index if not exists challenges_expires_idx on challenges(expires_at) where consumed_at is null;

alter table challenges enable row level security;

-- ---------------------------------------------------------------------------
-- sessions: one row per active session. session_public_key signs subsequent
-- requests until expires_at or revoked_at.
-- ---------------------------------------------------------------------------
create table if not exists sessions (
  id                  uuid primary key default gen_random_uuid(),
  device_id           uuid not null references devices(id) on delete cascade,
  session_public_key  text not null,
  expires_at          timestamptz not null,
  revoked_at          timestamptz,
  created_at          timestamptz not null default now(),
  last_used_at        timestamptz
);

create index if not exists sessions_device_id_idx on sessions(device_id) where revoked_at is null;
create index if not exists sessions_expires_idx on sessions(expires_at) where revoked_at is null;

alter table sessions enable row level security;

-- ---------------------------------------------------------------------------
-- Cleanup helper: hard-delete stale challenges and sessions.
--
-- Challenges: deleted as soon as they are expired. They are single-use nonces;
-- consumed_at already prevented replay before this runs, and an expired row
-- is indistinguishable from a deleted one from the server's perspective.
--
-- Sessions: deleted after a 7-day grace period past expiry or revocation.
-- The grace window gives operators a brief debugging window. Sessions contain
-- activity metadata (device_id, session_public_key, timestamps) that should
-- not be retained indefinitely — keeping it contradicts the zero-knowledge
-- design and the threat model's data-minimisation goal.
--
-- Schedule: run once daily at 3am UTC.
-- TODO(prod): tighten to hourly (0 * * * *) before launch — at scale,
--             expired challenges accumulate faster and the 24h window
--             means more dead rows sitting in the table between runs.
-- pg_cron (self-hosted):
--   select cron.schedule('ghostid-gc', '0 3 * * *', 'select ghostid_gc()');
-- Supabase Cron (dashboard → Database → Cron Jobs):
--   Function: ghostid_gc   Schedule: 0 3 * * *
-- ---------------------------------------------------------------------------
create or replace function ghostid_gc() returns void
language sql
set search_path = ''
as $$
  -- Challenges expire quickly (default 5 min TTL). Delete all expired rows
  -- regardless of consumed_at; a deleted challenge behaves identically to an
  -- expired one — the lookup returns nothing and the request is rejected.
  delete from public.challenges
  where expires_at < now();

  -- Sessions: remove rows that are past their TTL or explicitly revoked,
  -- after a 7-day grace period.
  delete from public.sessions
  where
    expires_at  < now() - interval '7 days'
    or revoked_at < now() - interval '7 days';
$$;
