-- Replay-nonce store for session request signatures. Replaces the per-process
-- in-memory cache: the primary-key insert is the atomic single-use check, so
-- replay protection holds across any number of server instances.
create table if not exists session_nonces (
  jti        uuid primary key,
  expires_at timestamptz not null
);

create index if not exists session_nonces_expires_idx on session_nonces(expires_at);

alter table session_nonces enable row level security;

-- Rows only need to outlive the signature tolerance window; after that the
-- timestamp check rejects the request before the nonce is consulted, so
-- expired rows are dead weight until GC runs.
create or replace function ignoti_gc() returns void
language sql
set search_path = ''
as $$
  delete from public.challenges
  where expires_at < now();

  delete from public.sessions
  where
    expires_at  < now() - interval '7 days'
    or revoked_at < now() - interval '7 days';

  delete from public.devices
  where revoked_at < now() - interval '7 days';

  delete from public.session_nonces
  where expires_at < now();
$$;