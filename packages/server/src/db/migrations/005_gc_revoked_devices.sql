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
$$;
