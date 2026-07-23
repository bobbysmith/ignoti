-- Immediately-prior restore-token hash, for single-generation reuse detection:
-- only a replay of the just-superseded secret revokes the session. Session ids
-- are not secret, so revoking on any mismatch would be a remote DoS.
alter table sessions add column if not exists prev_restore_token_hash text;
