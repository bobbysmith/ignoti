-- Refresh-token rotation with reuse detection for session restore (RFC 9700).
-- The session cookie now carries a rotating secret; only its SHA-256 hash is
-- stored here. On each /session/restore the secret is rotated. A presented
-- secret that does not match the current hash of an otherwise-active session
-- indicates a stolen/replayed cookie and triggers revocation of that session.
--
-- Existing sessions have a NULL hash: their old-format cookies (bare session id,
-- no secret) fail the restore parse cleanly and the user simply re-authenticates.
alter table sessions add column if not exists restore_token_hash text;
