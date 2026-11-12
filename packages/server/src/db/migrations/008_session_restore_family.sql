-- SHA-256 hash of the per-session restore family secret. The family secret is
-- minted at login, never rotates, and is carried in every restore cookie, so a
-- cookie with a matching family but a non-current rotating secret is an earlier
-- cookie of the session being replayed (any generation) and revokes it.
-- Replaces prev_restore_token_hash, which only covered the previous generation.
alter table sessions add column if not exists restore_family_hash text;
alter table sessions drop column if exists prev_restore_token_hash;
