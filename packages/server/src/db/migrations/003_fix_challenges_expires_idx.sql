-- challenges_expires_idx was defined as a partial index (WHERE consumed_at IS NULL)
-- but ghostid_gc() deletes all expired challenges regardless of consumed_at, so the
-- planner never used it for the cleanup query. Drop the WHERE clause so the index
-- covers all rows and the GC delete can use it.
drop index if exists challenges_expires_idx;
create index challenges_expires_idx on challenges(expires_at);