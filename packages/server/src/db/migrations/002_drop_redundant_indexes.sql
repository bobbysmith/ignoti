-- devices_credential_id_idx and challenges_value_idx duplicate the implicit
-- indexes created by the UNIQUE constraints on those columns. Drop them.
drop index if exists devices_credential_id_idx;
drop index if exists challenges_value_idx;