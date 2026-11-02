DROP INDEX IF EXISTS idx_auth_users_deletion_requested_at;
ALTER TABLE auth_users DROP COLUMN IF EXISTS deletion_requested_at;
