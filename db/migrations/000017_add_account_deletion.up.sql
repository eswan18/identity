-- Self-service account deletion: a user who deletes their account is
-- deactivated at once and stamped here; the cleanup worker erases the row
-- (cascading through every user-owned table) once the grace period has passed.
-- Reactivating during the grace period clears the stamp, cancelling deletion.
ALTER TABLE auth_users ADD COLUMN deletion_requested_at timestamptz;

CREATE INDEX idx_auth_users_deletion_requested_at
    ON auth_users (deletion_requested_at)
    WHERE deletion_requested_at IS NOT NULL;
