-- Remove avatar picture column
ALTER TABLE auth_users DROP COLUMN IF EXISTS picture;
