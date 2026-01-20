-- Remove login and password timestamp columns
ALTER TABLE auth_users DROP COLUMN IF EXISTS password_changed_at;
ALTER TABLE auth_users DROP COLUMN IF EXISTS last_login_at;
