-- Add timestamps for tracking login and password change events
ALTER TABLE auth_users ADD COLUMN last_login_at timestamptz;
ALTER TABLE auth_users ADD COLUMN password_changed_at timestamptz;
