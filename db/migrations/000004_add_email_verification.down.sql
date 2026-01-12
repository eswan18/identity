-- Remove email tokens table
DROP TABLE IF EXISTS auth_email_tokens;

-- Remove email verification columns from users
ALTER TABLE auth_users DROP COLUMN IF EXISTS email_verified_at;
ALTER TABLE auth_users DROP COLUMN IF EXISTS email_verified;
