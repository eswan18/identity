-- Remove MFA pending sessions table
DROP TABLE IF EXISTS auth_mfa_pending;

-- Remove MFA columns from auth_users table
ALTER TABLE auth_users DROP COLUMN IF EXISTS mfa_verified_at;
ALTER TABLE auth_users DROP COLUMN IF EXISTS mfa_secret;
ALTER TABLE auth_users DROP COLUMN IF EXISTS mfa_enabled;
