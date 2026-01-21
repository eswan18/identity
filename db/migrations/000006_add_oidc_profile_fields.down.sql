-- Remove OIDC profile fields
ALTER TABLE auth_users DROP COLUMN IF EXISTS zoneinfo;
ALTER TABLE auth_users DROP COLUMN IF EXISTS locale;
ALTER TABLE auth_users DROP COLUMN IF EXISTS family_name;
ALTER TABLE auth_users DROP COLUMN IF EXISTS given_name;
ALTER TABLE auth_users DROP COLUMN IF EXISTS name;
