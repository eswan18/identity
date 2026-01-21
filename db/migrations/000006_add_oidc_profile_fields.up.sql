-- Add OIDC standard profile claim fields
ALTER TABLE auth_users ADD COLUMN name text;
ALTER TABLE auth_users ADD COLUMN given_name text;
ALTER TABLE auth_users ADD COLUMN family_name text;
ALTER TABLE auth_users ADD COLUMN locale text;
ALTER TABLE auth_users ADD COLUMN zoneinfo text;
