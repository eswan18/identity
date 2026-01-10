-- Add audience column to oauth_clients table
-- The audience identifies which API/resource server the client is requesting access to
ALTER TABLE oauth_clients ADD COLUMN audience text NOT NULL DEFAULT '';

-- Remove default after adding the column (new clients must specify audience)
ALTER TABLE oauth_clients ALTER COLUMN audience DROP DEFAULT;
