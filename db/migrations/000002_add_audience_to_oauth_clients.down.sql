-- Remove audience column from oauth_clients table
ALTER TABLE oauth_clients DROP COLUMN audience;
