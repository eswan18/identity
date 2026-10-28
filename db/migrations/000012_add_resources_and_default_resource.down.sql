-- Reverse 000012. Lossy only for what the old schema cannot hold: resources
-- nobody uses as a default, allow-lists, CIMD clients' kind, and per-resource
-- consents (there are none until requests can name a resource).

DROP INDEX IF EXISTS oauth_user_consents_user_client_resource_key;
ALTER TABLE oauth_user_consents DROP COLUMN IF EXISTS resource;

DROP TRIGGER IF EXISTS oauth_tokens_fill_resource ON oauth_tokens;
DROP FUNCTION IF EXISTS oauth_tokens_fill_resource();

ALTER TABLE oauth_tokens
    DROP COLUMN IF EXISTS revoked_reason,
    DROP COLUMN IF EXISTS family_id,
    DROP COLUMN IF EXISTS resource;

ALTER TABLE oauth_authorization_codes DROP COLUMN IF EXISTS resource;

DROP TABLE IF EXISTS oauth_client_resources;

ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS metadata_fetched_at,
    DROP COLUMN IF EXISTS kind;

-- audience again holds what tokens are minted for. A client with no default
-- resource goes back to the empty audience the old code refuses to mint for,
-- which is where such a client started.
UPDATE oauth_clients SET audience = COALESCE(default_resource, '');
ALTER TABLE oauth_clients ALTER COLUMN audience SET NOT NULL;

ALTER TABLE oauth_clients DROP COLUMN IF EXISTS default_resource;

DROP TABLE IF EXISTS oauth_resources;
