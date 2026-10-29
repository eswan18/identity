-- Reverse 000016. Lossy only in that which clients were trusted is forgotten:
-- every client asks for consent again, as before.
ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS oauth_clients_trusted_registered_only,
    DROP COLUMN IF EXISTS trusted;
