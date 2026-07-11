-- Hash existing OAuth client secrets at rest.
--
-- Client secrets were previously stored as plaintext, so a database dump
-- disclosed every client's usable credential. Replace each plaintext secret
-- with its lowercase hex-encoded SHA-256 hash. This matches exactly what the
-- Go code produces via hex.EncodeToString(sha256.Sum256([]byte(secret))[:]),
-- so existing clients continue to authenticate with their original secret.
--
-- digest() comes from the pgcrypto extension, which is already enabled in
-- migration 000001; CREATE EXTENSION IF NOT EXISTS is a harmless no-op if so.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

UPDATE oauth_clients
SET client_secret = encode(digest(client_secret, 'sha256'), 'hex')
WHERE client_secret IS NOT NULL;
