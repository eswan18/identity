DROP TABLE IF EXISTS oauth_tokens;
DROP TABLE IF EXISTS oauth_authorization_codes;
DROP TABLE IF EXISTS oauth_clients;
DROP TABLE IF EXISTS auth_users;
DROP TABLE IF EXISTS auth_sessions;

-- Optional: drop extensions if you know nothing else in the DB uses them
DROP EXTENSION IF EXISTS citext;
DROP EXTENSION IF EXISTS pgcrypto;