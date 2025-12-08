-- Enable extensions we rely on
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- ============================
-- Users
-- ============================
CREATE TABLE auth_users (
    id              uuid            PRIMARY KEY DEFAULT gen_random_uuid(),
    username        text            NOT NULL UNIQUE,
    password_hash   text            NOT NULL,
    email           citext          NOT NULL UNIQUE,
    is_active       boolean         NOT NULL DEFAULT true,
    created_at      timestamptz     NOT NULL DEFAULT now(),
    updated_at      timestamptz     NOT NULL DEFAULT now()
);


-- ============================
-- OAuth Clients
-- ============================
CREATE TABLE oauth_clients (
    id               uuid            PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id        text            NOT NULL UNIQUE,
    client_secret    text,                          -- NULL for public clients (SPAs, mobile)
    name             text            NOT NULL,
    redirect_uris    text[]          NOT NULL,      -- list of allowed redirect URIs
    allowed_scopes   text[]          NOT NULL DEFAULT '{}'::text[],
    is_confidential  boolean         NOT NULL DEFAULT true,
    created_at       timestamptz     NOT NULL DEFAULT now(),
    updated_at       timestamptz     NOT NULL DEFAULT now(),

    -- If the client is confidential, it must have a secret
    CHECK (is_confidential = false OR client_secret IS NOT NULL)
);
CREATE INDEX idx_oauth_clients_client_id ON oauth_clients (client_id);

-- ============================
-- Authorization Codes
-- ============================
CREATE TABLE oauth_authorization_codes (
    code                  text        PRIMARY KEY,  -- random string
    user_id               uuid        NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    client_id             uuid        NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    redirect_uri          text        NOT NULL,
    scope                 text[]      NOT NULL,
    code_challenge        text,                    -- for PKCE
    code_challenge_method text,                    -- "S256", "plain", etc.
    expires_at            timestamptz NOT NULL,
    consumed_at           timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_oauth_authorization_codes_client_user
    ON oauth_authorization_codes (client_id, user_id);

CREATE INDEX idx_oauth_authorization_codes_expires_at
    ON oauth_authorization_codes (expires_at);

-- ============================
-- Tokens (Access + Refresh)
-- ============================
CREATE TABLE oauth_tokens (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- You can store opaque tokens here, or token IDs if you use JWTs
    access_token       text        UNIQUE,
    refresh_token      text        UNIQUE,

    user_id            uuid        REFERENCES auth_users(id) ON DELETE CASCADE,
    client_id          uuid        NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scope              text[]      NOT NULL,

    token_type         text        NOT NULL DEFAULT 'bearer',

    expires_at         timestamptz NOT NULL,         -- access token expiry
    refresh_expires_at timestamptz,                  -- optional separate refresh expiry
    revoked_at         timestamptz,                  -- set when revoked

    created_at         timestamptz NOT NULL DEFAULT now()
);

-- Common indexes / partial indexes
CREATE INDEX idx_oauth_tokens_access_active
    ON oauth_tokens (access_token)
    WHERE revoked_at IS NULL;

CREATE INDEX idx_oauth_tokens_refresh_active
    ON oauth_tokens (refresh_token)
    WHERE revoked_at IS NULL;

CREATE INDEX idx_oauth_tokens_user_client
    ON oauth_tokens (user_id, client_id);
