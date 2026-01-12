-- Add email verification status to users
ALTER TABLE auth_users ADD COLUMN email_verified boolean NOT NULL DEFAULT false;
ALTER TABLE auth_users ADD COLUMN email_verified_at timestamptz;

-- Create table for email verification tokens (and future password reset tokens)
CREATE TABLE auth_email_tokens (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    token_hash      text NOT NULL,          -- SHA-256 hash of token
    token_type      text NOT NULL,          -- 'verification' (future: 'password_reset')
    expires_at      timestamptz NOT NULL,
    used_at         timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- Index for looking up tokens by hash
CREATE INDEX idx_email_tokens_hash ON auth_email_tokens(token_hash);

-- Index for looking up user's tokens by type
CREATE INDEX idx_email_tokens_user_type ON auth_email_tokens(user_id, token_type);
