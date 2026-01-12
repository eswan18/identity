-- Add MFA columns to auth_users table
ALTER TABLE auth_users ADD COLUMN mfa_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE auth_users ADD COLUMN mfa_secret text;
ALTER TABLE auth_users ADD COLUMN mfa_verified_at timestamptz;

-- Create table for pending MFA sessions (short-lived tokens after password validation)
CREATE TABLE auth_mfa_pending (
    id              text            PRIMARY KEY,
    user_id         uuid            NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    client_id       text,
    redirect_uri    text,
    state           text,
    scope           text[],
    code_challenge  text,
    code_challenge_method text,
    created_at      timestamptz     NOT NULL DEFAULT now(),
    expires_at      timestamptz     NOT NULL
);

CREATE INDEX idx_mfa_pending_user_id ON auth_mfa_pending(user_id);
CREATE INDEX idx_mfa_pending_expires_at ON auth_mfa_pending(expires_at);
