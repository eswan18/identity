-- Pending TOTP secrets generated during MFA enrollment.
--
-- The secret is held server-side (never round-tripped through the browser) and is
-- keyed by user_id so the enrollment POST validates the submitted code against a
-- secret the client cannot choose. One in-flight enrollment per user: a fresh setup
-- GET replaces any prior pending secret via upsert. Rows are short-lived and expire.
--
-- This is deliberately separate from auth_mfa_pending, which stores login-time MFA
-- challenges (OAuth authorization context, keyed by a random id passed through the
-- browser). That table has no column for an enrollment secret and a different key
-- and lifecycle, so mixing the two concerns there would be incorrect.
CREATE TABLE auth_mfa_enrollment_pending (
    user_id     uuid            PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,
    secret      text            NOT NULL,
    created_at  timestamptz     NOT NULL DEFAULT now(),
    expires_at  timestamptz     NOT NULL
);

CREATE INDEX idx_mfa_enrollment_pending_expires_at ON auth_mfa_enrollment_pending(expires_at);
