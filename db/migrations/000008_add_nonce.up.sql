ALTER TABLE oauth_authorization_codes ADD COLUMN nonce text;
ALTER TABLE auth_mfa_pending ADD COLUMN nonce text;
