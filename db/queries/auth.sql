-- name: CreateUser :one
INSERT INTO auth_users (username, email, password_hash)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetUserByUsername :one
SELECT *
FROM auth_users
WHERE username = $1
  AND is_active = true;

-- name: GetUserByEmail :one
SELECT *
FROM auth_users
WHERE email = $1
  AND is_active = true;

-- name: GetUserByID :one
SELECT *
FROM auth_users
WHERE id = $1
  AND is_active = true;

-- name: CreateOAuthClient :one
INSERT INTO oauth_clients (
  client_id,
  client_secret,
  name,
  redirect_uris,
  allowed_scopes,
  is_confidential,
  audience
)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetOAuthClientByClientID :one
SELECT *
FROM oauth_clients
WHERE client_id = $1;

-- name: GetOAuthClientByID :one
SELECT *
FROM oauth_clients
WHERE id = $1;

-- name: ListOAuthClients :many
SELECT *
FROM oauth_clients
ORDER BY created_at DESC;

-- name: UpdateOAuthClient :one
UPDATE oauth_clients
SET
  name = COALESCE(NULLIF(sqlc.narg(name)::text, ''), name),
  redirect_uris = COALESCE(sqlc.narg(redirect_uris)::text[], redirect_uris),
  allowed_scopes = COALESCE(sqlc.narg(allowed_scopes)::text[], allowed_scopes),
  is_confidential = COALESCE(sqlc.narg(is_confidential), is_confidential),
  audience = COALESCE(NULLIF(sqlc.narg(audience)::text, ''), audience),
  updated_at = now()
WHERE client_id = sqlc.arg(client_id)
RETURNING *;

-- name: DeleteOAuthClient :exec
DELETE FROM oauth_clients
WHERE client_id = $1;

-- name: InsertAuthorizationCode :exec
INSERT INTO oauth_authorization_codes (
  code,
  user_id,
  client_id,
  redirect_uri,
  scope,
  code_challenge,
  code_challenge_method,
  expires_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetAuthorizationCode :one
SELECT *
FROM oauth_authorization_codes
WHERE code = $1;

-- name: ConsumeAuthorizationCode :exec
UPDATE oauth_authorization_codes
SET consumed_at = now()
WHERE code = $1;

-- name: InsertToken :one
INSERT INTO oauth_tokens (
  access_token,
  refresh_token,
  user_id,
  client_id,
  scope,
  token_type,
  expires_at,
  refresh_expires_at
)
VALUES ($1, $2, $3, $4, $5, COALESCE(sqlc.narg(token_type)::text, 'bearer'), $6, $7)
RETURNING *;

-- name: GetTokenByAccessToken :one
SELECT *
FROM oauth_tokens
WHERE access_token = $1
  AND revoked_at IS NULL
  AND expires_at > now();

-- name: GetTokenByRefreshToken :one
SELECT *
FROM oauth_tokens
WHERE refresh_token = $1
  AND revoked_at IS NULL;

-- name: RevokeTokenByRefreshToken :exec
UPDATE oauth_tokens
SET revoked_at = now()
WHERE refresh_token = $1
  AND revoked_at IS NULL;

-- name: RevokeAllUserTokens :exec
UPDATE oauth_tokens
SET revoked_at = now()
WHERE user_id = $1
  AND revoked_at IS NULL;

-- name: CreateSession :exec
INSERT INTO auth_sessions (id, user_id, expires_at)
VALUES ($1, $2, $3);

-- name: GetSession :one
SELECT *
FROM auth_sessions
WHERE id = $1
  AND expires_at > now();

-- name: DeleteSession :exec
DELETE FROM auth_sessions
WHERE id = $1;

-- name: UpdateUserPassword :exec
UPDATE auth_users
SET password_hash = $1, updated_at = now()
WHERE id = $2;

-- name: UpdateUserUsername :exec
UPDATE auth_users
SET username = $1, updated_at = now()
WHERE id = $2;

-- name: UpdateUserEmail :exec
UPDATE auth_users
SET email = $1, updated_at = now()
WHERE id = $2;

-- name: DeactivateUser :exec
UPDATE auth_users
SET is_active = false, updated_at = now()
WHERE id = $1;

-- name: ReactivateUser :exec
UPDATE auth_users
SET is_active = true, updated_at = now()
WHERE id = $1;

-- name: GetUserByIDIncludingInactive :one
SELECT *
FROM auth_users
WHERE id = $1;

-- name: GetUserByUsernameIncludingInactive :one
SELECT *
FROM auth_users
WHERE username = $1;

-- MFA queries

-- name: GetUserMFAStatus :one
SELECT id, mfa_enabled, mfa_secret FROM auth_users WHERE id = $1;

-- name: EnableMFA :exec
UPDATE auth_users
SET mfa_enabled = true, mfa_secret = $2, mfa_verified_at = now(), updated_at = now()
WHERE id = $1;

-- name: DisableMFA :exec
UPDATE auth_users
SET mfa_enabled = false, mfa_secret = NULL, mfa_verified_at = NULL, updated_at = now()
WHERE id = $1;

-- name: CreateMFAPending :exec
INSERT INTO auth_mfa_pending (id, user_id, client_id, redirect_uri, state, scope, code_challenge, code_challenge_method, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetMFAPending :one
SELECT * FROM auth_mfa_pending
WHERE id = $1 AND expires_at > now();

-- name: DeleteMFAPending :exec
DELETE FROM auth_mfa_pending WHERE id = $1;

-- name: DeleteExpiredMFAPending :exec
DELETE FROM auth_mfa_pending WHERE expires_at <= now();

-- Email verification queries

-- name: SetEmailVerified :exec
UPDATE auth_users
SET email_verified = true, email_verified_at = now(), updated_at = now()
WHERE id = $1;

-- name: CreateEmailToken :exec
INSERT INTO auth_email_tokens (user_id, token_hash, token_type, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetEmailToken :one
SELECT * FROM auth_email_tokens
WHERE token_hash = $1 AND token_type = $2 AND expires_at > now() AND used_at IS NULL;

-- name: MarkEmailTokenUsed :exec
UPDATE auth_email_tokens SET used_at = now() WHERE id = $1;

-- name: DeleteExpiredEmailTokens :exec
DELETE FROM auth_email_tokens WHERE expires_at <= now();

-- name: DeleteUserEmailTokens :exec
DELETE FROM auth_email_tokens WHERE user_id = $1 AND token_type = $2;

-- Password reset token queries (using auth_email_tokens table)

-- name: CreatePasswordResetToken :exec
INSERT INTO auth_email_tokens (user_id, token_hash, token_type, expires_at)
VALUES ($1, $2, 'password_reset', $3);

-- name: GetPasswordResetTokenByHash :one
SELECT et.*, u.id as uid, u.username, u.email, u.password_hash
FROM auth_email_tokens et
JOIN auth_users u ON et.user_id = u.id
WHERE et.token_hash = $1
  AND et.token_type = 'password_reset'
  AND et.expires_at > now()
  AND et.used_at IS NULL;

-- name: MarkPasswordResetTokenUsed :exec
UPDATE auth_email_tokens
SET used_at = now()
WHERE token_hash = $1 AND token_type = 'password_reset';

-- name: DeleteExpiredPasswordResetTokens :exec
DELETE FROM auth_email_tokens
WHERE token_type = 'password_reset'
  AND (expires_at <= now() OR used_at IS NOT NULL);
