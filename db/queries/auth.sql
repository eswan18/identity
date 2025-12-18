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

-- name: CreateOAuthClient :one
INSERT INTO oauth_clients (
  client_id,
  client_secret,
  name,
  redirect_uris,
  allowed_scopes,
  is_confidential
)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetOAuthClientByClientID :one
SELECT *
FROM oauth_clients
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
VALUES ($1, $2, $3, $4, $5, COALESCE($6, 'bearer'), $7, $8)
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
