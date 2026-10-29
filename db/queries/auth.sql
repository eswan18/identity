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

-- OAuth clients
--
-- Every oauth_clients query lists its columns rather than using *. sqlc expands
-- * into an explicit list at generation time, so * bakes in every column the
-- table has, and a running pod whose query names a column breaks the moment a
-- migration drops it (as 000014 dropped audience, which 000012 deprecated). The
-- order matches the table so sqlc maps every one of these onto db.OauthClient.

-- name: CreateOAuthClient :one
INSERT INTO oauth_clients (
  client_id,
  client_secret,
  name,
  redirect_uris,
  allowed_scopes,
  is_confidential,
  default_resource,
  trusted
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, client_id, client_secret, name, redirect_uris, allowed_scopes,
  is_confidential, created_at, updated_at, default_resource, kind,
  metadata_fetched_at, trusted;

-- name: GetOAuthClientByClientID :one
SELECT id, client_id, client_secret, name, redirect_uris, allowed_scopes,
  is_confidential, created_at, updated_at, default_resource, kind,
  metadata_fetched_at, trusted
FROM oauth_clients
WHERE client_id = $1;

-- name: GetOAuthClientByID :one
SELECT id, client_id, client_secret, name, redirect_uris, allowed_scopes,
  is_confidential, created_at, updated_at, default_resource, kind,
  metadata_fetched_at, trusted
FROM oauth_clients
WHERE id = $1;

-- name: ListOAuthClients :many
SELECT id, client_id, client_secret, name, redirect_uris, allowed_scopes,
  is_confidential, created_at, updated_at, default_resource, kind,
  metadata_fetched_at, trusted
FROM oauth_clients
ORDER BY created_at DESC;

-- name: UpdateOAuthClient :one
-- default_resource is replaced only when set_default_resource is true, and then
-- with whatever default_resource holds, NULL included: that is how a client's
-- default is cleared, which a COALESCE(NULLIF(...)) like the others cannot do.
-- trusted is left alone when NULL; the table's CHECK refuses it for anything
-- but a registered client (README, "Trusted (first-party) clients").
UPDATE oauth_clients
SET
  name = COALESCE(NULLIF(sqlc.narg(name)::text, ''), name),
  redirect_uris = COALESCE(sqlc.narg(redirect_uris)::text[], redirect_uris),
  allowed_scopes = COALESCE(sqlc.narg(allowed_scopes)::text[], allowed_scopes),
  is_confidential = COALESCE(sqlc.narg(is_confidential), is_confidential),
  trusted = COALESCE(sqlc.narg(trusted), trusted),
  default_resource = CASE
    WHEN sqlc.arg(set_default_resource)::boolean THEN sqlc.narg(default_resource)::text
    ELSE default_resource
  END,
  updated_at = now()
WHERE client_id = sqlc.arg(client_id)
RETURNING id, client_id, client_secret, name, redirect_uris, allowed_scopes,
  is_confidential, created_at, updated_at, default_resource, kind,
  metadata_fetched_at, trusted;

-- name: DeleteOAuthClient :exec
DELETE FROM oauth_clients
WHERE client_id = $1;

-- Clients identified by a Client ID Metadata Document (kind = 'cimd'). Their
-- row is materialized from the document, which the server fetches, rather than
-- registered (pkg/httpserver/cimd_clients.go). The document's URL is the
-- client_id; it is a public client with no secret, no default resource and no
-- registered allowed_scopes (its scopes are computed per request).

-- name: GetOAuthClientByClientIDForUpdate :one
SELECT id, client_id, client_secret, name, redirect_uris, allowed_scopes,
  is_confidential, created_at, updated_at, default_resource, kind,
  metadata_fetched_at, trusted
FROM oauth_clients
WHERE client_id = $1
FOR UPDATE;

-- name: CreateCIMDClient :one
-- ON CONFLICT DO NOTHING: two requests materializing the same client at once
-- both insert, and the loser gets no row back (sql.ErrNoRows) and reads the
-- winner's instead.
INSERT INTO oauth_clients (
  client_id,
  client_secret,
  name,
  redirect_uris,
  allowed_scopes,
  is_confidential,
  default_resource,
  kind,
  metadata_fetched_at
)
VALUES (
  sqlc.arg(client_id), NULL, sqlc.arg(name), sqlc.arg(redirect_uris)::text[],
  '{}'::text[], false, NULL, 'cimd', sqlc.arg(metadata_fetched_at)
)
ON CONFLICT (client_id) DO NOTHING
RETURNING id, client_id, client_secret, name, redirect_uris, allowed_scopes,
  is_confidential, created_at, updated_at, default_resource, kind,
  metadata_fetched_at, trusted;

-- name: UpdateCIMDClient :one
UPDATE oauth_clients
SET
  name = sqlc.arg(name),
  redirect_uris = sqlc.arg(redirect_uris)::text[],
  metadata_fetched_at = sqlc.arg(metadata_fetched_at),
  updated_at = now()
WHERE id = sqlc.arg(id) AND kind = 'cimd'
RETURNING id, client_id, client_secret, name, redirect_uris, allowed_scopes,
  is_confidential, created_at, updated_at, default_resource, kind,
  metadata_fetched_at, trusted;

-- OAuth resources: the APIs tokens are minted for (a token's aud is its uri).

-- name: CreateOAuthResource :one
INSERT INTO oauth_resources (uri, name, scopes, dynamic_clients)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetOAuthResourceByURI :one
SELECT *
FROM oauth_resources
WHERE uri = $1;

-- name: ListOAuthResources :many
SELECT *
FROM oauth_resources
ORDER BY uri;

-- name: UpdateOAuthResource :one
-- Every field is replaced: the CLI reads the row, applies the flags it was
-- given, and writes the whole result back. The uri is the key and never
-- changes here (it is every token's aud; see the spec, section 1).
UPDATE oauth_resources
SET name = sqlc.arg(name),
    scopes = sqlc.arg(scopes),
    dynamic_clients = sqlc.arg(dynamic_clients)
WHERE uri = sqlc.arg(uri)
RETURNING *;

-- name: DeleteOAuthResource :execrows
DELETE FROM oauth_resources
WHERE uri = $1;

-- name: ListClientsReferencingResource :many
-- The clients that name a resource, as their default or on their allow-list.
-- A resource is not deleted while this is non-empty.
SELECT c.client_id, c.name,
       (c.default_resource IS NOT NULL AND c.default_resource = r.uri)::boolean AS is_default
FROM oauth_resources r
JOIN oauth_clients c
  ON c.default_resource = r.uri
  OR EXISTS (
       SELECT 1 FROM oauth_client_resources cr
       WHERE cr.client_id = c.id AND cr.resource_id = r.id
     )
WHERE r.uri = $1
ORDER BY c.name, c.client_id;

-- Client resource allow-lists: the resources a registered client may request
-- by name, beyond its default (which is always allowed).

-- name: ClientMayRequestResource :one
SELECT EXISTS (
  SELECT 1
  FROM oauth_client_resources
  WHERE client_id = $1 AND resource_id = $2
);

-- name: ListClientResources :many
SELECT r.*
FROM oauth_client_resources cr
JOIN oauth_resources r ON r.id = cr.resource_id
WHERE cr.client_id = $1
ORDER BY r.uri;

-- name: AddClientResource :exec
INSERT INTO oauth_client_resources (client_id, resource_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: RemoveClientResource :execrows
DELETE FROM oauth_client_resources
WHERE client_id = $1 AND resource_id = $2;

-- name: InsertAuthorizationCode :exec
INSERT INTO oauth_authorization_codes (
  code,
  user_id,
  client_id,
  redirect_uri,
  scope,
  code_challenge,
  code_challenge_method,
  expires_at,
  nonce,
  resource
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: GetAuthorizationCode :one
SELECT *
FROM oauth_authorization_codes
WHERE code = $1;

-- name: ConsumeAuthorizationCode :execrows
-- Atomically consume an authorization code. Returns 1 if the code was consumed,
-- 0 if it was already consumed (or doesn't exist). Callers MUST check the row
-- count to prevent token issuance on a replayed code — see RFC 6749 §10.5.
UPDATE oauth_authorization_codes
SET consumed_at = now()
WHERE code = $1 AND consumed_at IS NULL;

-- name: InsertToken :one
-- family_id is the refresh-token family (lineage) the row belongs to: started
-- by the code exchange, copied by every refresh. NULL for rows with no refresh
-- token (client_credentials). See handleRefreshTokenGrant.
INSERT INTO oauth_tokens (
  access_token,
  refresh_token,
  user_id,
  client_id,
  scope,
  token_type,
  expires_at,
  refresh_expires_at,
  resource,
  family_id
)
VALUES ($1, $2, $3, $4, $5, COALESCE(sqlc.narg(token_type)::text, 'bearer'), $6, $7, sqlc.narg(resource), sqlc.narg(family_id))
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

-- name: GetTokenByRefreshTokenIncludingRevoked :one
-- The refresh grant's lookup. Unlike GetTokenByRefreshToken it returns revoked
-- rows too, because how a refresh token died decides what presenting it again
-- means: one revoked because it was rotated is a replay (reuse detection), any
-- other is just dead.
SELECT *
FROM oauth_tokens
WHERE refresh_token = $1;

-- name: RotateRefreshToken :execrows
-- Atomically spend a refresh token on a refresh. Returns 1 if this call spent
-- it, 0 if it was already revoked (or doesn't exist). Callers MUST check the row
-- count and refuse to hand out new tokens on a 0 result -- otherwise two
-- concurrent refreshes presenting the same refresh token could both succeed.
--
-- A row from before reuse detection has no family; it gets the one its
-- replacement was minted into, so replaying it later finds that family.
UPDATE oauth_tokens
SET revoked_at = now(),
    revoked_reason = 'rotated',
    family_id = COALESCE(family_id, sqlc.arg(family_id)::uuid)
WHERE refresh_token = $1
  AND revoked_at IS NULL;

-- name: RevokeTokenFamily :execrows
-- Revoke every live token in a refresh-token family (access tokens included:
-- they share the row). Returns how many were live.
UPDATE oauth_tokens
SET revoked_at = now(),
    revoked_reason = sqlc.arg(reason)::text
WHERE family_id = sqlc.arg(family_id)::uuid
  AND revoked_at IS NULL;

-- name: RevokeTokenByRefreshToken :execrows
-- Every revocation records why in revoked_reason (see revocationReason in
-- pkg/httpserver); rows revoked before reasons were recorded have NULL.
-- Returns 1 if the token was revoked, 0 if it was already revoked (or doesn't
-- exist). A refresh spends its token with RotateRefreshToken, not this.
UPDATE oauth_tokens
SET revoked_at = now(),
    revoked_reason = sqlc.arg(reason)::text
WHERE refresh_token = $1
  AND revoked_at IS NULL;

-- name: RevokeTokenByAccessToken :exec
UPDATE oauth_tokens
SET revoked_at = now(),
    revoked_reason = sqlc.arg(reason)::text
WHERE access_token = $1
  AND revoked_at IS NULL;

-- name: RevokeAllUserTokens :exec
UPDATE oauth_tokens
SET revoked_at = now(),
    revoked_reason = sqlc.arg(reason)::text
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

-- name: DeleteAllUserSessions :exec
DELETE FROM auth_sessions
WHERE user_id = $1;

-- name: UpdateUserPasswordWithTimestamp :exec
UPDATE auth_users
SET password_hash = $1, password_changed_at = now(), updated_at = now()
WHERE id = $2;

-- name: UpdateUserLastLogin :exec
UPDATE auth_users
SET last_login_at = now(), updated_at = now()
WHERE id = $1;

-- name: UpdateUserUsername :exec
UPDATE auth_users
SET username = $1, updated_at = now()
WHERE id = $2;

-- name: UpdateUserEmail :exec
-- Changing the email address invalidates any prior verification: the user
-- has not proven ownership of the new address, so email_verified must be
-- reset to false here rather than left at its previous value.
UPDATE auth_users
SET email = $1, email_verified = false, updated_at = now()
WHERE id = $2;

-- name: UpdateUserProfile :exec
UPDATE auth_users
SET given_name = $1, family_name = $2, updated_at = now()
WHERE id = $3;

-- name: UpdateUserPicture :exec
UPDATE auth_users
SET picture = $1, updated_at = now()
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

-- name: ListUsers :many
SELECT *
FROM auth_users
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountUsers :one
SELECT COUNT(*) FROM auth_users;

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
-- authorize_query is the original /oauth/authorize request's query string
-- (NULL outside an OAuth flow). The table's older per-parameter columns are
-- no longer written or read; see migration 000013.
INSERT INTO auth_mfa_pending (id, user_id, authorize_query, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetMFAPending :one
SELECT id, user_id, authorize_query, created_at, expires_at FROM auth_mfa_pending
WHERE id = $1 AND expires_at > now();

-- name: DeleteMFAPending :exec
DELETE FROM auth_mfa_pending WHERE id = $1;

-- name: DeleteExpiredMFAPending :exec
DELETE FROM auth_mfa_pending WHERE expires_at <= now();

-- MFA enrollment pending secrets (server-side, keyed by user)

-- name: CreateMFAEnrollmentPending :exec
INSERT INTO auth_mfa_enrollment_pending (user_id, secret, expires_at)
VALUES ($1, $2, $3)
ON CONFLICT (user_id) DO UPDATE
SET secret = EXCLUDED.secret,
    created_at = now(),
    expires_at = EXCLUDED.expires_at;

-- name: GetMFAEnrollmentPending :one
SELECT * FROM auth_mfa_enrollment_pending
WHERE user_id = $1 AND expires_at > now();

-- name: DeleteMFAEnrollmentPending :exec
DELETE FROM auth_mfa_enrollment_pending WHERE user_id = $1;

-- name: DeleteExpiredMFAEnrollmentPending :exec
DELETE FROM auth_mfa_enrollment_pending WHERE expires_at <= now();

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

-- name: MarkPasswordResetTokenUsed :execrows
-- Atomically mark a password reset token as used. Returns 1 if the token was
-- marked, 0 if it was already used (or doesn't exist / wrong type). Callers
-- MUST check the row count and refuse the reset if 0 — otherwise a replayed
-- token can reset the password more than once.
UPDATE auth_email_tokens
SET used_at = now()
WHERE token_hash = $1 AND token_type = 'password_reset' AND used_at IS NULL;

-- name: DeleteExpiredPasswordResetTokens :exec
DELETE FROM auth_email_tokens
WHERE token_type = 'password_reset'
  AND (expires_at <= now() OR used_at IS NOT NULL);

-- name: DeleteExpiredSessions :exec
-- auth_sessions reads (GetSession) filter on expires_at > now(), so an expired
-- session can never be used again -- safe to delete outright.
DELETE FROM auth_sessions
WHERE expires_at <= now();

-- name: DeleteExpiredAuthorizationCodes :exec
-- Authorization codes are single-use and short-lived; a consumed OR expired
-- code can never yield tokens (replay of a consumed code is rejected by the
-- atomic ConsumeAuthorizationCode update), so both are safe to delete.
DELETE FROM oauth_authorization_codes
WHERE expires_at <= now() OR consumed_at IS NOT NULL;

-- name: DeleteDeadTokens :exec
-- Each row holds both an access token (expires_at) and a refresh token
-- (refresh_expires_at, which is NULLABLE -- NULL means the refresh token never
-- expires). A row is only safe to delete once it can never be used again:
-- either it has been revoked, or the access token is expired AND the refresh
-- token is also expired (never delete just because expires_at passed -- a
-- non-revoked row whose refresh token is still valid, or non-expiring, must
-- be kept since it can still mint new access tokens).
--
-- Except a refresh token revoked because it was rotated: it is kept until it
-- would have expired, because presenting it again is how reuse is detected,
-- and a deleted row can only answer "unknown token". Past its expiry a replay
-- is refused as expired and detects nothing, so the row can go then.
DELETE FROM oauth_tokens
WHERE (revoked_at IS NOT NULL
       AND NOT (revoked_reason IS NOT DISTINCT FROM 'rotated'
                AND (refresh_expires_at IS NULL OR refresh_expires_at > now())))
   OR (expires_at <= now()
       AND refresh_expires_at IS NOT NULL
       AND refresh_expires_at <= now());

-- Consent queries

-- Consent is remembered per (user, client, resource): approving one resource
-- for a client does not approve another. resource is the URI the grant is for,
-- or NULL for a grant for identity itself, and IS NOT DISTINCT FROM makes NULL
-- match NULL, like the unique index (NULLS NOT DISTINCT) that the upsert names.

-- name: GetUserConsent :one
SELECT * FROM oauth_user_consents
WHERE user_id = sqlc.arg(user_id)
  AND client_id = sqlc.arg(client_id)
  AND resource IS NOT DISTINCT FROM sqlc.narg(resource)::text;

-- name: UpsertUserConsent :exec
INSERT INTO oauth_user_consents (user_id, client_id, resource, scopes)
VALUES (sqlc.arg(user_id), sqlc.arg(client_id), sqlc.narg(resource)::text, sqlc.arg(scopes))
ON CONFLICT (user_id, client_id, resource)
DO UPDATE SET scopes = EXCLUDED.scopes, updated_at = now();

-- name: DeleteUserConsentsForClient :execrows
-- Every user's remembered consent for one client, for every resource. Used
-- when a metadata-document client's redirect_uris change (CIMD §8.4): what
-- users approved was sending answers to the old ones.
DELETE FROM oauth_user_consents
WHERE client_id = sqlc.arg(client_id);

-- Connected apps (the account page that lists and disconnects them).

-- name: ListUserConnectedApps :many
-- One row per remembered consent of one user: the client it was given to, and
-- the resource it was for (resource_name is NULL for a consent for identity
-- itself, or for a resource since removed from the registry). The page groups
-- rows by client. Trusted (first-party) clients are never listed: identity
-- writes no consent for them, and one left over from before a client was
-- trusted is ignored here rather than shown.
SELECT
  c.id AS client_uuid,
  c.client_id,
  c.name AS client_name,
  c.kind AS client_kind,
  uc.resource,
  r.name AS resource_name,
  COALESCE(r.scopes, '{}'::jsonb)::jsonb AS resource_scopes,
  uc.scopes,
  uc.created_at,
  uc.updated_at
FROM oauth_user_consents uc
JOIN oauth_clients c ON c.id = uc.client_id
LEFT JOIN oauth_resources r ON r.uri = uc.resource
WHERE uc.user_id = sqlc.arg(user_id)
  AND NOT c.trusted
ORDER BY c.name, c.id, uc.resource NULLS FIRST;

-- name: ListUserTokenLastIssued :many
-- When a token was last issued to one user, per client: by a code exchange or
-- a refresh, each of which inserts an oauth_tokens row. A client whose rows
-- are all gone (the cleanup sweep deletes dead ones) has no row here.
SELECT client_id, max(created_at)::timestamptz AS last_issued_at
FROM oauth_tokens
WHERE user_id = sqlc.arg(user_id)::uuid
GROUP BY client_id;

-- name: DeleteUserConsentsForUserClient :execrows
-- One user's remembered consents for one client, for every resource, so the
-- next sign-in to it asks again. Returns how many there were.
DELETE FROM oauth_user_consents
WHERE user_id = sqlc.arg(user_id)
  AND client_id = sqlc.arg(client_id);

-- name: RevokeUserClientTokens :execrows
-- Every live token (access and refresh: they share the row) one user holds for
-- one client. Returns how many were live.
UPDATE oauth_tokens
SET revoked_at = now(),
    revoked_reason = sqlc.arg(reason)::text
WHERE user_id = sqlc.arg(user_id)::uuid
  AND client_id = sqlc.arg(client_id)
  AND revoked_at IS NULL;

-- name: DeleteUnconsumedUserClientAuthorizationCodes :execrows
-- Codes issued to one user for one client and not yet exchanged, so one in
-- flight cannot be redeemed for tokens after the user disconnected the client.
DELETE FROM oauth_authorization_codes
WHERE user_id = sqlc.arg(user_id)
  AND client_id = sqlc.arg(client_id)
  AND consumed_at IS NULL;
