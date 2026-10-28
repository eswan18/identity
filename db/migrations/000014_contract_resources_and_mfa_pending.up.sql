-- The CONTRACT step for 000012 (resources) and 000013 (the carried authorize
-- request).
--
-- Design: docs/superpowers/specs/2026-10-27-resource-indicators-and-mcp-clients-design.md
-- (section 11).
--
-- 000012 and 000013 kept the old structures because the release serving when
-- each was applied still used them. Every release since #150 uses none of
-- them, so once no older pod is running they can go. Apply this only after
-- staging and prod both run a release at or after #150: an older pod would
-- break on its next query naming one of these.
--
-- The release built with this migration is the same code as the one before it;
-- only the migration version it expects changes. That is the proof the code
-- already matched this schema: sqlc generated it with oauth_clients.audience
-- dropped (db/sqlc_pending_contract.sql, deleted with this migration), and
-- dropping the auth_mfa_pending columns only removes fields of db.AuthMfaPending,
-- which nothing outside pkg/db reads.

-- Replaced by default_resource (000012). No query names it.
ALTER TABLE oauth_clients DROP COLUMN audience;

-- Consent is keyed by (user, client, resource) since 000012, through the
-- NULLS NOT DISTINCT unique index oauth_user_consents_user_client_resource_key,
-- which stays. This is the old (user, client) key, which only the pre-000012
-- release's upsert named in ON CONFLICT. With it gone, a user can hold one
-- consent per resource for the same client.
ALTER TABLE oauth_user_consents DROP CONSTRAINT oauth_user_consents_user_id_client_id_key;

-- The trigger filled oauth_tokens.resource for rows the pre-000012 release
-- inserted during the rollout, since that release did not know the column.
-- Every release since writes the resource itself (the issuer, for a token for
-- identity itself), so it never fires any more. The values it filled stay.
--
-- resource stays nullable. A NULL can still exist on rows from before 000012
-- whose client had no audience (the backfill skipped them; the old code refused
-- to mint for an empty audience, so these should be none or long expired), and
-- the right value for them is identity's issuer, which SQL does not know.
-- NULL is read as the issuer anyway (tokenAudience), so NOT NULL would buy
-- nothing but a migration that can fail on data it cannot see.
DROP TRIGGER oauth_tokens_fill_resource ON oauth_tokens;
DROP FUNCTION oauth_tokens_fill_resource();

-- The authorize request's fields, one column each, replaced by the single
-- authorize_query column (000013). No query names any of them.
ALTER TABLE auth_mfa_pending
    DROP COLUMN client_id,
    DROP COLUMN redirect_uri,
    DROP COLUMN state,
    DROP COLUMN scope,
    DROP COLUMN code_challenge,
    DROP COLUMN code_challenge_method,
    DROP COLUMN nonce;

-- For refresh-token reuse detection, which revokes a whole family at once
-- (family_id was added in 000012). Not CONCURRENTLY: golang-migrate runs this
-- file as one implicit transaction, and the table is small.
CREATE INDEX idx_oauth_tokens_family_id ON oauth_tokens (family_id);
