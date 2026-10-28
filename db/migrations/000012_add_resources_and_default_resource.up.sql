-- Resources registry and per-client default resource: the EXPAND step.
--
-- Design: docs/superpowers/specs/2026-10-27-resource-indicators-and-mcp-clients-design.md
-- (sections 1, 2, 4 and 11).
--
-- identity refuses to start unless the database is at exactly its migration
-- version, but pods that are already running never re-check. So this migration
-- is applied while the previous release is still serving, and everything here
-- has to leave that release working:
--
--   * oauth_clients.audience stays, and is still written by the old code. Only
--     its NOT NULL goes, because the new code no longer names the column. A
--     later CONTRACT migration drops it once no pod reads it.
--   * The old UNIQUE (user_id, client_id) on oauth_user_consents stays, because
--     the old code's upsert names it in ON CONFLICT. The new, wider key is added
--     beside it; the contract migration drops the old one.
--   * Tokens the old code mints in the rollout window would have no resource,
--     and the new code refreshes a token with the resource stored on it. The
--     trigger at the bottom fills that in so those refreshes keep their aud.
--
-- Contract-migration checklist (not this file): drop oauth_clients.audience,
-- drop the oauth_user_consents_user_id_client_id_key constraint, drop the
-- oauth_tokens_fill_resource trigger and function, and delete
-- db/sqlc_pending_contract.sql (see sqlc.yaml).

-- ============================
-- Resources
-- ============================
-- A resource is an API that tokens can be minted for. Its uri is the token's
-- aud, stored in canonical form for new rows (lowercase scheme and host, no
-- default port, no trailing slash, no fragment; https required). Rows backfilled
-- below keep their value byte for byte, which is what grandfathers the URN-style
-- "ethanswan:fitness": footstrike-api compares aud to it exactly.
CREATE TABLE oauth_resources (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    uri              text        NOT NULL UNIQUE CHECK (uri <> ''),
    name             text        NOT NULL,
    -- {scope: description}: the scopes this resource defines, with the text the
    -- consent screen shows for each.
    scopes           jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(scopes) = 'object'),
    -- Whether clients identified by a metadata document (CIMD) may request it.
    dynamic_clients  boolean     NOT NULL DEFAULT false,
    created_at       timestamptz NOT NULL DEFAULT now()
);

-- One resource per distinct audience in use, so every client keeps getting the
-- aud it gets today. The name is the client's own name when one client uses the
-- audience, and the URI itself when several share it (no one name is right).
-- An empty audience was never usable (token issuance refused it), so it gets no
-- resource: that client's default is NULL below.
INSERT INTO oauth_resources (uri, name)
SELECT audience,
       CASE WHEN count(*) = 1 THEN min(name) ELSE audience END
FROM oauth_clients
WHERE audience IS NOT NULL AND audience <> ''
GROUP BY audience;

-- ============================
-- Clients
-- ============================
-- default_resource: the resource a request that names none gets. NULL means no
-- default, and such a token's aud is identity's own issuer. It follows a
-- resource's URI if that is ever corrected (ON UPDATE CASCADE), and a resource
-- that is some client's default cannot be deleted out from under it.
ALTER TABLE oauth_clients
    ADD COLUMN default_resource text REFERENCES oauth_resources(uri) ON UPDATE CASCADE;

UPDATE oauth_clients
SET default_resource = audience
WHERE audience IS NOT NULL AND audience <> '';

ALTER TABLE oauth_clients ALTER COLUMN audience DROP NOT NULL;

-- 'registered' clients are created by hand with identity-cli; 'cimd' clients
-- are created on first use from a Client ID Metadata Document, refreshed when
-- that document is re-fetched (metadata_fetched_at).
ALTER TABLE oauth_clients
    ADD COLUMN kind text NOT NULL DEFAULT 'registered' CHECK (kind IN ('registered', 'cimd')),
    ADD COLUMN metadata_fetched_at timestamptz;

-- The resources a registered client may request by name, beyond its default
-- (which is always allowed).
CREATE TABLE oauth_client_resources (
    client_id    uuid NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    resource_id  uuid NOT NULL REFERENCES oauth_resources(id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, resource_id)
);

-- ============================
-- Codes and tokens
-- ============================
-- The resource a code or token was issued for: its aud. For a token for
-- identity itself the new release stores identity's issuer, never NULL (see the
-- trigger below). A refresh reissues for the stored resource, never the
-- client's current default.
ALTER TABLE oauth_authorization_codes ADD COLUMN resource text;

-- family_id and revoked_reason are for refresh-token reuse detection (a later
-- phase); nothing reads or writes them yet.
ALTER TABLE oauth_tokens
    ADD COLUMN resource text,
    ADD COLUMN family_id uuid,
    ADD COLUMN revoked_reason text;

-- Existing tokens were minted with aud = their client's audience; record that,
-- so refreshing one after the upgrade keeps the same aud.
UPDATE oauth_tokens t
SET resource = c.audience
FROM oauth_clients c
WHERE t.client_id = c.id
  AND c.audience IS NOT NULL AND c.audience <> '';

-- Tokens the previous release inserts after this migration (it is still serving
-- until the new release rolls out) don't set resource. Fill it from the client's
-- default, which is exactly the aud that release put in the JWT.
--
-- This is only correct because the new release never inserts a NULL resource:
-- it stores the aud it minted, which is identity's issuer for a token for
-- identity itself. So a NULL here can only be a previous-release row. Were the
-- new release to write NULL for "identity itself", this trigger would re-point
-- that token at the client's current default -- e.g. when refreshing it after
-- the client gained one -- and the wrong aud would carry through every later
-- refresh. Drop in the contract migration, once no previous-release pod exists.
CREATE FUNCTION oauth_tokens_fill_resource() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    SELECT default_resource INTO NEW.resource
    FROM oauth_clients
    WHERE id = NEW.client_id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER oauth_tokens_fill_resource
    BEFORE INSERT ON oauth_tokens
    FOR EACH ROW
    WHEN (NEW.resource IS NULL)
    EXECUTE FUNCTION oauth_tokens_fill_resource();

-- ============================
-- Consents
-- ============================
-- Consent is remembered per (user, client, resource). resource is NULL for "no
-- resource" (all rows, until requests can name one), and the key treats NULL as
-- a value so there is still one such row per (user, client).
ALTER TABLE oauth_user_consents ADD COLUMN resource text;

CREATE UNIQUE INDEX oauth_user_consents_user_client_resource_key
    ON oauth_user_consents (user_id, client_id, resource) NULLS NOT DISTINCT;
