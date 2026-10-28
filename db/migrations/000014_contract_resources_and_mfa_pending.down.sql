-- Reverse 000014: back to the schema 000013 left. The dropped columns come back
-- nullable, and empty except audience (below): their values are gone, and
-- nothing that runs at version 13 reads them. The one row-level loss is
-- consents for a named resource (below).

DROP INDEX IF EXISTS idx_oauth_tokens_family_id;

-- Empty is right: release #150, which runs at version 13, writes only
-- authorize_query. A row in flight loses nothing.
ALTER TABLE auth_mfa_pending
    ADD COLUMN client_id text,
    ADD COLUMN redirect_uri text,
    ADD COLUMN state text,
    ADD COLUMN scope text[],
    ADD COLUMN code_challenge text,
    ADD COLUMN code_challenge_method text,
    ADD COLUMN nonce text;

-- Identical to 000012's. Harmless at version 13: that release never inserts a
-- NULL resource, so it never fires.
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

-- The old (user, client) key allows one consent per user and client. A consent
-- for a named resource cannot exist at version 13 (no release before this
-- migration writes one), but one may have been written since; such rows are
-- deleted so the key can be restored -- the user is just asked to consent again.
-- What remains is at most one no-resource row per (user, client), which the
-- NULLS NOT DISTINCT index already guarantees, so the constraint always applies.
DELETE FROM oauth_user_consents WHERE resource IS NOT NULL;
ALTER TABLE oauth_user_consents
    ADD CONSTRAINT oauth_user_consents_user_id_client_id_key UNIQUE (user_id, client_id);

-- Nullable, as 000012 left it, and refilled from default_resource, which is what
-- 000012 copied into it and what the release before 000012 would read. (000012's
-- own down rewrites it and restores NOT NULL.)
ALTER TABLE oauth_clients ADD COLUMN audience text;
UPDATE oauth_clients SET audience = default_resource;
