-- Existing consents recorded under the resource they were given for.
--
-- Design: docs/superpowers/specs/2026-10-27-resource-indicators-and-mcp-clients-design.md
-- (section 8). Consent is remembered per (user, client, resource). 000012 added
-- oauth_user_consents.resource and its key, and 000014 dropped the old
-- (user_id, client_id) key, but every consent given so far has resource NULL:
-- requests could not name a resource when it was given.
--
-- Each of those consents was for the token the client's request got, which was
-- for the client's default resource (000012 set every default to the audience
-- the client had then). From this release, a request that names no resource is
-- looked up under that default, so recording it here means no existing user is
-- asked to consent again. A client with no default keeps NULL, which is what
-- "no resource" (a token for identity itself) means.
--
-- Data only, and safe while the previous release is serving: that release
-- reads and writes only resource-NULL consents, so in the rollout window its
-- users may be asked once more, and the NULL row it then writes is one the new
-- release never reads for such a client.
--
-- MUST BE APPLIED AFTER 000014. golang-migrate never goes back for a lower
-- version.
--
-- A user who already has a consent under the default keeps it, and the NULL
-- row is left alone rather than collide with it on the key. That cannot
-- happen on the first run (nothing writes per-resource consents before this
-- release), only after a down and up again.
UPDATE oauth_user_consents uc
SET resource = c.default_resource
FROM oauth_clients c
WHERE uc.client_id = c.id
  AND uc.resource IS NULL
  AND c.default_resource IS NOT NULL
  AND NOT EXISTS (
        SELECT 1 FROM oauth_user_consents other
        WHERE other.user_id = uc.user_id
          AND other.client_id = uc.client_id
          AND other.resource = c.default_resource
      );
