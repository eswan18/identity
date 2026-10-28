-- Reverse 000015: a consent for its client's default resource goes back to
-- NULL, which is how the release before this one looks it up, unless the
-- client already has a NULL consent for that user (the previous release wrote
-- one during the rollout), in which case the key would not allow a second.
-- Consents for other resources stay; 000014's down deletes them if it runs.
UPDATE oauth_user_consents uc
SET resource = NULL
FROM oauth_clients c
WHERE uc.client_id = c.id
  AND uc.resource = c.default_resource
  AND NOT EXISTS (
        SELECT 1 FROM oauth_user_consents other
        WHERE other.user_id = uc.user_id
          AND other.client_id = uc.client_id
          AND other.resource IS NULL
      );
