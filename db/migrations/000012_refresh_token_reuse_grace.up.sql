-- Link a rotated refresh token to the token that replaced it.
--
-- Rotation revokes the old refresh token the instant the new one is minted,
-- with no tolerance for reuse. That is correct against a thief and wrong
-- against a browser: a client that fires several requests at once crosses the
-- access token's expiry together, every one of them refreshes with the same
-- refresh token, and only the first survives. The rest get invalid_grant and,
-- in at least one relying party, are treated as "your session is over".
--
-- Knowing which token replaced which lets the token endpoint tell those two
-- cases apart. A refresh presenting a token that was rotated moments ago can be
-- answered with the successor instead of an error; the same token presented
-- later is a genuine replay, and now has a chain to revoke.
--
-- Nullable on purpose: every row that predates this reads as "no successor",
-- which is exactly the behaviour it has today.
ALTER TABLE oauth_tokens
    ADD COLUMN replaced_by_token_id uuid REFERENCES oauth_tokens(id) ON DELETE SET NULL;
