-- Trusted (first-party) clients: apps the identity operator builds and
-- controls, whose consent screen would only ask the user to approve the
-- operator's own service. A trusted client skips the consent screen (consent is
-- implied, and no consent row is written) and is not listed on the Connected
-- Apps page. Nothing else about it changes: login, MFA, redirect-URI checks,
-- PKCE, resource and scope checks all apply as before. See README, "Trusted
-- (first-party) clients", before setting it.
--
-- Only identity-cli sets it (client create/update --trusted); no HTTP endpoint
-- does. The CHECK makes it impossible for a client identity did not register by
-- hand -- one materialized from a Client ID Metadata Document (kind 'cimd'),
-- whose code and redirect URIs belong to someone else -- ever to be trusted,
-- whatever path writes the row.
--
-- Additive and safe while the previous release is serving: its queries list
-- oauth_clients' columns explicitly, so they never see the new one, and every
-- existing client is untrusted (the default), which is how it behaves today.
ALTER TABLE oauth_clients
    ADD COLUMN trusted boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT oauth_clients_trusted_registered_only
        CHECK (NOT trusted OR kind = 'registered');
