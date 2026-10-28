# Resource Indicators and MCP Clients

**Date:** 2026-10-27
**Status:** Draft for review. Nothing built.
**Why now:** Sensibility (and later footstrike-api) will host MCP servers that
Claude connects to as the signed-in user, through identity
(`sensibility/docs/superpowers/specs/2026-10-25-mcp-agent-access-design.md`).
That needs identity to be a standards-complete OAuth 2.1 authorization server
for clients it has never seen, not only for the fleet's own hand-registered
apps. Few people use identity today and rarely, so this design prefers doing
it correctly over keeping every existing behavior, while keeping every
existing client working.

## Goals

1. **Audience-bound tokens per resource** (RFC 8707). A client names the API
   it wants a token for; identity only mints tokens for APIs it knows, with
   the scopes those APIs define, and the token's `aud` is that API.
2. **`iss` in every authorization response** (RFC 9207), so clients that talk
   to many authorization servers (Claude) can detect mix-up attacks.
3. **Metadata a modern client can rely on** (RFC 8414 alongside OIDC
   Discovery).
4. **Clients identified by URL** (Client ID Metadata Documents), so Claude and
   Claude Code connect without anyone registering them by hand.
5. **Native-app redirects on any loopback port** (RFC 8252), which Claude Code
   requires.
6. **A consent screen that says who is asking, for what, and where the answer
   goes.**
7. **Refresh-token reuse revokes the grant** (RFC 9700; issue #144).

Non-goals: Dynamic Client Registration (deprecated in MCP 2026-07-28; Claude
uses CIMD when it is advertised), sender-constrained tokens (DPoP/mTLS),
`private_key_jwt` client authentication, multiple signing keys (#65), hashing
refresh tokens (#62), the session management UI (#66). Each stays possible.

## Standards in force (checked 2026-10-27)

| Spec | Version | Notes |
|---|---|---|
| MCP Authorization | 2026-07-28 | Claude's connector docs still cite 2025-11-25 (no `iss` text, DCR not yet deprecated) |
| OAuth 2.1 | draft-ietf-oauth-v2-1-16 | MCP cites -13; section numbers below are -16 |
| Client ID Metadata Documents | draft-ietf-oauth-client-id-metadata-document-02 | MCP cites -00 |
| RFC 8707, 9207, 8414, 9728, 9068, 8252, 9700 | final | |
| OIDC Core 1.0, OIDC Discovery 1.0 | final | |

Claude's own requirements (claude.com/docs/connectors/building/authentication):
CIMD only if metadata has **both** `client_id_metadata_document_supported:
true` and `"none"` in `token_endpoint_auth_methods_supported`; hosted Claude
redirects to `https://claude.ai/api/mcp/auth_callback`; Claude Code's CIMD
(`https://claude.ai/oauth/claude-code-client-metadata`) registers
`http://localhost/callback` and `http://127.0.0.1/callback` **without a port**
and calls back on an ephemeral one; Claude sends `resource` on authorize and
token requests in canonical form; appends `offline_access` when AS metadata
lists it; needs `invalid_grant` for a dead refresh token; allows 10s for
discovery and token calls, 30s for refresh; calls from `160.79.104.0/21`.

## Where identity stands

Already correct: PKCE S256 required and advertised; exact redirect matching
(plus validated wildcards for previews); single-use 10-minute codes;
refresh-token rotation with an atomic revoke (no reuse detection); ID token
`aud` = client_id; per-(user, client) remembered consent.

Gaps this design closes: no `resource`; access-token `aud` comes from the
client row (`oauth_clients.audience`, re-read at refresh time); no `iss` on
redirects; no RFC 8414 document; `"none"` and `offline_access` not
advertised; no loopback port rule; client identity only by hand registration;
consent shows only the client's name; userinfo and introspection accept any
token; introspection returns the internal UUID as `client_id`; logout matches
`post_logout_redirect_uri` with its own exact `slices.Contains`.

## Fleet compatibility: who depends on what

| Client | Flow | Uses the access token? | Checks `aud`? |
|---|---|---|---|
| footstrike-dashboard (SPA, public) | code + PKCE, `openid profile email` | **Sends it to footstrike-api** | — |
| footstrike-ios (public, `footstrike://`) | code + PKCE | **Sends it to footstrike-api** | — |
| footstrike-api | resource server | validates locally (PyJWKClient) | **yes: `aud == "ethanswan:fitness"`** |
| haruspex (confidential) | code + PKCE | stores it, validates `iss` only, calls userinfo | no |
| sensibility web login (confidential) | code + PKCE, authlib | discards it; ID token + userinfo | no |
| bifrost (confidential) | code + PKCE, go-oidc | discards it; ID token | no |

No client sends `resource`, none uses `client_credentials`, introspection or
revocation. So the rule that keeps everyone working: **a client that sends no
`resource` gets exactly the `aud` it gets today**, via its default resource.

## Design

### 1. Resources registry

New table `oauth_resources`:

| Column | |
|---|---|
| `id` | uuid PK |
| `uri` | text UNIQUE, the canonical resource indicator and the token's `aud` |
| `name` | text, shown on consent ("Sensibility") |
| `scopes` | jsonb `{scope: description}`, the scopes this resource defines, with consent text |
| `dynamic_clients` | bool, whether CIMD clients may request it (default false) |
| `created_at` | |

- `uri` must be an absolute URI with no fragment (RFC 8707 §2), stored in
  canonical form (below). `https` is required for new resources; the one
  legacy URN-style value in use, `ethanswan:fitness`, is grandfathered by the
  backfill (§11) and can move to `https://api.footstrike.run` later.
- **Canonical form** (MCP "Canonical Server URI"): lowercase scheme and host,
  no default port, no trailing slash, no fragment. Incoming `resource` values
  are canonicalized before lookup, so `HTTPS://Sensibility.money/mcp/` finds
  `https://sensibility.money/mcp`.
- Scope names must not collide with identity's own scopes (below). They
  need not be unique across resources (prod and staging Sensibility both
  define `sensibility:read`): requested scopes are always checked against the
  one resource the request resolved to (§3).
- Initial rows: `https://sensibility.money/mcp` ("Sensibility",
  `sensibility:read`, `sensibility:write`, `dynamic_clients=true`), the
  staging equivalent, plus one row per distinct existing audience (§11).
  Like clients, resources are registered in **both** identity databases,
  since staging's is periodically replaced by a copy of prod's.

**Identity's own scopes** are not in the registry: `openid`, `profile`,
`email`, `offline_access` (and `admin:*`, client_credentials only). They are
always grantable to any client that may use them, independent of resource.

### 2. Clients: default resource and allowed resources

- `oauth_clients.audience` becomes **`default_resource`**, nullable, a foreign
  key to `oauth_resources(uri)`. It is the resource used when a request names
  none. NULL means "no default": such a token is for identity itself (§4).
- New `oauth_client_resources(client_id, resource_id)`: the resources a
  **registered** client may request by name. The default resource is
  implicitly allowed.
- **CIMD clients** have no allow-list: they may request any resource with
  `dynamic_clients = true`, and the user approves each on consent (§8).
- `allowed_scopes` keeps its meaning for registered clients (requested scopes
  must be a subset). For CIMD clients it is computed: identity's user scopes
  plus the scopes of the requested resource.

### 3. The `resource` parameter, request by request

One resource per request. RFC 8707 allows several, but a multi-audience token
is replayable at each of its audiences (§3 encourages one), MCP sends one, and
a single `aud` keeps validation simple. More than one `resource` value is
refused with `invalid_target`.

**Authorize** (`/oauth/authorize`, and consent POST):
1. Read `resource` (all values; refuse more than one). Canonicalize.
2. Absent: use the client's `default_resource` (may be none).
3. Present but unknown, malformed, or not allowed for this client:
   `invalid_target`, redirected to the client (with `iss`, §5).
4. Scope check against the resolved resource: each requested scope is either
   an identity scope or one of that resource's scopes, else
   `invalid_scope`; for registered clients also a subset of `allowed_scopes`
   (unchanged rule).
5. The resolved resource (canonical URI or NULL) is stored on the
   authorization code (new column `oauth_authorization_codes.resource`).

**Token, `authorization_code` grant:**
- `resource` optional. If present it must canonicalize to the code's
  resource, else `invalid_target`. If absent, the code's resource is used.
- The resource is stored on the token row (new column
  `oauth_tokens.resource`), and the access token's `aud` is it (§4).

**Token, `refresh_token` grant:**
- The resource comes **from the token row**, never re-derived from the
  client (today's drift bug). `resource` optional; if present it must equal
  the stored one, else `invalid_target`. Widening is impossible by
  construction; narrowing has nothing to narrow to with one resource.
- `scope` on refresh stays unsupported (the original scope is reissued),
  which satisfies OAuth 2.1 §4.3 (no scope beyond the original).

**Token, `client_credentials`:** `resource` honored the same way (allowed
resources, else the client's default). A client with neither gets `aud` =
identity's issuer, which the admin API (§4) accepts.

### 4. Access tokens

- `aud` is a single-element array holding the resource URI, or the issuer
  when there is none. (Today user tokens use an array and service tokens a
  plain string; both become the array form.)
- Header `typ: at+jwt` and a `client_id` claim (the public client_id), per
  RFC 9068 §2, so a resource server can refuse an ID token presented as an
  access token. No fleet consumer checks `typ` today, so adding it breaks
  nothing.
- ID tokens are unchanged: `aud` = client_id (OIDC Core §2).

**Who accepts which token at identity itself:**
- **Userinfo** accepts a live token only if its scope includes `openid`
  (OIDC: userinfo serves tokens "obtained through OpenID Connect
  Authentication"). Every existing login client requests `openid`; Claude's
  MCP tokens carry only resource scopes, so an MCP token can't be used to
  read the user's profile.
- **Admin API** requires `aud` = issuer as well as the admin scope.
- **Introspection** returns the public `client_id` (bug fix) and `aud`.

### 5. `iss` on every authorization response

- Every redirect from the authorization endpoint back to a client carries
  `iss=<issuer>`, success and error (RFC 9207 §2; OAuth 2.1 -16 makes it
  REQUIRED). Errors identity shows itself (bad `client_id` or
  `redirect_uri`) are not redirects and don't carry it.
- One helper builds every authorization response: today there are five sites
  (authorize success and error, consent success and error, the login page's
  PKCE-method error). All of them move to it; a test walks every response
  path and asserts `iss` is present.
- Metadata advertises `authorization_response_iss_parameter_supported:
  true`. Advertising it and then omitting `iss` on any error path makes
  compliant clients reject the response, which is why it ships with the
  helper, not before.
- `JWT_ISSUER` must have no trailing slash; startup refuses one.

### 6. Metadata

- Serve the same metadata at **`/.well-known/oauth-authorization-server`**
  (RFC 8414; MCP clients try it first) and keep
  `/.well-known/openid-configuration`. The issuer has no path, so both are at
  the root and identical.
- Changes:
  - `token_endpoint_auth_methods_supported`: add `"none"` (public clients
    already work; Claude requires it to use CIMD).
  - `scopes_supported`: `openid`, `profile`, `email`, `offline_access`.
    Resource scopes are published by each resource's own protected resource
    metadata, not here (Claude may request every AS scope as a last resort).
  - `authorization_response_iss_parameter_supported: true` (§5).
  - `client_id_metadata_document_supported: true` (§9, once it ships).
  - Generated from config, not a hardcoded literal.

### 7. Loopback redirect URIs

- A registered redirect URI whose scheme is `http` and host is `127.0.0.1`,
  `[::1]` or `localhost` matches a request URI that differs **only in port**
  (RFC 8252 §7.3, extended to `localhost` as Claude Code requires). Scheme,
  host, path and query must still match exactly; hosts never cross-match
  (`localhost` ≠ `127.0.0.1`).
- No other URI ever matches by ignoring the port. Custom schemes
  (`footstrike://…`) and https URIs are unchanged.
- The code still stores the concrete URI the request used, so the token
  endpoint's exact comparison stays correct.
- Logout's `post_logout_redirect_uri` uses the same matcher
  (`redirecturi.Allowed`) instead of its own exact check.

### 8. Consent

What the page shows:
1. **Who is asking.** Registered client: its name. CIMD client: the
   **host of its client_id URL** as the app ("claude.ai"), with the
   document's self-asserted `client_name` beneath it ("calls itself Claude
   Code") (CIMD §8.5; Claude's guidance).
2. **What for:** the resource's name and host ("Sensibility,
   sensibility.money"), and each scope's description from the registry
   (identity scopes keep theirs). Unknown scope strings never reach the page.
3. **Where the answer goes:** the redirect URI's host, always (MCP: MUST).
4. **A warning** when every redirect URI the client has is loopback ("This
   app runs on your computer; only continue if you started this sign-in"),
   per MCP's localhost guidance.

Rules:
- Consent is remembered per **(user, client, resource)**; approving
  Sensibility for Claude doesn't approve footstrike for it. The table's key
  gains `resource` (NULL for no resource, with a unique index treating NULL
  as a value).
- Consent GET validates `redirect_uri` as the POST does (it currently
  doesn't).
- The consent page sends `frame-ancestors 'none'` / `X-Frame-Options: DENY`.
- CIMD clients always see consent the first time for each resource;
  registered first-party clients keep today's behavior.

### 9. Client ID Metadata Documents

A `client_id` that is an https URL with a path is a CIMD client. Hand-made
client IDs are base64 strings that never start with `https://`, so the two
can't be confused.

**Fetching** (CIMD -02 §5, §8.6, §8.7):
- https only; no userinfo; no `.`/`..` path segments; no fragment.
- Resolve DNS first and refuse any special-use address (RFC 6890: private,
  loopback, link-local, CGNAT, multicast…), then connect to the address
  resolved, so a rebinding DNS answer can't redirect the fetch.
- No redirects followed; non-200 is an error; at most 5 KB read; 5 s timeout
  (inside Claude's 10 s budget); identity's own User-Agent.
- Cache honoring `Cache-Control: max-age` within [5 min, 24 h]; never cache
  an error or an invalid document; re-fetch when the cache expires.

**Validation:**
- JSON object; `client_id` equal to the fetch URL by simple string
  comparison; `client_name` and `redirect_uris` present.
- `token_endpoint_auth_method` must be `none` (or absent, meaning none).
  `private_key_jwt` and any secret-based method are refused; the document
  must not contain `client_secret`.
- Each redirect URI is https or a loopback http URI (§7).
- Optional `client_uri`/`logo_uri` are stored but not shown in this
  iteration.

**Persistence:** codes, tokens and consents reference `oauth_clients(id)`, so
a CIMD client gets a row there, created on first use and refreshed on each
re-fetch: `client_id` = the URL, `name` = `client_name`, `redirect_uris` from
the document, `is_confidential = false`, new column `kind = 'cimd'` (else
`'registered'`) and `metadata_fetched_at`. If a re-fetch changes
`redirect_uris`, remembered consents for that client are cleared (CIMD
§8.4).

**Trust policy:** CIMD is accepted only for client_id hosts on a configured
allow-list (`CIMD_ALLOWED_HOSTS`, initially `claude.ai`). The standard
permits any host; identity serves one person's apps, so it admits the clients
it means to and nothing else. Widening the list is a config change.

Before relying on it, verify from inside the cluster that Claude's documents
(behind Cloudflare) answer identity's fetcher with 200 and not a bot
challenge.

### 10. Refresh-token reuse (issue #144)

- Tokens gain `family_id` (set at the code exchange, copied on each refresh)
  and `revoked_reason` (`rotated`, `reuse_detected`, `logout`, `revoked`,
  `admin`).
- Presenting a refresh token already revoked **because it was rotated**
  revokes every token in its family, logs it, and returns `invalid_grant`.
  Tokens revoked for any other reason just return `invalid_grant`.
- No grace window (RFC 9700 defines none). Claude's 30 s refresh timeout
  makes a slow token endpoint the main way a legitimate client trips this,
  so the token endpoint must stay fast; revisit only if a real client does.
- Families get an absolute lifetime of 90 days from the original sign-in.

### 11. Migrations and rollout

identity refuses to start unless the database is at exactly its migration
version, and running pods name columns explicitly. A rename in one step would
break every running pod the moment it lands. So: **expand, deploy, contract.**

- **000012 (expand):** create `oauth_resources` and `oauth_client_resources`;
  insert one resource per distinct `oauth_clients.audience` (name = the
  client's name, `dynamic_clients = false`, URI as-is so `ethanswan:fitness`
  is preserved byte-for-byte); add nullable `default_resource` and backfill it
  from `audience`; add `resource` to codes and tokens, `family_id`/
  `revoked_reason` to tokens, `kind`/`metadata_fetched_at` to clients; widen
  the consent key. `audience` stays.
- **Deploy release A,** which reads `default_resource` and never names
  `audience` in its queries.
- **000013 (contract):** drop `audience`. Release A keeps working; release B
  is the same code against the new schema.

Every existing client's tokens are byte-for-byte the same `aud` after the
backfill, which is the compatibility guarantee for footstrike-api. The
sensibility, haruspex and bifrost login clients don't read `aud`, so their
defaults can later be set to NULL (tokens for identity itself) as tidying.

**Carry the authorization request, don't rebuild it.** Today login, MFA,
register and consent each pass the authorize parameters along field by field
(eight carriers), so a new parameter is silently dropped unless added to all
of them; register already loses `nonce`. Instead the original authorization
request's query string travels as one value (hidden field, pending-MFA
column), and every step re-parses and re-validates it through
`checkCodeIssuance`. `resource` then needs no plumbing, and neither will the
next parameter. The sign-up and sign-in links get proper URL encoding.

### 12. CLI

- `identity-cli resource create|list|get|update|delete` (URI, name, scopes
  with descriptions, `--dynamic-clients`).
- `client create|update`: `--default-resource` (or none), `--resources`
  (allow-list); `--audience` removed. `client list/get` show both.
- `client update` can clear the default resource (today's SQL can't set the
  column empty).

### 13. Rate limits

The global 20 requests/min per IP also covers discovery, JWKS and the token
endpoint, and Claude's backend calls from a shared range for every Claude
user. Discovery, JWKS and token get their own, higher per-IP limit; the login
and consent forms keep today's.

## Phases

Each phase is shippable and leaves every existing client working.

1. **Foundations:** migration 000012; release A reading `default_resource`;
   the carried authorization request; `iss` everywhere plus its flag; RFC
   8414 path; `"none"` and `offline_access` advertised; `at+jwt` and
   `client_id` claim; loopback matching (including logout); userinfo's
   `openid` rule; introspection `client_id` fix; rate limits.
2. **Resources:** the `resource` parameter end to end (authorize, consent,
   code, token, refresh, client_credentials); registry-driven scope checks;
   the consent screen (§8); CLI. Register the Sensibility resources.
   Then 000013 drops `audience`.
3. **CIMD:** fetcher, validation, persistence, trust allow-list, metadata
   flag. Verify the fetch from the cluster.
4. **Reuse detection** (#144).

Sensibility's MCP endpoint can be built alongside phase 1 and tested end to
end once phase 2 lands (Claude Code with a hand-registered client), then with
claude.ai once phase 3 lands.

## Testing

- Unit: canonicalization; loopback matcher (port-only differences, no host
  cross-match, no https port leniency); CIMD document validation; SSRF guard
  (every special-use range, DNS rebinding); metadata contents; the
  authorization-response helper.
- Integration (testcontainers, `OAuthFlowSuite`): every authorization
  response path carries `iss`; resource happy path and every
  `invalid_target`/`invalid_scope` case; refresh keeps the original resource
  after the client's default changes; a no-`resource` client gets its old
  `aud` exactly (the footstrike guarantee); userinfo refuses a token without
  `openid`; consent per (user, client, resource); family revocation; CIMD
  against a local test document server; migrations up/down/up.
- A conformance check against the MCP Inspector or Claude Code before
  calling phase 3 done.

## Decisions to confirm

1. **CIMD trust:** allow-list (`claude.ai` only) rather than any host. I'd
   start strict.
2. **No refresh grace window** for reuse detection.
3. **Keep `ethanswan:fitness`** as a grandfathered non-https resource until
   footstrike-api moves to a URL.
4. **Refresh tokens keep being issued on every code exchange** (not only
   with `offline_access`), as today; `offline_access` is accepted and
   advertised so Claude asks for it.
5. **Staging:** identity-staging is tailnet-only, so claude.ai (on the public
   internet) can't complete OAuth against it. Staging MCP is tested with
   Claude Code from the tailnet; claude.ai is tested against prod. (Exposing
   staging identity publicly is a separate decision.)

## Sources

- MCP Authorization 2026-07-28:
  https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
  (and its client-registration, authorization-server-discovery and
  security-considerations pages)
- Claude connector authentication:
  https://claude.com/docs/connectors/building/authentication
- RFC 8707 https://www.rfc-editor.org/rfc/rfc8707 · RFC 9207
  https://www.rfc-editor.org/rfc/rfc9207 · RFC 8414
  https://www.rfc-editor.org/rfc/rfc8414 · RFC 9728
  https://www.rfc-editor.org/rfc/rfc9728 · RFC 9068
  https://www.rfc-editor.org/rfc/rfc9068 · RFC 8252
  https://www.rfc-editor.org/rfc/rfc8252 · RFC 9700
  https://www.rfc-editor.org/rfc/rfc9700
- OAuth 2.1 -16:
  https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16
- CIMD -02:
  https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02
- OIDC Core https://openid.net/specs/openid-connect-core-1_0.html · OIDC
  Discovery https://openid.net/specs/openid-connect-discovery-1_0.html
