// Package cimd resolves OAuth Client ID Metadata Documents
// (draft-ietf-oauth-client-id-metadata-document-02, "CIMD"): a client_id that
// is an https URL names a JSON document, served at that URL, describing the
// client. Claude and Claude Code identify themselves to authorization servers
// this way instead of being registered by hand.
//
// The package is self-contained and is not yet called by any handler. Phase 3
// of docs/superpowers/specs/2026-10-27-resource-indicators-and-mcp-clients-design.md
// (§9) wires it in.
//
// # What it does
//
// Resolver.Resolve takes a client_id and, in order:
//
//  1. checks it is a well-formed Client Identifier URL (ValidateClientIDURL),
//     else ErrNotClientIDURL;
//  2. checks its host is on the configured allow-list (Config.AllowedHosts,
//     from CIMD_ALLOWED_HOSTS, initially "claude.ai"), else ErrHostNotAllowed.
//     Both checks happen before any DNS lookup or connection;
//  3. returns a cached document if one is fresh;
//  4. otherwise fetches the document through an SSRF-guarded client (see
//     below), else ErrFetch, and validates it, else ErrInvalidDocument;
//  5. caches a valid document for its Cache-Control max-age clamped to
//     [MinCacheTTL, MaxCacheTTL]. Errors and invalid documents are never
//     cached.
//
// Concurrent Resolves of the same URL share one fetch (singleflight).
//
// # SSRF guard
//
// The fetcher resolves the host itself and refuses the fetch if any address
// it resolves to is special-use (RFC 6890 and its successors; see
// IsForbiddenAddress). It then dials one of the addresses it vetted -- never
// the hostname, so a second, rebinding DNS answer is never consulted -- and
// checks the address actually connected to once more, both in the dialer's
// Control hook (before connect) and on the returned connection. TLS is
// verified against the original hostname. Redirects are never followed,
// proxies from the environment are ignored, only a 200 with a JSON content
// type is accepted, at most MaxDocumentBytes are read (more is an error, not
// a truncation), and the whole fetch has FetchTimeout.
//
// # How phase 3 uses it
//
// Routing. Hand-registered client IDs are base64 strings that never start
// with "https://". A client_id that does is CIMD-shaped and goes to Resolve;
// anything else keeps the oauth_clients lookup it has today.
//
// Errors. Every error from Resolve means the client is unknown, and therefore
// its redirect_uri is unverified: on the authorization endpoint, show an
// error page and do not redirect (OAuth 2.1 §4.1.2.1). ErrNotClientIDURL and
// ErrHostNotAllowed are the client's or the operator's fault and say so;
// ErrFetch and ErrInvalidDocument are worth logging with the wrapped detail
// (the error text never includes the response body). On the token endpoint
// any of them is invalid_client. errors.Is distinguishes them; ErrFetch from
// the SSRF guard additionally matches ErrForbiddenAddress.
//
// Persistence (phase 3's job, not this package's). Codes, tokens and consents
// reference oauth_clients(id), so each resolved document materializes a row:
// client_id = Metadata.ClientID, name = Metadata.ClientName, redirect_uris =
// Metadata.RedirectURIs, is_confidential = false, kind = 'cimd',
// metadata_fetched_at = Metadata.FetchedAt. Create it on first use and update
// it whenever Resolve returns a document fetched after the row's
// metadata_fetched_at. If redirect_uris changed, clear that client's
// remembered consents (CIMD §8.4). Consent shows Metadata.Host() as the app
// and ClientName only as what it "calls itself" (CIMD §8.5).
//
// A redirect URI this package admits is either https or one
// redirecturi.IsLoopback accepts, and never contains "*", so storing the list
// in oauth_clients.redirect_uris cannot create a wildcard entry; redirecturi
// then matches it exactly, or by port for the loopback ones (which is what
// Claude Code's port-less http://localhost/callback needs).
//
// Metadata flag. Advertise client_id_metadata_document_supported only when
// Resolver.Enabled reports true (a non-empty allow-list).
//
// Testing the wiring. Handlers should depend on a small interface with
// Resolve's signature, so integration tests can substitute a fake. The
// network seams here (DNS, dialer, loopback, trust roots) are deliberately
// unexported: nothing outside this package can turn the SSRF guard off.
package cimd
