package httpserver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"slices"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/cimd"
	"github.com/eswan18/identity/pkg/db"
)

// Clients identified by a Client ID Metadata Document (CIMD). Spec:
// docs/superpowers/specs/2026-10-27-resource-indicators-and-mcp-clients-design.md,
// section 9; pkg/cimd's package doc lists what this file must do.
//
// A client_id that is an https URL (cimd.IsClientIDURL) names a JSON document
// describing the client. Hand-registered client IDs never start with
// "https://", so the shape of the client_id alone decides which kind of client
// a request names. Every place a request's client_id is looked up goes through
// lookupClient, which resolves a URL-shaped one through the resolver and
// materializes it as an oauth_clients row (codes, tokens and consents
// reference oauth_clients(id)). So a metadata-document client is unknown --
// exactly as an unregistered client_id is -- whenever its host is not on the
// allow-list (CIMD_ALLOWED_HOSTS; empty disables CIMD), its document cannot be
// fetched, or the document is invalid. A row already in the database is never
// a substitute for a document identity can fetch and accept right now.

// clientMetadataResolver is what identity needs from pkg/cimd. *cimd.Resolver
// implements it; tests substitute a fake, since the package's network seams
// are deliberately unexported.
type clientMetadataResolver interface {
	// Enabled reports whether any host is allowed.
	Enabled() bool
	// HostAllowed reports, without touching the network, whether clientID is
	// a Client Identifier URL on an allowed host.
	HostAllowed(clientID string) bool
	// Resolve returns the validated document for clientID, cached or fetched.
	Resolve(ctx context.Context, clientID string) (*cimd.Metadata, error)
}

// clientKindCIMD is oauth_clients.kind for a client materialized from a
// metadata document (the other kind is "registered").
const clientKindCIMD = "cimd"

// errUnknownClient is a verdict on the client_id a request named: there is no
// such client, or none identity will accept. Any other error from lookupClient
// is the lookup itself failing.
var errUnknownClient = errors.New("unknown client")

// cimdEnabled reports whether identity accepts metadata-document clients at
// all, which is when it advertises client_id_metadata_document_supported.
func (s *Server) cimdEnabled() bool {
	return s.clientMetadata != nil && s.clientMetadata.Enabled()
}

// cimdHostAllowed reports whether clientID is a metadata-document client_id on
// an allowed host. It never touches the network.
func (s *Server) cimdHostAllowed(clientID string) bool {
	return s.clientMetadata != nil && s.clientMetadata.HostAllowed(clientID)
}

// lookupClient returns the client a request's client_id names: the registered
// row for a registered client, the materialized row for a metadata-document
// client (resolving its document first). The error wraps errUnknownClient when
// there is no such client; any other error is a failed lookup, which callers
// must not report as a verdict on the client.
func (s *Server) lookupClient(ctx context.Context, clientID string) (db.OauthClient, error) {
	if cimd.IsClientIDURL(clientID) {
		return s.cimdClient(ctx, clientID)
	}
	client, err := s.datastore.Q.GetOAuthClientByClientID(ctx, clientID)
	if errors.Is(err, sql.ErrNoRows) {
		return db.OauthClient{}, fmt.Errorf("%w: %q", errUnknownClient, clientID)
	}
	if err != nil {
		return db.OauthClient{}, err
	}
	if client.Kind == clientKindCIMD {
		// Unreachable: a materialized row's client_id is a URL that passed
		// IsClientIDURL. Refused rather than trusted, since this path skips
		// the allow-list and the document.
		log.Printf("lookupClient: client %q is a metadata-document client but not a valid client ID URL; refusing it", clientID)
		return db.OauthClient{}, fmt.Errorf("%w: %q", errUnknownClient, clientID)
	}
	return client, nil
}

// cimdClient resolves a metadata-document client_id and materializes its row.
func (s *Server) cimdClient(ctx context.Context, clientID string) (db.OauthClient, error) {
	// The allow-list is checked here, before anything else: a disabled CIMD or
	// a host not on the list costs no DNS lookup, no connection and no query.
	// (Resolve checks it again; this check is the one handlers can see.)
	if !s.cimdHostAllowed(clientID) {
		return db.OauthClient{}, fmt.Errorf("%w: %q: %w", errUnknownClient, clientID, cimd.ErrHostNotAllowed)
	}
	md, err := s.clientMetadata.Resolve(ctx, clientID)
	if err != nil {
		// ErrFetch and ErrInvalidDocument carry the detail an operator needs
		// (status, content type, which rule the document broke); never the
		// response body.
		log.Printf("cimd: client %s refused: %v", clientID, err)
		return db.OauthClient{}, fmt.Errorf("%w: %w", errUnknownClient, err)
	}
	return s.materializeCIMDClient(ctx, md)
}

// materializeCIMDClient returns the oauth_clients row for a resolved
// document, creating it on first use and updating it when this document is
// newer than the row.
//
// metadata_fetched_at is when the document the row holds was fetched. Each pod
// caches documents separately, so a pod can hold an older copy than the row;
// the row then wins, and an older fetch never overwrites a newer one. A pod
// writes once per fetch (at most every cimd.MinCacheTTL), and a steady state
// costs one read per request.
//
// Recording every fetch, even of an unchanged document, is what keeps a pod
// holding a stale copy from "updating" the row back to it: were an unchanged
// re-fetch not recorded, the row's timestamp could predate that stale copy.
func (s *Server) materializeCIMDClient(ctx context.Context, md *cimd.Metadata) (db.OauthClient, error) {
	row, err := s.datastore.Q.GetOAuthClientByClientID(ctx, md.ClientID)
	switch {
	case err == nil:
		if row.Kind != clientKindCIMD {
			return db.OauthClient{}, registeredClientAtCIMDURL(row)
		}
		if cimdRowCurrent(row, md) {
			return row, nil
		}
	case errors.Is(err, sql.ErrNoRows):
	default:
		return db.OauthClient{}, fmt.Errorf("looking up client %s: %w", md.ClientID, err)
	}
	return s.storeCIMDClient(ctx, md)
}

// cimdRowCurrent reports whether row needs no update from md: it holds a
// fetch at least as recent.
func cimdRowCurrent(row db.OauthClient, md *cimd.Metadata) bool {
	return row.MetadataFetchedAt.Valid && !md.FetchedAt.After(row.MetadataFetchedAt.Time)
}

// storeCIMDClient creates or updates the row for md in one transaction, with
// the row locked, so concurrent requests (on any pod) agree on the outcome
// and on whether the redirect URIs changed. When they did, every grant users
// gave the client is withdrawn (CIMD §8.4), because what they approved was
// sending answers to the old ones: every remembered consent is deleted, every
// live token revoked (revokedClientRedirectsChanged), and every unexchanged
// code deleted. Deleting only the consents would leave the client holding
// tokens no consent backs, which a refresh would keep alive and the Connected
// Apps page could not explain.
func (s *Server) storeCIMDClient(ctx context.Context, md *cimd.Metadata) (db.OauthClient, error) {
	tx, err := s.datastore.DB.BeginTx(ctx, nil)
	if err != nil {
		return db.OauthClient{}, fmt.Errorf("materializing client %s: %w", md.ClientID, err)
	}
	defer tx.Rollback()
	q := s.datastore.Q.WithTx(tx)
	fetchedAt := sql.NullTime{Time: md.FetchedAt, Valid: true}

	row, err := q.GetOAuthClientByClientIDForUpdate(ctx, md.ClientID)
	if errors.Is(err, sql.ErrNoRows) {
		created, err := q.CreateCIMDClient(ctx, db.CreateCIMDClientParams{
			ClientID:          md.ClientID,
			Name:              md.ClientName,
			RedirectUris:      md.RedirectURIs,
			MetadataFetchedAt: fetchedAt,
		})
		if err == nil {
			if err := tx.Commit(); err != nil {
				return db.OauthClient{}, fmt.Errorf("materializing client %s: %w", md.ClientID, err)
			}
			log.Printf("cimd: client %s (calls itself %q) seen for the first time; redirect_uris %v", md.ClientID, md.ClientName, md.RedirectURIs)
			return created, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return db.OauthClient{}, fmt.Errorf("creating client %s: %w", md.ClientID, err)
		}
		// Another request created it first; carry on with its row.
		row, err = q.GetOAuthClientByClientIDForUpdate(ctx, md.ClientID)
	}
	if err != nil {
		return db.OauthClient{}, fmt.Errorf("locking client %s: %w", md.ClientID, err)
	}
	if row.Kind != clientKindCIMD {
		return db.OauthClient{}, registeredClientAtCIMDURL(row)
	}
	if cimdRowCurrent(row, md) {
		return row, tx.Commit()
	}

	updated, err := q.UpdateCIMDClient(ctx, db.UpdateCIMDClientParams{
		ID:                row.ID,
		Name:              md.ClientName,
		RedirectUris:      md.RedirectURIs,
		MetadataFetchedAt: fetchedAt,
	})
	if err != nil {
		return db.OauthClient{}, fmt.Errorf("updating client %s: %w", md.ClientID, err)
	}
	var cleared, revoked, codes int64
	redirectsChanged := !sameStringSet(row.RedirectUris, md.RedirectURIs)
	if redirectsChanged {
		if cleared, err = q.DeleteUserConsentsForClient(ctx, row.ID); err != nil {
			return db.OauthClient{}, fmt.Errorf("clearing consents for client %s: %w", md.ClientID, err)
		}
		if revoked, err = q.RevokeClientTokens(ctx, db.RevokeClientTokensParams{
			ClientID: row.ID, Reason: string(revokedClientRedirectsChanged),
		}); err != nil {
			return db.OauthClient{}, fmt.Errorf("revoking tokens for client %s: %w", md.ClientID, err)
		}
		if codes, err = q.DeleteUnconsumedClientAuthorizationCodes(ctx, row.ID); err != nil {
			return db.OauthClient{}, fmt.Errorf("deleting codes for client %s: %w", md.ClientID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return db.OauthClient{}, fmt.Errorf("updating client %s: %w", md.ClientID, err)
	}
	if redirectsChanged {
		log.Printf("cimd: client %s changed its redirect_uris from %v to %v; cleared %d remembered consents, revoked %d tokens, deleted %d unexchanged codes",
			md.ClientID, row.RedirectUris, md.RedirectURIs, cleared, revoked, codes)
	}
	if row.Name != md.ClientName {
		log.Printf("cimd: client %s now calls itself %q (was %q)", md.ClientID, md.ClientName, row.Name)
	}
	return updated, nil
}

// registeredClientAtCIMDURL is the refusal for a hand-registered client whose
// client_id is a metadata-document URL. identity-cli never makes one, but if
// one exists the document must not overwrite it, nor it stand in for the
// document.
func registeredClientAtCIMDURL(row db.OauthClient) error {
	log.Printf("cimd: client %s is registered (kind %q), not a metadata-document client; refusing it", row.ClientID, row.Kind)
	return fmt.Errorf("%w: %q is registered, not a metadata-document client", errUnknownClient, row.ClientID)
}

// sameStringSet reports whether a and b hold the same strings, in any order.
func sameStringSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

// cimdAllowedScopes is what a metadata-document client may request, computed
// rather than registered (spec, section 2): identity's user scopes, plus the
// scopes of the resource the request resolved to (none: identity's alone).
func cimdAllowedScopes(resource *resolvedResource) []string {
	allowed := slices.Clone(auth.IdentityScopes)
	if resource != nil {
		for sc := range resource.Scopes {
			allowed = append(allowed, sc)
		}
	}
	return allowed
}
