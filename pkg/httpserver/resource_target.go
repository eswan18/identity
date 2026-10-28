package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/resourceuri"
)

// The resource parameter (RFC 8707), request by request. Spec:
// docs/superpowers/specs/2026-10-27-resource-indicators-and-mcp-clients-design.md,
// section 3.
//
// A request names at most one resource. On /oauth/authorize (and the consent
// POST, which re-checks the carried request) and on the client_credentials
// grant it is resolved against the registry: absent means the client's default
// resource, which may be none; present, it must be a registered resource this
// client may request, else invalid_target. On the code exchange and on refresh
// nothing is resolved: the grant already fixed the resource, and a resource
// parameter there may only repeat it.
//
// "None" is a token for identity itself: aud = the issuer. Codes and tokens
// record it as the issuer string rather than NULL (see storedResource), so on
// the way back out a stored issuer is read as none (grantedResource).

// errInvalidTarget is the RFC 8707 error for a resource that cannot be used.
const errInvalidTarget = "invalid_target"

// resolvedResource is the resource a request resolved to: what the token will
// be for, its name for the consent screen, and the scopes it defines with
// their consent text. A nil *resolvedResource means none.
type resolvedResource struct {
	URI    string
	Name   string
	Scopes map[string]string
}

// uri is r's URI as a nullable column value: NULL for none.
func (r *resolvedResource) uri() sql.NullString {
	if r == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: r.URI, Valid: true}
}

// newResolvedResource reads a registry row.
func newResolvedResource(row db.OauthResource) (*resolvedResource, error) {
	scopes := map[string]string{}
	if err := json.Unmarshal(row.Scopes, &scopes); err != nil {
		return nil, fmt.Errorf("resource %s has unreadable scopes: %w", row.Uri, err)
	}
	return &resolvedResource{URI: row.Uri, Name: row.Name, Scopes: scopes}, nil
}

// requestedResource reads the resource parameter's values: present reports
// whether there was one, and canonical is it in canonical form. More than one
// value, or one that is not an absolute URI without a fragment, is an
// invalid_target error whose description says why.
func requestedResource(values []string) (canonical string, present bool, oauthErr *oauthAuthorizeError) {
	switch len(values) {
	case 0:
		return "", false, nil
	case 1:
	default:
		// RFC 8707 allows several, but a token with several audiences is
		// replayable at each of them; identity mints for one (spec, section 3).
		return "", true, &oauthAuthorizeError{errInvalidTarget, "Only one resource may be requested"}
	}
	canonical, err := resourceuri.Canonicalize(values[0])
	if err != nil {
		return "", true, &oauthAuthorizeError{errInvalidTarget, fmt.Sprintf("Invalid resource: %v", err)}
	}
	return canonical, true, nil
}

// sameResource reports whether two resource URIs name the same resource:
// equal once both are canonical. Resources registered before the canonical
// form existed (the 000012 backfill) keep their URI byte for byte, so a stored
// value is not assumed canonical; one that will not canonicalize is compared
// as it stands.
func sameResource(a, b string) bool {
	if a == b {
		return true
	}
	ca, errA := resourceuri.Canonicalize(a)
	cb, errB := resourceuri.Canonicalize(b)
	return errA == nil && errB == nil && ca == cb
}

// resolveResource decides which resource a request is for, from the values of
// its resource parameter. It returns the resource (nil: none), or an
// invalid_target error to hand back to the client, or an error for a lookup
// that failed (a server error, never a verdict on the request).
//
// Absent: the client's default resource, or none. Present: a registered
// resource the client may request (resourceAllowedForClient). An unknown
// resource and one the client may not have get the same answer, so the error
// does not reveal which resources exist.
func (s *Server) resolveResource(ctx context.Context, client db.OauthClient, values []string) (*resolvedResource, *oauthAuthorizeError, error) {
	canonical, present, oauthErr := requestedResource(values)
	if oauthErr != nil {
		return nil, oauthErr, nil
	}

	if !present || (client.DefaultResource.Valid && sameResource(client.DefaultResource.String, canonical)) {
		// The default is always allowed. It is matched before the registry
		// lookup so that a client naming its own default finds it even when
		// the stored URI predates the canonical form.
		if !client.DefaultResource.Valid {
			return nil, nil, nil
		}
		row, err := s.datastore.Q.GetOAuthResourceByURI(ctx, client.DefaultResource.String)
		if err != nil {
			// The foreign key guarantees the row, so any error is a failure.
			return nil, nil, fmt.Errorf("looking up default resource %s: %w", client.DefaultResource.String, err)
		}
		res, err := newResolvedResource(row)
		return res, nil, err
	}

	notAvailable := &oauthAuthorizeError{errInvalidTarget, fmt.Sprintf("Resource %s is not available to this client", canonical)}
	row, err := s.datastore.Q.GetOAuthResourceByURI(ctx, canonical)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notAvailable, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("looking up resource %s: %w", canonical, err)
	}
	allowed, err := s.resourceAllowedForClient(ctx, client, row)
	if err != nil {
		return nil, nil, err
	}
	if !allowed {
		return nil, notAvailable, nil
	}
	res, err := newResolvedResource(row)
	return res, nil, err
}

// resourceAllowedForClient reports whether client may request resource by
// name. Its default resource is handled by the caller and always allowed.
func (s *Server) resourceAllowedForClient(ctx context.Context, client db.OauthClient, resource db.OauthResource) (bool, error) {
	switch client.Kind {
	case "registered":
		// A registered client may request what its allow-list names
		// (identity-cli client create|update --resources).
		allowed, err := s.datastore.Q.ClientMayRequestResource(ctx, db.ClientMayRequestResourceParams{
			ClientID:   client.ID,
			ResourceID: resource.ID,
		})
		if err != nil {
			return false, fmt.Errorf("checking whether client %s may request %s: %w", client.ClientID, resource.Uri, err)
		}
		return allowed, nil
	case "cimd":
		// Phase 3 (spec, section 2): a client identified by a metadata
		// document has no allow-list and may request any resource with
		// dynamic_clients = true, i.e. `return resource.DynamicClients, nil`;
		// the user then approves each resource on consent. Its allowed_scopes
		// are also computed rather than registered (identity's user scopes plus
		// the resource's), which validateAuthorizeParams will need to learn.
		// Until phase 3 creates such clients, refuse.
		return false, nil
	default:
		return false, nil
	}
}

// checkScopesAgainstResource is the registry's half of the scope check: each
// requested scope is one of identity's own (whose rules validateAuthorizeParams
// applies) or one the resolved resource defines. A request for no resource may
// ask only for identity's scopes. Scopes are checked against the one resource
// the request resolved to; another resource defining the same name does not
// make it valid here.
func checkScopesAgainstResource(scope []string, resource *resolvedResource) *oauthAuthorizeError {
	var undefined []string
	for _, sc := range scope {
		if auth.IsIdentityScope(sc) {
			continue
		}
		if resource != nil {
			if _, ok := resource.Scopes[sc]; ok {
				continue
			}
		}
		if !slices.Contains(undefined, sc) {
			undefined = append(undefined, sc)
		}
	}
	if len(undefined) == 0 {
		return nil
	}
	if resource == nil {
		return &oauthAuthorizeError{"invalid_scope", fmt.Sprintf(
			"Scopes %v belong to no resource this request is for; name the resource that defines them", undefined)}
	}
	return &oauthAuthorizeError{"invalid_scope", fmt.Sprintf(
		"Scopes %v are not defined by resource %s", undefined, resource.URI)}
}

// grantedResource reads the resource a code or token row was issued for: none
// when the row holds the issuer (a token for identity itself; see
// storedResource), else the URI. A NULL can only be a row the previous release
// wrote, which minted for the client's default; legacy says what that was.
func (s *Server) grantedResource(stored sql.NullString, legacy sql.NullString) sql.NullString {
	if !stored.Valid {
		return legacy
	}
	if stored.String == s.config.JWTIssuer {
		return sql.NullString{}
	}
	return stored
}

// checkTokenRequestResource is the token endpoint's rule for the code
// exchange and refresh: the grant fixed the resource, so a resource parameter
// is optional and, when present, must name that same resource. For a grant
// for no resource it must be absent. Returns an invalid_target description,
// or "" when the request is acceptable.
func checkTokenRequestResource(values []string, granted sql.NullString) string {
	canonical, present, oauthErr := requestedResource(values)
	if oauthErr != nil {
		return oauthErr.Description
	}
	if !present {
		return ""
	}
	if !granted.Valid {
		return fmt.Sprintf("This grant is not for a resource; resource %s cannot be requested with it", canonical)
	}
	if !sameResource(granted.String, canonical) {
		return fmt.Sprintf("This grant is for a different resource than %s", canonical)
	}
	return ""
}
