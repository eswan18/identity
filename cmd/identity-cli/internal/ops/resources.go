package ops

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/eswan18/identity/cmd/identity-cli/internal"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/resourceuri"
	"github.com/eswan18/identity/pkg/store"
)

// ScopeEdit is a change to a resource's scopes. Set holds name→description
// for Replace (the full set) and Add (add or redescribe); Remove holds names.
type ScopeEdit struct {
	Mode   EditMode
	Set    map[string]string
	Remove []string
}

// ResourceUpdate changes a resource. The URI never changes: it is every
// token's aud.
type ResourceUpdate struct {
	Name           *string
	Scopes         ScopeEdit
	DynamicClients *bool
	// ExpectFingerprint, when set, must equal the resource's current
	// Fingerprint or nothing is written and ErrStale is returned.
	ExpectFingerprint string
}

// ListResources returns every resource, by URI.
func ListResources(ctx context.Context, s *store.Store) ([]db.OauthResource, error) {
	resources, err := s.Q.ListOAuthResources(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list resources: %w", err)
	}
	return resources, nil
}

// GetResource returns a resource (looked up as FindResource does), its
// scopes, and the clients that name it.
func GetResource(ctx context.Context, s *store.Store, uri string) (ResourceDetail, error) {
	r, err := FindResource(ctx, s.Q, "resource", uri)
	if err != nil {
		return ResourceDetail{}, err
	}
	return resourceDetail(ctx, s.Q, r)
}

func resourceDetail(ctx context.Context, q *db.Queries, r db.OauthResource) (ResourceDetail, error) {
	scopes, err := internal.ParseScopes(r.Scopes)
	if err != nil {
		return ResourceDetail{}, fmt.Errorf("resource %s: %w", r.Uri, err)
	}
	usedBy, err := q.ListClientsReferencingResource(ctx, r.Uri)
	if err != nil {
		return ResourceDetail{}, fmt.Errorf("listing the clients that use %s: %w", r.Uri, err)
	}
	return ResourceDetail{Resource: r, Scopes: scopes, UsedBy: usedBy}, nil
}

// CreateResource registers a resource. The URI must be https and is stored
// in canonical form.
func CreateResource(ctx context.Context, s *store.Store, rawURI, name string, scopes map[string]string, dynamicClients bool) (ResourceDetail, error) {
	uri, err := resourceuri.ValidateNew(rawURI)
	if err != nil {
		return ResourceDetail{}, fmt.Errorf("uri %q: %w", rawURI, err)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return ResourceDetail{}, errors.New("name cannot be empty")
	}
	if err := internal.ValidateResourceScopes(scopes); err != nil {
		return ResourceDetail{}, err
	}
	scopesJSON, err := internal.ScopesJSON(scopes)
	if err != nil {
		return ResourceDetail{}, err
	}
	r, err := s.Q.CreateOAuthResource(ctx, db.CreateOAuthResourceParams{
		Uri: uri, Name: name, Scopes: scopesJSON, DynamicClients: dynamicClients,
	})
	if err != nil {
		return ResourceDetail{}, fmt.Errorf("failed to create resource: %w", err)
	}
	return resourceDetail(ctx, s.Q, r)
}

// UpdateResource applies u to a resource in one transaction, holding the row
// lock from the read (and fingerprint check) to the write.
func UpdateResource(ctx context.Context, s *store.Store, rawURI string, u ResourceUpdate) (ResourceDetail, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ResourceDetail{}, fmt.Errorf("failed to start a transaction: %w", err)
	}
	defer tx.Rollback()
	q := s.Q.WithTx(tx)

	found, err := FindResource(ctx, q, "resource", rawURI)
	if err != nil {
		return ResourceDetail{}, err
	}
	if _, err := tx.ExecContext(ctx, "SELECT 1 FROM oauth_resources WHERE uri = $1 FOR UPDATE", found.Uri); err != nil {
		return ResourceDetail{}, fmt.Errorf("locking resource %s: %w", found.Uri, err)
	}
	// Re-read under the lock: the fingerprint is checked against what the
	// write will replace.
	locked, err := q.GetOAuthResourceByURI(ctx, found.Uri)
	if err != nil {
		return ResourceDetail{}, fmt.Errorf("looking up resource %s: %w", found.Uri, err)
	}
	current, err := resourceDetail(ctx, q, locked)
	if err != nil {
		return ResourceDetail{}, err
	}
	if u.ExpectFingerprint != "" && u.ExpectFingerprint != current.Fingerprint() {
		return ResourceDetail{}, fmt.Errorf("resource %s %w", locked.Uri, ErrStale)
	}

	params := db.UpdateOAuthResourceParams{
		Uri:            locked.Uri,
		Name:           locked.Name,
		Scopes:         locked.Scopes,
		DynamicClients: locked.DynamicClients,
	}
	if u.Name != nil {
		name := strings.TrimSpace(*u.Name)
		if name == "" {
			return ResourceDetail{}, errors.New("name cannot be empty")
		}
		params.Name = name
	}
	if u.Scopes.Mode != Keep {
		scopes := current.Scopes
		switch u.Scopes.Mode {
		case Replace:
			scopes = u.Scopes.Set
		case Add:
			scopes = internal.MergeScopes(scopes, u.Scopes.Set)
		case Remove:
			var notFound []string
			scopes, notFound = internal.RemoveScopes(scopes, u.Scopes.Remove)
			if len(notFound) > 0 {
				return ResourceDetail{}, fmt.Errorf("resource %s has no such scope: %s - nothing was changed",
					locked.Uri, strings.Join(notFound, ", "))
			}
		}
		if err := internal.ValidateResourceScopes(scopes); err != nil {
			return ResourceDetail{}, err
		}
		if params.Scopes, err = internal.ScopesJSON(scopes); err != nil {
			return ResourceDetail{}, err
		}
	}
	if u.DynamicClients != nil {
		params.DynamicClients = *u.DynamicClients
	}

	updated, err := q.UpdateOAuthResource(ctx, params)
	if err != nil {
		return ResourceDetail{}, fmt.Errorf("failed to update resource: %w", err)
	}
	detail, err := resourceDetail(ctx, q, updated)
	if err != nil {
		return ResourceDetail{}, err
	}
	if err := tx.Commit(); err != nil {
		return ResourceDetail{}, fmt.Errorf("failed to commit: %w", err)
	}
	return detail, nil
}

// DeleteResource deletes a resource no client names. While any does, it
// refuses and names them.
func DeleteResource(ctx context.Context, s *store.Store, rawURI string) error {
	detail, err := GetResource(ctx, s, rawURI)
	if err != nil {
		return err
	}
	if len(detail.UsedBy) > 0 {
		var users []string
		for _, c := range detail.UsedBy {
			users = append(users, fmt.Sprintf("%s (%s) %s", c.Name, c.ClientID, ReferenceKind(c)))
		}
		return fmt.Errorf("resource %s is still used by: %s - change those clients first; nothing was deleted",
			detail.Resource.Uri, strings.Join(users, "; "))
	}
	// A client could have started naming it since the check above; the
	// default-resource foreign key still refuses then. An allow-list entry
	// added in that window would be removed with the resource (ON DELETE
	// CASCADE), which is the one race this does not close.
	if _, err := s.Q.DeleteOAuthResource(ctx, detail.Resource.Uri); err != nil {
		return fmt.Errorf("failed to delete resource: %w", err)
	}
	return nil
}

// ReferenceKind says how a client names a resource.
func ReferenceKind(c db.ListClientsReferencingResourceRow) string {
	if c.IsDefault {
		return "as its default resource"
	}
	return "on its allow-list"
}

// FindResource looks up a registered resource by a URI an operator typed. The
// value as typed is tried first, so a resource registered before the
// canonical form existed (the 000012 backfill keeps URIs byte for byte) is
// found as listed; then its canonical form, so any spelling of a registered
// https URI finds it. what names the field or flag, for the error.
func FindResource(ctx context.Context, q *db.Queries, what, raw string) (db.OauthResource, error) {
	resource, err := q.GetOAuthResourceByURI(ctx, raw)
	if err == nil {
		return resource, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return db.OauthResource{}, fmt.Errorf("looking up resource %s: %w", raw, err)
	}
	uri, err := resourceuri.Canonicalize(raw)
	if err != nil {
		return db.OauthResource{}, fmt.Errorf("%s %q: %w", what, raw, err)
	}
	resource, err = q.GetOAuthResourceByURI(ctx, uri)
	if errors.Is(err, sql.ErrNoRows) {
		return db.OauthResource{}, fmt.Errorf(
			"%s %q: no resource is registered with URI %s - register it first (`identity-cli resource create`, or Resources in identity-cli ui)",
			what, raw, uri)
	}
	if err != nil {
		return db.OauthResource{}, fmt.Errorf("looking up resource %s: %w", uri, err)
	}
	return resource, nil
}
