// Package ops is the one implementation of identity-cli's client and resource
// operations. The cobra commands and the local admin panel (identity-cli ui)
// both call it, so every rule -- trusted-client checks, wildcard validation,
// the admin-scope check, resource-URI canonicalisation, refusing to delete a
// resource still in use -- lives here and nowhere else.
package ops

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"github.com/eswan18/identity/pkg/db"
)

// ErrStale is returned when an update names the version it was reviewed
// against (ExpectFingerprint) and the record no longer matches it.
var ErrStale = errors.New("changed since it was reviewed")

// ClientDetail is a client with its resource allow-list.
type ClientDetail struct {
	Client    db.OauthClient
	Resources []db.OauthResource
}

// Fingerprint identifies the editable state of a client, allow-list
// included. The allow-list lives in another table and does not bump the
// client's updated_at, which is why this is a hash and not a timestamp.
func (d ClientDetail) Fingerprint() string {
	uris := make([]string, 0, len(d.Resources))
	for _, r := range d.Resources {
		uris = append(uris, r.Uri)
	}
	sort.Strings(uris)
	c := d.Client
	return hashJSON(struct {
		Name            string
		RedirectURIs    []string
		Scopes          []string
		Confidential    bool
		Trusted         bool
		DefaultResource *string
		Kind            string
		Resources       []string
	}{c.Name, c.RedirectUris, c.AllowedScopes, c.IsConfidential, c.Trusted, nullString(c.DefaultResource.String, c.DefaultResource.Valid), c.Kind, uris})
}

// ResourceDetail is a resource with its decoded scopes and the clients that
// name it.
type ResourceDetail struct {
	Resource db.OauthResource
	Scopes   map[string]string
	UsedBy   []db.ListClientsReferencingResourceRow
}

// Fingerprint identifies the editable state of a resource (oauth_resources
// has no updated_at).
func (d ResourceDetail) Fingerprint() string {
	return hashJSON(struct {
		Name           string
		Scopes         map[string]string // json.Marshal sorts map keys
		DynamicClients bool
	}{d.Resource.Name, d.Scopes, d.Resource.DynamicClients})
}

func hashJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // only plain strings, slices, maps and bools go in
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func nullString(s string, valid bool) *string {
	if !valid {
		return nil
	}
	return &s
}
