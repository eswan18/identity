package ops

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/eswan18/identity/cmd/identity-cli/internal"
	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/store"
	"github.com/google/uuid"
)

// EditMode says how a list field changes.
type EditMode int

const (
	Keep    EditMode = iota // leave the list as it is
	Replace                 // replace it with Values
	Add                     // append Values not already present
	Remove                  // drop Values; any not present is an error
)

// ListEdit is a change to a list field.
type ListEdit struct {
	Mode   EditMode
	Values []string
}

// ClientCreate is a new registered client.
type ClientCreate struct {
	Name            string
	RedirectURIs    []string
	Scopes          []string
	Resources       []string // URIs for the allow-list
	Confidential    bool
	Trusted         bool
	DefaultResource string // a registered resource URI, or "" for identity itself
}

// ClientUpdate changes a client. A nil pointer or Keep edit leaves that field
// alone.
type ClientUpdate struct {
	Name          *string
	RedirectURIs  ListEdit
	Scopes        *[]string
	Confidential  *bool
	Trusted       *bool
	// DefaultResource: nil leaves it, "" clears it (tokens are for identity
	// itself), anything else must name a registered resource.
	DefaultResource *string
	Resources       ListEdit
	// ExpectFingerprint, when set, must equal the client's current
	// Fingerprint or nothing is written and ErrStale is returned.
	ExpectFingerprint string
}

// ListClients returns every client, newest first.
func ListClients(ctx context.Context, s *store.Store) ([]db.OauthClient, error) {
	clients, err := s.Q.ListOAuthClients(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list OAuth clients: %w", err)
	}
	return clients, nil
}

// GetClient returns a client and its allow-list.
func GetClient(ctx context.Context, s *store.Store, clientID string) (ClientDetail, error) {
	return getClient(ctx, s.Q, clientID, false)
}

func getClient(ctx context.Context, q *db.Queries, clientID string, forUpdate bool) (ClientDetail, error) {
	var client db.OauthClient
	var err error
	if forUpdate {
		client, err = q.GetOAuthClientByClientIDForUpdate(ctx, clientID)
	} else {
		client, err = q.GetOAuthClientByClientID(ctx, clientID)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ClientDetail{}, fmt.Errorf("no client with client_id %s", clientID)
	}
	if err != nil {
		return ClientDetail{}, fmt.Errorf("failed to get OAuth client: %w", err)
	}
	resources, err := q.ListClientResources(ctx, client.ID)
	if err != nil {
		return ClientDetail{}, fmt.Errorf("reading the client's allowed resources: %w", err)
	}
	return ClientDetail{Client: client, Resources: resources}, nil
}

// CreateClient registers a client. For a confidential client it also returns
// the plaintext secret, which is shown once: only its hash is stored.
func CreateClient(ctx context.Context, s *store.Store, in ClientCreate) (ClientDetail, string, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return ClientDetail{}, "", errors.New("name cannot be empty")
	}
	if err := internal.ValidateRedirectURIs(in.RedirectURIs); err != nil {
		return ClientDetail{}, "", err
	}
	// Admin scopes are only issued via client_credentials, which needs a
	// confidential client (see ValidateAdminScopes).
	if err := internal.ValidateAdminScopes(in.Scopes, in.Confidential); err != nil {
		return ClientDetail{}, "", err
	}
	// A trusted client skips consent, so it may only have exact, non-loopback
	// redirect URIs (README, "Trusted (first-party) clients").
	if in.Trusted {
		if err := internal.ValidateTrustable("registered", in.RedirectURIs); err != nil {
			return ClientDetail{}, "", err
		}
	}

	var defaultResource sql.NullString
	if in.DefaultResource != "" {
		r, err := FindResource(ctx, s.Q, "default resource", in.DefaultResource)
		if err != nil {
			return ClientDetail{}, "", err
		}
		defaultResource = sql.NullString{String: r.Uri, Valid: true}
	}
	allowed, err := resolveResourceList(ctx, s.Q, "resources", in.Resources)
	if err != nil {
		return ClientDetail{}, "", err
	}

	clientID, err := internal.GenerateRandomString(32)
	if err != nil {
		return ClientDetail{}, "", fmt.Errorf("failed to generate client_id: %w", err)
	}
	var secretHash sql.NullString
	var plaintext string
	if in.Confidential {
		if plaintext, err = internal.GenerateRandomString(32); err != nil {
			return ClientDetail{}, "", fmt.Errorf("failed to generate client_secret: %w", err)
		}
		secretHash = sql.NullString{String: auth.HashClientSecret(plaintext), Valid: true}
	}

	// The client and its allow-list are created together or not at all.
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ClientDetail{}, "", fmt.Errorf("failed to start a transaction: %w", err)
	}
	defer tx.Rollback()
	q := s.Q.WithTx(tx)
	client, err := q.CreateOAuthClient(ctx, db.CreateOAuthClientParams{
		ClientID:        clientID,
		ClientSecret:    secretHash,
		Name:            name,
		RedirectUris:    nonNil(in.RedirectURIs),
		AllowedScopes:   nonNil(in.Scopes),
		IsConfidential:  in.Confidential,
		DefaultResource: defaultResource,
		Trusted:         in.Trusted,
	})
	if err != nil {
		return ClientDetail{}, "", fmt.Errorf("failed to create OAuth client: %w", err)
	}
	if err := addClientResources(ctx, q, client.ID, allowed); err != nil {
		return ClientDetail{}, "", err
	}
	if err := tx.Commit(); err != nil {
		return ClientDetail{}, "", fmt.Errorf("failed to commit: %w", err)
	}
	return ClientDetail{Client: client, Resources: allowed}, plaintext, nil
}

// UpdateClient applies u to a client in one transaction, holding the row
// lock from the read (and fingerprint check) to the write.
func UpdateClient(ctx context.Context, s *store.Store, clientID string, u ClientUpdate) (ClientDetail, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ClientDetail{}, fmt.Errorf("failed to start a transaction: %w", err)
	}
	defer tx.Rollback()
	q := s.Q.WithTx(tx)

	current, err := getClient(ctx, q, clientID, true)
	if err != nil {
		return ClientDetail{}, err
	}
	if u.ExpectFingerprint != "" && u.ExpectFingerprint != current.Fingerprint() {
		return ClientDetail{}, fmt.Errorf("client %s %w", clientID, ErrStale)
	}
	cur := current.Client

	params := db.UpdateOAuthClientParams{
		ClientID:       clientID,
		Name:           sql.NullString{String: cur.Name, Valid: true},
		RedirectUris:   cur.RedirectUris,
		AllowedScopes:  cur.AllowedScopes,
		IsConfidential: sql.NullBool{Bool: cur.IsConfidential, Valid: true},
	}

	if u.Name != nil {
		name := strings.TrimSpace(*u.Name)
		if name == "" {
			return ClientDetail{}, errors.New("name cannot be empty")
		}
		params.Name = sql.NullString{String: name, Valid: true}
	}

	switch u.RedirectURIs.Mode {
	case Replace:
		params.RedirectUris = nonNil(u.RedirectURIs.Values)
	case Add:
		params.RedirectUris = internal.AppendUnique(cur.RedirectUris, u.RedirectURIs.Values)
	case Remove:
		remaining, notFound := internal.RemoveValues(cur.RedirectUris, u.RedirectURIs.Values)
		if len(notFound) > 0 {
			return ClientDetail{}, fmt.Errorf("client %s has no such redirect URI: %s - nothing was changed",
				clientID, strings.Join(notFound, ", "))
		}
		params.RedirectUris = remaining
	}

	if u.Scopes != nil {
		params.AllowedScopes = nonNil(*u.Scopes)
	}
	if u.Confidential != nil {
		params.IsConfidential = sql.NullBool{Bool: *u.Confidential, Valid: true}
	}

	// Trust is left alone unless asked. Whenever the result is a trusted
	// client -- trusting one, or changing the redirect URIs of one already
	// trusted -- it must pass ValidateTrustable against the redirect URIs it
	// will have.
	trusted := cur.Trusted
	if u.Trusted != nil {
		trusted = *u.Trusted
		params.Trusted = sql.NullBool{Bool: *u.Trusted, Valid: true}
	}
	if trusted {
		if err := internal.ValidateTrustable(cur.Kind, params.RedirectUris); err != nil {
			if cur.Trusted && u.Trusted == nil {
				return ClientDetail{}, fmt.Errorf("client %s is trusted: %w - nothing was changed", clientID, err)
			}
			return ClientDetail{}, err
		}
	}

	// The default resource is left alone unless asked; clearing it sets NULL.
	if u.DefaultResource != nil {
		params.SetDefaultResource = true
		if *u.DefaultResource != "" {
			r, err := FindResource(ctx, q, "default resource", *u.DefaultResource)
			if err != nil {
				return ClientDetail{}, err
			}
			params.DefaultResource = sql.NullString{String: r.Uri, Valid: true}
		}
	}

	// Same admin-scope rule as create, against the effective values.
	if err := internal.ValidateAdminScopes(params.AllowedScopes, params.IsConfidential.Bool); err != nil {
		return ClientDetail{}, err
	}
	if params.IsConfidential.Bool && !cur.ClientSecret.Valid {
		return ClientDetail{}, errors.New("cannot make a public client confidential - secret generation not yet supported in update")
	}
	if u.RedirectURIs.Mode == Replace || u.RedirectURIs.Mode == Add {
		if err := internal.ValidateRedirectURIs(params.RedirectUris); err != nil {
			return ClientDetail{}, err
		}
	}

	// The allow-list edit is resolved before anything is written, so an
	// unknown URI changes nothing.
	var resources []db.OauthResource
	if u.Resources.Mode != Keep {
		if resources, err = resolveResourceList(ctx, q, "resources", u.Resources.Values); err != nil {
			return ClientDetail{}, err
		}
	}

	updated, err := q.UpdateOAuthClient(ctx, params)
	if err != nil {
		return ClientDetail{}, fmt.Errorf("failed to update OAuth client: %w", err)
	}
	switch u.Resources.Mode {
	case Replace:
		err = replaceClientResources(ctx, q, updated.ID, resources)
	case Add:
		err = addClientResources(ctx, q, updated.ID, resources)
	case Remove:
		var notFound []string
		notFound, err = removeClientResources(ctx, q, updated.ID, resources)
		if err == nil && len(notFound) > 0 {
			err = fmt.Errorf("client %s does not have resource %s on its allow-list - nothing was changed",
				clientID, strings.Join(notFound, ", "))
		}
	}
	if err != nil {
		return ClientDetail{}, err
	}
	allowed, err := q.ListClientResources(ctx, updated.ID)
	if err != nil {
		return ClientDetail{}, fmt.Errorf("reading the client's allowed resources: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ClientDetail{}, fmt.Errorf("failed to commit: %w", err)
	}
	return ClientDetail{Client: updated, Resources: allowed}, nil
}

// DeleteClient deletes a client.
func DeleteClient(ctx context.Context, s *store.Store, clientID string) error {
	if _, err := GetClient(ctx, s, clientID); err != nil {
		return err
	}
	if err := s.Q.DeleteOAuthClient(ctx, clientID); err != nil {
		return fmt.Errorf("failed to delete OAuth client: %w", err)
	}
	return nil
}

// resolveResourceList turns resource URIs into registered resources (see
// FindResource), each once. what names the field for errors.
func resolveResourceList(ctx context.Context, q *db.Queries, what string, uris []string) ([]db.OauthResource, error) {
	var resources []db.OauthResource
	seen := map[uuid.UUID]bool{}
	for _, raw := range uris {
		resource, err := FindResource(ctx, q, what, raw)
		if err != nil {
			return nil, err
		}
		if !seen[resource.ID] {
			seen[resource.ID] = true
			resources = append(resources, resource)
		}
	}
	return resources, nil
}

// addClientResources puts resources on a client's allow-list. One already on
// it is left as it is.
func addClientResources(ctx context.Context, q *db.Queries, clientID uuid.UUID, resources []db.OauthResource) error {
	for _, r := range resources {
		if err := q.AddClientResource(ctx, db.AddClientResourceParams{ClientID: clientID, ResourceID: r.ID}); err != nil {
			return fmt.Errorf("allowing resource %s: %w", r.Uri, err)
		}
	}
	return nil
}

// removeClientResources takes resources off a client's allow-list and returns
// the URIs of any that were not on it. Callers treat that as an error and roll
// back, so a typo can't look like a successful revocation.
func removeClientResources(ctx context.Context, q *db.Queries, clientID uuid.UUID, resources []db.OauthResource) ([]string, error) {
	var notFound []string
	for _, r := range resources {
		n, err := q.RemoveClientResource(ctx, db.RemoveClientResourceParams{ClientID: clientID, ResourceID: r.ID})
		if err != nil {
			return nil, fmt.Errorf("removing resource %s: %w", r.Uri, err)
		}
		if n == 0 {
			notFound = append(notFound, r.Uri)
		}
	}
	return notFound, nil
}

// replaceClientResources makes a client's allow-list exactly resources.
func replaceClientResources(ctx context.Context, q *db.Queries, clientID uuid.UUID, resources []db.OauthResource) error {
	current, err := q.ListClientResources(ctx, clientID)
	if err != nil {
		return fmt.Errorf("reading the client's allowed resources: %w", err)
	}
	keep := map[uuid.UUID]bool{}
	for _, r := range resources {
		keep[r.ID] = true
	}
	var drop []db.OauthResource
	for _, r := range current {
		if !keep[r.ID] {
			drop = append(drop, r)
		}
	}
	if _, err := removeClientResources(ctx, q, clientID, drop); err != nil {
		return err
	}
	return addClientResources(ctx, q, clientID, resources)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
