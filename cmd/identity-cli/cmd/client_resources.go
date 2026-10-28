package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/eswan18/identity/cmd/identity-cli/internal"
	"github.com/eswan18/identity/pkg/db"
	"github.com/google/uuid"
)

// A registered client's resource allow-list: the resources it may request by
// name with the resource parameter, beyond its default resource (which is
// always allowed). client create --resources sets it; client update
// --resources replaces it, --add-resources and --remove-resources edit it,
// with the same semantics as the redirect-URI flags.

// resolveResourceList turns a comma-separated list of resource URIs into
// registered resources (see findResource), each once. flag names the flag
// for errors.
func resolveResourceList(ctx context.Context, q *db.Queries, flag, list string) ([]db.OauthResource, error) {
	var resources []db.OauthResource
	seen := map[uuid.UUID]bool{}
	for _, raw := range internal.ParseList(list) {
		resource, err := findResource(ctx, q, flag, raw)
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

// allowedResourcesValue renders a client's allow-list for display.
func allowedResourcesValue(resources []db.OauthResource) string {
	if len(resources) == 0 {
		return "(none beyond the default)"
	}
	uris := make([]string, len(resources))
	for i, r := range resources {
		uris[i] = r.Uri
	}
	return strings.Join(uris, ", ")
}
