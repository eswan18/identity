package ui

import (
	"slices"

	"github.com/eswan18/identity/cmd/identity-cli/internal/ops"
	"github.com/eswan18/identity/cmd/identity-cli/internal/ui/views"
)

// Change is one line of the review page: a scalar's before and after, or a
// list's additions and removals.
type Change = views.Change

// DiffClient lists what u would change on cur.
func DiffClient(cur ops.ClientDetail, u ops.ClientUpdate) []Change {
	var out []Change
	c := cur.Client
	if u.Name != nil && *u.Name != c.Name {
		out = append(out, Change{Field: "Name", Before: c.Name, After: *u.Name})
	}
	if u.RedirectURIs.Mode == ops.Replace {
		if ch, ok := listChange("Redirect URIs", c.RedirectUris, u.RedirectURIs.Values); ok {
			out = append(out, ch)
		}
	}
	if u.Scopes != nil {
		if ch, ok := listChange("Scopes", c.AllowedScopes, *u.Scopes); ok {
			out = append(out, ch)
		}
	}
	if u.DefaultResource != nil && *u.DefaultResource != c.DefaultResource.String {
		out = append(out, Change{Field: "Default resource",
			Before: defaultLabel(c.DefaultResource.String), After: defaultLabel(*u.DefaultResource)})
	}
	if u.Resources.Mode == ops.Replace {
		if ch, ok := listChange("Allowed resources", resourceURIs(cur), u.Resources.Values); ok {
			out = append(out, ch)
		}
	}
	if u.Trusted != nil && *u.Trusted != c.Trusted {
		out = append(out, Change{Field: "Trusted", Before: yesNo(c.Trusted), After: yesNo(*u.Trusted)})
	}
	return out
}

// listChange is the additions and removals that turn before into after.
func listChange(field string, before, after []string) (Change, bool) {
	ch := Change{Field: field}
	for _, v := range after {
		if !slices.Contains(before, v) {
			ch.Added = append(ch.Added, v)
		}
	}
	for _, v := range before {
		if !slices.Contains(after, v) {
			ch.Removed = append(ch.Removed, v)
		}
	}
	return ch, len(ch.Added)+len(ch.Removed) > 0
}

func defaultLabel(uri string) string {
	if uri == "" {
		return "(identity itself)"
	}
	return uri
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// DiffResource lists what u would change on cur. A scope whose description
// changes shows as removed (old text) and added (new text).
func DiffResource(cur ops.ResourceDetail, u ops.ResourceUpdate) []Change {
	var out []Change
	r := cur.Resource
	if u.Name != nil && *u.Name != r.Name {
		out = append(out, Change{Field: "Name", Before: r.Name, After: *u.Name})
	}
	if u.Scopes.Mode == ops.Replace {
		if ch, ok := listChange("Scopes", scopeLines(cur.Scopes), scopeLines(u.Scopes.Set)); ok {
			out = append(out, ch)
		}
	}
	if u.DynamicClients != nil && *u.DynamicClients != r.DynamicClients {
		out = append(out, Change{Field: "Dynamic clients", Before: yesNo(r.DynamicClients), After: yesNo(*u.DynamicClients)})
	}
	return out
}
