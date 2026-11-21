package ui

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/eswan18/identity/cmd/identity-cli/internal/ops"
)

// ParseLines splits a textarea or text field into values: on newlines,
// commas and other whitespace (none of which a redirect URI, scope or
// resource URI contains), trimmed, with empties and repeats dropped, in
// order.
func ParseLines(s string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// clientForm is the client edit form as submitted: the state the operator
// wants the client to have.
type clientForm struct {
	Name            string
	RedirectURIs    []string
	Scopes          []string
	Resources       []string // allow-list URIs
	DefaultResource string   // "" = identity itself
	Trusted         bool
	Fingerprint     string // the version the form (or review) was built from
}

func parseClientForm(r *http.Request) clientForm {
	var resources []string
	for _, v := range r.PostForm["resources"] {
		resources = append(resources, ParseLines(v)...)
	}
	return clientForm{
		Name:            strings.TrimSpace(r.PostFormValue("name")),
		RedirectURIs:    ParseLines(r.PostFormValue("redirect_uris")),
		Scopes:          ParseLines(r.PostFormValue("scopes")),
		Resources:       uniq(resources),
		DefaultResource: strings.TrimSpace(r.PostFormValue("default_resource")),
		Trusted:         r.PostFormValue("trusted") == "on",
		Fingerprint:     r.PostFormValue("fingerprint"),
	}
}

// formFromClient is the edit form pre-filled with a client's current state.
func formFromClient(d ops.ClientDetail) clientForm {
	return clientForm{
		Name:            d.Client.Name,
		RedirectURIs:    d.Client.RedirectUris,
		Scopes:          d.Client.AllowedScopes,
		Resources:       resourceURIs(d),
		DefaultResource: d.Client.DefaultResource.String,
		Trusted:         d.Client.Trusted,
		Fingerprint:     d.Fingerprint(),
	}
}

// buildClientUpdate is the change that turns cur into f: only the fields
// that differ, each as a full replacement of exactly the submitted value.
// Lists are compared as sets, so reordering alone is not a change.
func buildClientUpdate(cur ops.ClientDetail, f clientForm) ops.ClientUpdate {
	var u ops.ClientUpdate
	c := cur.Client
	if f.Name != c.Name {
		name := f.Name
		u.Name = &name
	}
	if !sameSet(f.RedirectURIs, c.RedirectUris) {
		u.RedirectURIs = ops.ListEdit{Mode: ops.Replace, Values: f.RedirectURIs}
	}
	if !sameSet(f.Scopes, c.AllowedScopes) {
		scopes := f.Scopes
		u.Scopes = &scopes
	}
	if !sameSet(f.Resources, resourceURIs(cur)) {
		u.Resources = ops.ListEdit{Mode: ops.Replace, Values: f.Resources}
	}
	if f.DefaultResource != c.DefaultResource.String {
		d := f.DefaultResource
		u.DefaultResource = &d
	}
	if f.Trusted != c.Trusted {
		t := f.Trusted
		u.Trusted = &t
	}
	return u
}

func resourceURIs(d ops.ClientDetail) []string {
	uris := make([]string, 0, len(d.Resources))
	for _, r := range d.Resources {
		uris = append(uris, r.Uri)
	}
	return uris
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

func uniq(vs []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range vs {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// resourceForm is the resource edit form as submitted.
type resourceForm struct {
	URI            string // create only
	Name           string
	Scopes         map[string]string
	DynamicClients bool
	Fingerprint    string
}

// parseResourceForm reads the scope rows (paired scope_name/scope_desc
// fields; rows with both blank are ignored). A row with only one half is
// kept, so the shared validation refuses it with a clear message. On error
// the form is still returned, as far as it was read, so the page can show
// the operator's input back to them.
func parseResourceForm(r *http.Request) (resourceForm, error) {
	f := resourceForm{
		URI:            strings.TrimSpace(r.PostFormValue("uri")),
		Name:           strings.TrimSpace(r.PostFormValue("name")),
		Scopes:         map[string]string{},
		DynamicClients: r.PostFormValue("dynamic_clients") == "on",
		Fingerprint:    r.PostFormValue("fingerprint"),
	}
	names, descs := r.PostForm["scope_name"], r.PostForm["scope_desc"]
	scopes := f.Scopes
	for i := 0; i < max(len(names), len(descs)); i++ {
		var name, desc string
		if i < len(names) {
			name = strings.TrimSpace(names[i])
		}
		if i < len(descs) {
			desc = strings.TrimSpace(descs[i])
		}
		if name == "" && desc == "" {
			continue
		}
		if _, dup := scopes[name]; dup {
			return f, fmt.Errorf("scope %q is listed twice", name)
		}
		scopes[name] = desc
	}
	return f, nil
}

func formFromResource(d ops.ResourceDetail) resourceForm {
	return resourceForm{
		URI: d.Resource.Uri, Name: d.Resource.Name, Scopes: d.Scopes,
		DynamicClients: d.Resource.DynamicClients, Fingerprint: d.Fingerprint(),
	}
}

// buildResourceUpdate is the change that turns cur into f: only what
// differs, scopes as a full replacement.
func buildResourceUpdate(cur ops.ResourceDetail, f resourceForm) ops.ResourceUpdate {
	var u ops.ResourceUpdate
	if f.Name != cur.Resource.Name {
		name := f.Name
		u.Name = &name
	}
	if !maps.Equal(f.Scopes, cur.Scopes) {
		u.Scopes = ops.ScopeEdit{Mode: ops.Replace, Set: f.Scopes}
	}
	if f.DynamicClients != cur.Resource.DynamicClients {
		d := f.DynamicClients
		u.DynamicClients = &d
	}
	return u
}

// scopeLines renders scopes as sorted "name: description" lines.
func scopeLines(scopes map[string]string) []string {
	lines := make([]string, 0, len(scopes))
	for name, desc := range scopes {
		lines = append(lines, name+": "+desc)
	}
	sort.Strings(lines)
	return lines
}
