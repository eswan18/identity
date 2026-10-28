package httpserver

import (
	"net/url"
	"slices"

	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/redirecturi"
	"github.com/eswan18/identity/pkg/views"
)

// consentView is what the consent screen shows for a request that passed
// checkCodeIssuance (spec, section 8): who is asking, what for, and where the
// answer goes.
func consentView(client db.OauthClient, p authorizeParams, resource *resolvedResource) views.ConsentView {
	data := views.ConsentView{
		ClientName:        client.Name,
		ScopeDescriptions: consentScopeDescriptions(p.Scope, resource),
		RedirectHost:      redirectDestination(p.RedirectURI),
		LoopbackOnly:      allLoopback(client.RedirectUris),
	}

	// Who is asking. A registered client was named by whoever registered it,
	// so its name is shown as the app. A client identified by a metadata
	// document (CIMD, phase 3) named itself; the one thing about it identity
	// can vouch for is the host serving that document, so the host is the app
	// and the self-asserted name is only shown beneath it (CIMD §8.5).
	if client.Kind == "cimd" {
		data.ClientName = urlHost(client.ClientID)
		data.ClaimedName = client.Name
	}

	if resource != nil {
		data.ResourceName = resource.Name
		data.ResourceHost = resourceHost(resource.URI)
	}
	return data
}

// consentScopeDescriptions describes each requested scope, in request order
// and once each: identity's own scopes from scopeDescriptionMap, the
// resource's from the registry. A scope with no description is left out
// rather than shown raw; checkCodeIssuance has refused any request with a
// scope that is neither identity's nor the resource's, so none should reach
// here.
func consentScopeDescriptions(scope []string, resource *resolvedResource) []views.ScopeDescription {
	var descriptions []views.ScopeDescription
	var seen []string
	for _, sc := range scope {
		if slices.Contains(seen, sc) {
			continue
		}
		seen = append(seen, sc)
		desc, ok := scopeDescriptionMap[sc]
		if !ok && resource != nil {
			desc, ok = resource.Scopes[sc]
		}
		if ok {
			descriptions = append(descriptions, views.ScopeDescription{Scope: sc, Description: desc})
		}
	}
	return descriptions
}

// redirectDestination is where the answer goes, as the consent screen names
// it: the redirect URI's host (with any port) for a web URI, and the whole URI
// less any query for a custom scheme, whose "host" alone would mean nothing
// (footstrike://callback). The URI was validated against the client's
// registration before the page renders.
func redirectDestination(redirectURI string) string {
	u, err := url.Parse(redirectURI)
	if err != nil || u.Scheme == "" {
		return redirectURI
	}
	if u.Scheme == "http" || u.Scheme == "https" {
		return u.Host
	}
	u.RawQuery, u.ForceQuery, u.Fragment = "", false, ""
	return u.String()
}

// resourceHost is the host a resource URI names, for the consent screen. A URI
// without one (the grandfathered "ethanswan:fitness") is shown whole.
func resourceHost(uri string) string {
	if host := urlHost(uri); host != "" {
		return host
	}
	return uri
}

// urlHost is the host of a URL, or "" if it has none.
func urlHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// allLoopback reports whether every registered redirect URI is a loopback one
// (RFC 8252 §7.3): the client can only answer to a program on the user's own
// computer, which any program there could be. MCP's guidance is to warn
// before such a sign-in. A client with no redirect URIs is not warned about;
// it cannot complete a flow anyway.
func allLoopback(registered []string) bool {
	return len(registered) > 0 && !slices.ContainsFunc(registered, func(uri string) bool {
		return !redirecturi.IsLoopback(uri)
	})
}
