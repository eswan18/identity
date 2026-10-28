package httpserver

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/views"
)

func TestConsentViewRegisteredClient(t *testing.T) {
	client := db.OauthClient{
		ClientID:     "abc",
		Name:         "Claude Code",
		Kind:         "registered",
		RedirectUris: []string{"http://localhost/callback", "http://127.0.0.1/callback"},
	}
	resource := &resolvedResource{
		URI:    "https://sensibility.money/mcp",
		Name:   "Sensibility",
		Scopes: map[string]string{"sensibility:read": "Read your accounts"},
	}
	p := authorizeParams{
		RedirectURI: "http://localhost:51234/callback",
		Scope:       []string{"sensibility:read", "offline_access", "sensibility:read", "not:defined"},
	}
	got := consentView(client, p, resource)

	if got.ClientName != "Claude Code" || got.ClaimedName != "" {
		t.Errorf("who: %q / %q, want the registered name and no claim", got.ClientName, got.ClaimedName)
	}
	if got.ResourceName != "Sensibility" || got.ResourceHost != "sensibility.money" {
		t.Errorf("what for: %q (%q)", got.ResourceName, got.ResourceHost)
	}
	want := []views.ScopeDescription{
		{Scope: "sensibility:read", Description: "Read your accounts"},
		{Scope: "offline_access", Description: scopeDescriptionMap["offline_access"]},
	}
	if !reflect.DeepEqual(got.ScopeDescriptions, want) {
		t.Errorf("scopes = %+v, want %+v (each once, an undefined one never shown)", got.ScopeDescriptions, want)
	}
	if got.RedirectHost != "localhost:51234" {
		t.Errorf("RedirectHost = %q", got.RedirectHost)
	}
	if !got.LoopbackOnly {
		t.Error("every redirect URI is loopback: the page should warn")
	}
}

// TestConsentViewCIMDClient: a client identified by a metadata document is
// presented by the host serving it, with the name it gives itself beneath.
// Not reachable until phase 3 creates such clients.
func TestConsentViewCIMDClient(t *testing.T) {
	client := db.OauthClient{
		ClientID:     "https://claude.ai/oauth/claude-code-client-metadata",
		Name:         "Claude Code",
		Kind:         "cimd",
		RedirectUris: []string{"https://claude.ai/api/mcp/auth_callback"},
	}
	got := consentView(client, authorizeParams{RedirectURI: "https://claude.ai/api/mcp/auth_callback", Scope: []string{"openid"}}, nil)
	if got.ClientName != "claude.ai" || got.ClaimedName != "Claude Code" {
		t.Errorf("who: %q / %q, want claude.ai calling itself Claude Code", got.ClientName, got.ClaimedName)
	}
	if got.ResourceName != "" || got.LoopbackOnly {
		t.Errorf("no resource and an https redirect: %+v", got)
	}
}

func TestRedirectDestination(t *testing.T) {
	cases := map[string]string{
		"https://app.example.com/callback?x=1": "app.example.com",
		"http://localhost:3000/cb":             "localhost:3000",
		"footstrike://callback":                "footstrike://callback",
		"footstrike://callback?x=1":            "footstrike://callback",
		"com.example.app:/oauth":               "com.example.app:/oauth",
	}
	for in, want := range cases {
		if got := redirectDestination(in); got != want {
			t.Errorf("redirectDestination(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResourceHost(t *testing.T) {
	if got := resourceHost("https://sensibility.money/mcp"); got != "sensibility.money" {
		t.Errorf("got %q", got)
	}
	if got := resourceHost("ethanswan:fitness"); got != "ethanswan:fitness" {
		t.Errorf("a URI with no host is shown whole, got %q", got)
	}
}

func TestAllLoopback(t *testing.T) {
	cases := []struct {
		uris []string
		want bool
	}{
		{[]string{"http://localhost/callback"}, true},
		{[]string{"http://localhost/callback", "http://127.0.0.1:8080/callback", "http://[::1]/cb"}, true},
		{[]string{"http://localhost/callback", "https://app.example.com/callback"}, false},
		{[]string{"https://localhost/callback"}, false},
		{[]string{"footstrike://callback"}, false},
		{nil, false},
	}
	for _, c := range cases {
		if got := allLoopback(c.uris); got != c.want {
			t.Errorf("allLoopback(%v) = %v, want %v", c.uris, got, c.want)
		}
	}
}

// TestPageTemplatesRenderConsentForResource: the consent page names the
// resource and its host, where the answer goes, and warns for a loopback-only
// client; without those, none of it appears.
func TestPageTemplatesRenderConsentForResource(t *testing.T) {
	render := func(v views.ConsentView) string {
		var buf bytes.Buffer
		if err := views.Consent(v).Render(context.Background(), &buf); err != nil {
			t.Fatalf("rendering Consent: %v", err)
		}
		return buf.String()
	}
	page := render(views.ConsentView{
		ClientName:        "claude.ai",
		ClaimedName:       "Claude Code",
		ResourceName:      "Sensibility",
		ResourceHost:      "sensibility.money",
		ScopeDescriptions: []views.ScopeDescription{{Scope: "sensibility:read", Description: "Read your accounts"}},
		RedirectHost:      "localhost:51234",
		LoopbackOnly:      true,
	})
	requireContainsAll(t, page,
		"<strong>claude.ai</strong>",
		"It calls itself “Claude Code”",
		"<strong>Sensibility</strong>",
		"(sensibility.money)",
		"Read your accounts",
		"<strong>localhost:51234</strong>",
		"This app runs on your computer",
	)

	plain := render(views.ConsentView{ClientName: "Footstrike", RedirectHost: "footstrike.run"})
	for _, absent := range []string{"It calls itself", "Access to:", "This app runs on your computer"} {
		if strings.Contains(plain, absent) {
			t.Errorf("page without a claim, resource or loopback-only client contains %q", absent)
		}
	}
	requireContainsAll(t, plain, "<strong>footstrike.run</strong>")
}
