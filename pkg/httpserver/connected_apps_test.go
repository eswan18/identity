package httpserver

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/views"
	"github.com/google/uuid"
)

func TestBuildConnectedApps(t *testing.T) {
	registered := uuid.New()
	claude := uuid.New()
	day1 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	used := time.Date(2026, 10, 27, 23, 30, 0, 0, time.UTC)

	rows := []db.ListUserConnectedAppsRow{
		{
			ClientUuid: claude, ClientID: "https://claude.ai/oauth/mcp-oauth-client-metadata",
			ClientName: "Claude", ClientKind: clientKindCIMD,
			Resource:       sql.NullString{String: "https://mcp.footstrike.run", Valid: true},
			ResourceName:   sql.NullString{String: "Footstrike", Valid: true},
			ResourceScopes: json.RawMessage(`{"runs:read": "Read your runs"}`),
			Scopes:         []string{"runs:read", "offline_access", "runs:read", "legacy:scope"},
			CreatedAt:      day2,
		},
		{
			ClientUuid: claude, ClientID: "https://claude.ai/oauth/mcp-oauth-client-metadata",
			ClientName: "Claude", ClientKind: clientKindCIMD,
			// A resource since removed from the registry: named by its host.
			Resource:       sql.NullString{String: "https://gone.example/api", Valid: true},
			ResourceScopes: json.RawMessage(`{}`),
			Scopes:         []string{"x:read"},
			CreatedAt:      day1,
		},
		{
			ClientUuid: registered, ClientID: "abc123", ClientName: "Footstrike Dashboard",
			ClientKind:     "registered",
			ResourceScopes: json.RawMessage(`{}`),
			Scopes:         []string{"openid", "profile"},
			CreatedAt:      day1,
		},
	}
	apps := buildConnectedApps(rows, map[uuid.UUID]time.Time{claude: used})

	if len(apps) != 2 {
		t.Fatalf("want 2 apps (grouped by client), got %d: %+v", len(apps), apps)
	}

	c := apps[0]
	if c.Name != "claude.ai" || c.ClaimedName != "Claude" || c.ClientURI != "https://claude.ai/oauth/mcp-oauth-client-metadata" {
		t.Errorf("CIMD client should be named by its host, with its claim and URL: %+v", c)
	}
	if c.ClientRef != claude.String() {
		t.Errorf("ClientRef = %q", c.ClientRef)
	}
	if len(c.Access) != 2 {
		t.Fatalf("want one access entry per resource, got %+v", c.Access)
	}
	a := c.Access[0]
	if a.ResourceName != "Footstrike" || a.ResourceHost != "mcp.footstrike.run" {
		t.Errorf("resource = %q (%q)", a.ResourceName, a.ResourceHost)
	}
	want := []views.ScopeDescription{
		{Scope: "runs:read", Description: "Read your runs"},
		{Scope: "offline_access", Description: scopeDescriptionMap["offline_access"]},
		{Scope: "legacy:scope", Description: "legacy:scope"},
	}
	if len(a.ScopeDescriptions) != len(want) {
		t.Fatalf("scopes = %+v, want %+v", a.ScopeDescriptions, want)
	}
	for i := range want {
		if a.ScopeDescriptions[i] != want[i] {
			t.Errorf("scope %d = %+v, want %+v", i, a.ScopeDescriptions[i], want[i])
		}
	}
	if c.Access[1].ResourceName != "gone.example" {
		t.Errorf("a resource missing from the registry should be named by its host, got %q", c.Access[1].ResourceName)
	}
	if c.ConnectedAt != "Oct 1, 2026" {
		t.Errorf("ConnectedAt should be the earliest consent, got %q", c.ConnectedAt)
	}
	if c.LastUsed != "Oct 27, 2026" || c.LastUsedISO != "2026-10-27T23:30:00Z" {
		t.Errorf("LastUsed = %q (%q)", c.LastUsed, c.LastUsedISO)
	}

	r := apps[1]
	if r.Name != "Footstrike Dashboard" || r.ClaimedName != "" || r.ClientURI != "" {
		t.Errorf("registered client: %+v", r)
	}
	if r.Access[0].ResourceName != "" {
		t.Errorf("a consent for identity itself has no resource name, got %q", r.Access[0].ResourceName)
	}
	if r.LastUsed != "" {
		t.Errorf("no token record: LastUsed should be empty, got %q", r.LastUsed)
	}
}

func TestConnectedAppsTemplate_EmptyState(t *testing.T) {
	var buf bytes.Buffer
	if err := views.ConnectedApps(views.ConnectedAppsView{CSRFToken: "tok"}).Render(context.Background(), &buf); err != nil {
		t.Fatal(err)
	}
	requireContainsAll(t, buf.String(),
		"<title>Connected Apps</title>",
		"No apps are connected to your account.",
		`href="/oauth/account-settings"`,
	)
	if strings.Contains(buf.String(), "/oauth/connected-apps/disconnect") {
		t.Error("empty state should have no disconnect form")
	}
}

func TestConnectedAppsTemplate_Apps(t *testing.T) {
	var buf bytes.Buffer
	err := views.ConnectedApps(views.ConnectedAppsView{
		CSRFToken: "tok",
		Success:   "App disconnected.",
		Apps: []views.ConnectedApp{{
			ClientRef: "11111111-1111-1111-1111-111111111111", Name: "claude.ai", ClaimedName: "Claude <b>",
			ClientURI: "https://claude.ai/oauth/meta",
			Access: []views.ConnectedAppAccess{{
				ResourceName: "Footstrike", ResourceHost: "mcp.footstrike.run",
				ScopeDescriptions: []views.ScopeDescription{{Scope: "runs:read", Description: "Read your runs"}},
			}},
			ConnectedAt: "Oct 1, 2026", ConnectedAtISO: "2026-10-01T12:00:00Z",
		}},
	}).Render(context.Background(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	requireContainsAll(t, html,
		"claude.ai",
		"Claude &lt;b&gt;",
		"https://claude.ai/oauth/meta",
		"Footstrike",
		"(mcp.footstrike.run)",
		"Read your runs",
		`<time datetime="2026-10-01T12:00:00Z">Oct 1, 2026</time>`,
		"Not recorded",
		`action="/oauth/connected-apps/disconnect"`,
		`name="csrf_token" value="tok"`,
		`name="client" value="11111111-1111-1111-1111-111111111111"`,
		`name="confirm" value="yes"`,
		"App disconnected.",
	)
	if strings.Contains(html, "No apps are connected") {
		t.Error("empty-state text shown alongside apps")
	}
}

func TestAccountSettingsLinksToConnectedApps(t *testing.T) {
	var buf bytes.Buffer
	if err := views.AccountSettings(views.AccountSettingsView{Username: "u"}).Render(context.Background(), &buf); err != nil {
		t.Fatal(err)
	}
	requireContainsAll(t, buf.String(), `href="/oauth/connected-apps"`, "Connected Apps")
}

// The disconnect POST is in the CSRF-protected group: without a token it is
// refused before the session is even looked at.
func TestConnectedAppsDisconnect_RequiresCSRF(t *testing.T) {
	s := newHermeticTestServer(t)
	form := url.Values{"client": {uuid.NewString()}, "confirm": {"yes"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/connected-apps/disconnect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "whatever"})
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without CSRF token: got %d, want 403", rec.Code)
	}
}

// Signed out, the page sends the visitor to login carrying it as return_to.
func TestConnectedApps_SignedOutRedirectsToLogin(t *testing.T) {
	s := newHermeticTestServer(t)
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/connected-apps", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("got %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/oauth/login?return_to=%2Foauth%2Fconnected-apps" {
		t.Fatalf("Location = %q", loc)
	}
}
