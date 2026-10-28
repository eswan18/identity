package httpserver

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/eswan18/identity/pkg/config"
)

// TestAuthorizationResponsesCarryIss pins the helper every authorization
// response goes through: iss is always the configured issuer, on success and
// on error, with or without state. The integration suite walks the handlers'
// response paths; this checks the helper's own contract.
func TestAuthorizationResponsesCarryIss(t *testing.T) {
	const issuer = "https://identity.example.com"
	s := &Server{config: &config.Config{JWTIssuer: issuer}}

	tests := []struct {
		name      string
		p         authorizeParams
		respond   func(w http.ResponseWriter, r *http.Request, p authorizeParams)
		wantQuery url.Values
	}{
		{
			name: "code with state",
			p:    authorizeParams{RedirectURI: "https://app.example.com/cb", State: "xyz"},
			respond: func(w http.ResponseWriter, r *http.Request, p authorizeParams) {
				s.respondWithCode(w, r, p, "the-code")
			},
			wantQuery: url.Values{"code": {"the-code"}, "state": {"xyz"}, "iss": {issuer}},
		},
		{
			name: "code without state omits state",
			p:    authorizeParams{RedirectURI: "https://app.example.com/cb"},
			respond: func(w http.ResponseWriter, r *http.Request, p authorizeParams) {
				s.respondWithCode(w, r, p, "the-code")
			},
			wantQuery: url.Values{"code": {"the-code"}, "iss": {issuer}},
		},
		{
			name: "error with state",
			p:    authorizeParams{RedirectURI: "https://app.example.com/cb", State: "xyz"},
			respond: func(w http.ResponseWriter, r *http.Request, p authorizeParams) {
				s.respondWithError(w, r, p, "access_denied", "User denied consent")
			},
			wantQuery: url.Values{
				"error": {"access_denied"}, "error_description": {"User denied consent"},
				"state": {"xyz"}, "iss": {issuer},
			},
		},
		{
			name: "error without state omits state",
			p:    authorizeParams{RedirectURI: "https://app.example.com/cb"},
			respond: func(w http.ResponseWriter, r *http.Request, p authorizeParams) {
				s.respondWithError(w, r, p, "invalid_scope", "nope")
			},
			wantQuery: url.Values{"error": {"invalid_scope"}, "error_description": {"nope"}, "iss": {issuer}},
		},
		{
			name: "registered query parameters are kept",
			p:    authorizeParams{RedirectURI: "http://localhost:3118/callback?app=cli"},
			respond: func(w http.ResponseWriter, r *http.Request, p authorizeParams) {
				s.respondWithCode(w, r, p, "the-code")
			},
			wantQuery: url.Values{"app": {"cli"}, "code": {"the-code"}, "iss": {issuer}},
		},
		{
			name: "custom scheme",
			p:    authorizeParams{RedirectURI: "footstrike://auth/callback", State: "s"},
			respond: func(w http.ResponseWriter, r *http.Request, p authorizeParams) {
				s.respondWithCode(w, r, p, "the-code")
			},
			wantQuery: url.Values{"code": {"the-code"}, "state": {"s"}, "iss": {issuer}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tt.respond(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil), tt.p)

			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302", rec.Code)
			}
			loc, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parsing Location: %v", err)
			}
			want, _ := url.Parse(tt.p.RedirectURI)
			if loc.Scheme != want.Scheme || loc.Host != want.Host || loc.Path != want.Path {
				t.Errorf("redirected to %s://%s%s, want the redirect_uri %s", loc.Scheme, loc.Host, loc.Path, tt.p.RedirectURI)
			}
			got := loc.Query()
			if len(got) != len(tt.wantQuery) {
				t.Errorf("query = %v, want exactly %v", got, tt.wantQuery)
			}
			for k, v := range tt.wantQuery {
				if got.Get(k) != v[0] || len(got[k]) != 1 {
					t.Errorf("%s = %q, want exactly %q (query %v)", k, got[k], v[0], got)
				}
			}
		})
	}
}

// TestAuthorizationResponseRefusesUnparseableRedirectURI: the helper never
// redirects somewhere it cannot parse; that is identity's own error page.
func TestAuthorizationResponseRefusesUnparseableRedirectURI(t *testing.T) {
	s := &Server{config: &config.Config{JWTIssuer: "https://identity.example.com"}}
	rec := httptest.NewRecorder()
	s.respondWithCode(rec, httptest.NewRequest(http.MethodGet, "/", nil),
		authorizeParams{RedirectURI: "http://bad host/%zz"}, "c")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, want none", loc)
	}
}
