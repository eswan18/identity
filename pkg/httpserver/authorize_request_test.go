package httpserver

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// A request the way a client sends it, including a repeated parameter and one
// identity does not read yet (resource): carrying the request whole means both
// survive every page untouched.
const sampleAuthorizeQuery = "response_type=code&client_id=app&redirect_uri=http%3A%2F%2Flocalhost%3A3118%2Fcallback" +
	"&scope=openid+profile&state=s%26t&code_challenge=abc&code_challenge_method=S256&nonce=n" +
	"&resource=https%3A%2F%2Fa.example&resource=https%3A%2F%2Fb.example"

func TestAuthorizeRequest_ResumesVerbatim(t *testing.T) {
	a := authorizeRequest(sampleAuthorizeQuery)
	if got, want := a.authorizeURL(), "/oauth/authorize?"+sampleAuthorizeQuery; got != want {
		t.Errorf("authorizeURL() = %q, want the original query unchanged: %q", got, want)
	}
}

// TestAuthorizeRequest_PageURLsRoundTrip checks that a page URL carries the
// request as exactly one value that decodes back to the original bytes, next
// to the page's own parameters, which never mix into the request.
func TestAuthorizeRequest_PageURLsRoundTrip(t *testing.T) {
	a := authorizeRequest(sampleAuthorizeQuery)

	tests := []struct {
		name, got, path string
		extra           url.Values
	}{
		{"login", a.loginURL(nil), "/oauth/login", nil},
		{"login with notice", a.loginURL(url.Values{"error": {"account_deactivated"}}), "/oauth/login", url.Values{"error": {"account_deactivated"}}},
		{"consent", a.consentURL(), "/oauth/consent", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, rawQuery, _ := strings.Cut(tt.got, "?")
			if path != tt.path {
				t.Errorf("path = %q, want %q", path, tt.path)
			}
			q, err := url.ParseQuery(rawQuery)
			if err != nil {
				t.Fatalf("page URL query does not parse: %v", err)
			}
			if got := q["authorize_query"]; len(got) != 1 || got[0] != sampleAuthorizeQuery {
				t.Errorf("authorize_query = %q, want exactly the original request", got)
			}
			for k, v := range tt.extra {
				if !reflect.DeepEqual(q[k], v) {
					t.Errorf("%s = %q, want %q", k, q[k], v)
				}
			}
			if len(q) != 1+len(tt.extra) {
				t.Errorf("page URL has parameters %v; the request's own must not leak out of authorize_query", q)
			}
		})
	}
}

func TestAuthorizeRequest_OutsideAFlow(t *testing.T) {
	var a authorizeRequest
	if a.inFlow() {
		t.Error("an empty request is not an OAuth flow")
	}
	if got := a.loginURL(nil); got != "/oauth/login" {
		t.Errorf("loginURL(nil) = %q, want /oauth/login", got)
	}
	if got := a.loginURL(url.Values{"registered": {"true"}}); got != "/oauth/login?registered=true" {
		t.Errorf("loginURL(registered) = %q", got)
	}
	// A request naming no client is not a flow either, as before the request
	// was carried whole (the check was client_id != "").
	if authorizeRequest("scope=openid").inFlow() {
		t.Error("a request without client_id is not an OAuth flow")
	}
}

func TestAuthorizeRequest_Params(t *testing.T) {
	got := authorizeRequest(sampleAuthorizeQuery).params()
	want := authorizeParams{
		ResponseType:        "code",
		ClientID:            "app",
		RedirectURI:         "http://localhost:3118/callback",
		Scope:               []string{"openid", "profile"},
		State:               "s&t",
		CodeChallenge:       "abc",
		CodeChallengeMethod: "S256",
		Nonce:               "n",
		// Every value, as sent: refusing more than one is checkCodeIssuance's
		// job, so it can answer the client with invalid_target.
		Resource: []string{"https://a.example", "https://b.example"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("params() = %+v, want %+v", got, want)
	}

	// scope defaults to openid, as on /oauth/authorize.
	if s := authorizeRequest("client_id=app").params().Scope; !reflect.DeepEqual(s, []string{"openid"}) {
		t.Errorf("default scope = %v, want [openid]", s)
	}

	// A malformed pair is skipped, as r.URL.Query() skips it on /oauth/authorize.
	if c := authorizeRequest("client_id=app&bad=%zz").params().ClientID; c != "app" {
		t.Errorf("client_id = %q, want the well-formed pair kept", c)
	}
}

// TestAuthorizeParams_SameReadingEverywhere: /oauth/authorize reads the
// request from its own URL, consent from the carried value. They must agree.
func TestAuthorizeParams_SameReadingEverywhere(t *testing.T) {
	direct := parseAuthorizeParams(httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+sampleAuthorizeQuery, nil).URL.Query())
	form := url.Values{"authorize_query": {sampleAuthorizeQuery}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	carried := carriedAuthorizeRequest(req).params()
	if !reflect.DeepEqual(direct, carried) {
		t.Errorf("direct %+v != carried %+v", direct, carried)
	}
}
