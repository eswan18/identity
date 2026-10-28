package httpserver

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/eswan18/identity/pkg/config"
)

// metadataJSON is the document as clients see it: newAuthorizationServerMetadata
// marshaled, then decoded into a generic map so the tests check the wire form
// (key names, omitted fields) rather than the Go struct.
func metadataJSON(t *testing.T, issuer string) map[string]any {
	t.Helper()
	raw, err := json.Marshal(newAuthorizationServerMetadata(&config.Config{JWTIssuer: issuer}))
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	return doc
}

func stringList(t *testing.T, doc map[string]any, key string) []string {
	t.Helper()
	raw, ok := doc[key].([]any)
	if !ok {
		t.Fatalf("%s is missing or not an array: %#v", key, doc[key])
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("%s holds a non-string %#v", key, v)
		}
		out = append(out, s)
	}
	return out
}

func TestAuthorizationServerMetadata_Contents(t *testing.T) {
	const issuer = "https://identity.example.com"
	doc := metadataJSON(t, issuer)

	// The issuer is the configured string verbatim, and every endpoint hangs off it.
	for key, want := range map[string]string{
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/oauth/authorize",
		"token_endpoint":         issuer + "/oauth/token",
		"jwks_uri":               issuer + "/.well-known/jwks.json",
		"userinfo_endpoint":      issuer + "/oauth/userinfo",
		"introspection_endpoint": issuer + "/oauth/introspect",
		"revocation_endpoint":    issuer + "/oauth/revoke",
		"end_session_endpoint":   issuer + "/oauth/logout",
	} {
		if doc[key] != want {
			t.Errorf("%s = %#v, want %q", key, doc[key], want)
		}
	}

	if got, want := stringList(t, doc, "scopes_supported"), []string{"openid", "profile", "email", "offline_access"}; !slices.Equal(got, want) {
		t.Errorf("scopes_supported = %v, want %v", got, want)
	}
	// Public clients authenticate with client_id alone. Claude needs "none"
	// advertised before it will use a client ID metadata document.
	authMethods := stringList(t, doc, "token_endpoint_auth_methods_supported")
	for _, m := range []string{"none", "client_secret_basic", "client_secret_post"} {
		if !slices.Contains(authMethods, m) {
			t.Errorf("token_endpoint_auth_methods_supported %v lacks %q", authMethods, m)
		}
	}
	if got := stringList(t, doc, "code_challenge_methods_supported"); !slices.Equal(got, []string{"S256"}) {
		t.Errorf("code_challenge_methods_supported = %v, want [S256]", got)
	}

	// Required by OIDC Discovery, so present in the shared document.
	for _, key := range []string{"response_types_supported", "subject_types_supported", "id_token_signing_alg_values_supported"} {
		if len(stringList(t, doc, key)) == 0 {
			t.Errorf("%s is empty", key)
		}
	}
}

// RFC 8414 §3.2: a parameter with zero elements must be omitted, not sent as [].
func TestAuthorizationServerMetadata_NoEmptyArrays(t *testing.T) {
	for key, v := range metadataJSON(t, "https://identity.example.com") {
		if arr, ok := v.([]any); ok && len(arr) == 0 {
			t.Errorf("%s is a zero-length array; it must be omitted", key)
		}
	}

	// And the omission is mechanical, not a matter of today's values: a field
	// left empty disappears from the wire form.
	md := newAuthorizationServerMetadata(&config.Config{JWTIssuer: "https://identity.example.com"})
	md.ResponseModesSupported = []string{}
	raw, err := json.Marshal(md)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("response_modes_supported")) {
		t.Errorf("an empty response_modes_supported was serialized: %s", raw)
	}
}

// These flags promise behavior that ships later: iss on every authorization
// response (with the helper that adds it), and client ID metadata documents.
// Advertising either early makes compliant clients fail.
func TestAuthorizationServerMetadata_NoPrematureFlags(t *testing.T) {
	doc := metadataJSON(t, "https://identity.example.com")
	for _, key := range []string{
		"authorization_response_iss_parameter_supported",
		"client_id_metadata_document_supported",
		"registration_endpoint",
	} {
		if _, present := doc[key]; present {
			t.Errorf("%s is advertised but not yet supported", key)
		}
	}
}

// Both well-known paths serve the same document, as JSON, with CORS.
func TestMetadataEndpoints_ServeTheSameDocument(t *testing.T) {
	srv := newHermeticTestServer(t)
	t.Cleanup(func() { srv.Close() })

	fetch := func(path string) []byte {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Origin", "https://claude.ai")
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d, want 200", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("GET %s: Content-Type %q, want application/json", path, ct)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("GET %s: Access-Control-Allow-Origin %q, want *", path, got)
		}
		body, err := io.ReadAll(rec.Body)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}

	oidc := fetch("/.well-known/openid-configuration")
	rfc8414 := fetch("/.well-known/oauth-authorization-server")
	if !bytes.Equal(oidc, rfc8414) {
		t.Errorf("documents differ:\nopenid-configuration:       %s\noauth-authorization-server: %s", oidc, rfc8414)
	}

	var doc map[string]any
	if err := json.Unmarshal(rfc8414, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["issuer"] != srv.config.JWTIssuer {
		t.Errorf("issuer = %#v, want the configured %q", doc["issuer"], srv.config.JWTIssuer)
	}
}
