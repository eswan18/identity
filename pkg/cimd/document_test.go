package cimd

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/eswan18/identity/pkg/redirecturi"
)

const claudeCodeID = "https://claude.ai/oauth/claude-code-client-metadata"

// claudeCodeDocument is Claude Code's live document, as served on 2026-10-27.
const claudeCodeDocument = `{"client_id":"https://claude.ai/oauth/claude-code-client-metadata","client_name":"Claude Code","client_uri":"https://claude.ai","redirect_uris":["http://localhost/callback","http://127.0.0.1/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}`

func TestParseClaudeCodeDocument(t *testing.T) {
	if err := ValidateClientIDURL(claudeCodeID); err != nil {
		t.Fatalf("Claude Code's client_id is refused: %v", err)
	}
	md, err := parseDocument(claudeCodeID, []byte(claudeCodeDocument))
	if err != nil {
		t.Fatalf("Claude Code's document is refused: %v", err)
	}
	if md.ClientID != claudeCodeID || md.ClientName != "Claude Code" || md.ClientURI != "https://claude.ai" || md.LogoURI != "" {
		t.Errorf("unexpected metadata %+v", md)
	}
	want := []string{"http://localhost/callback", "http://127.0.0.1/callback"}
	if !slices.Equal(md.RedirectURIs, want) {
		t.Errorf("RedirectURIs = %v, want %v", md.RedirectURIs, want)
	}
	// Stored as oauth_clients.redirect_uris, these must admit Claude Code's
	// ephemeral-port callbacks and nothing across hosts.
	for _, cand := range []string{"http://localhost:51234/callback", "http://127.0.0.1:8080/callback", "http://localhost/callback"} {
		if !redirecturi.Allowed(md.RedirectURIs, cand) {
			t.Errorf("redirecturi.Allowed refuses %q", cand)
		}
	}
	for _, cand := range []string{"http://[::1]:5000/callback", "http://localhost:5000/other", "https://localhost/callback"} {
		if redirecturi.Allowed(md.RedirectURIs, cand) {
			t.Errorf("redirecturi.Allowed admits %q", cand)
		}
	}
}

// doc builds a document for "https://example.com/client" from a base that is
// valid, with fields replaced (a value of nil deletes the field).
func doc(overrides map[string]string) string {
	fields := map[string]string{
		"client_id":     `"https://example.com/client"`,
		"client_name":   `"Example"`,
		"redirect_uris": `["https://example.com/cb"]`,
	}
	for k, v := range overrides {
		if v == "" {
			delete(fields, k)
			continue
		}
		fields[k] = v
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	b.WriteString("{")
	for i, k := range keys {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"` + k + `":` + fields[k])
	}
	b.WriteString("}")
	return b.String()
}

func TestParseDocument(t *testing.T) {
	const id = "https://example.com/client"
	valid := []struct {
		name string
		body string
	}{
		{"minimal", doc(nil)},
		{"auth method none", doc(map[string]string{"token_endpoint_auth_method": `"none"`})},
		{"loopback with port", doc(map[string]string{"redirect_uris": `["http://127.0.0.1:8080/cb"]`})},
		{"loopback ipv6", doc(map[string]string{"redirect_uris": `["http://[::1]/cb"]`})},
		{"loopback localhost", doc(map[string]string{"redirect_uris": `["http://localhost/callback"]`})},
		{"hosted Claude callback", doc(map[string]string{"redirect_uris": `["https://claude.ai/api/mcp/auth_callback"]`})},
		{"https with port and query", doc(map[string]string{"redirect_uris": `["https://example.com:8443/cb?x=1"]`})},
		{"grant types: code only", doc(map[string]string{"grant_types": `["authorization_code"]`})},
		{"grant types: code and refresh", doc(map[string]string{"grant_types": `["refresh_token","authorization_code"]`})},
		{"response types code", doc(map[string]string{"response_types": `["code"]`})},
		{"client and logo uri", doc(map[string]string{"client_uri": `"https://example.com"`, "logo_uri": `"https://example.com/logo.png"`})},
		{"unknown fields ignored", doc(map[string]string{"scope": `"openid"`, "software_id": `{"x":1}`, "jwks_uri": `"https://example.com/jwks"`})},
		{"unicode name", doc(map[string]string{"client_name": `"Café Client"`})},
		{"surrounding whitespace", "  \n" + doc(nil) + "\n  "},
	}
	for _, c := range valid {
		if _, err := parseDocument(id, []byte(c.body)); err != nil {
			t.Errorf("%s: parseDocument = %v, want nil\n%s", c.name, err, c.body)
		}
	}

	invalid := []struct {
		name string
		body string
	}{
		{"empty", ""},
		{"not JSON", "hello"},
		{"array", `[` + doc(nil) + `]`},
		{"string", `"https://example.com/client"`},
		{"null", `null`},
		{"truncated", doc(nil)[:20]},
		{"trailing data", doc(nil) + `{}`},
		{"trailing garbage", doc(nil) + `x`},
		{"invalid UTF-8", "{\"client_name\":\"\xff\"}"},
		{"client_id missing", doc(map[string]string{"client_id": ""})},
		{"client_id differs", doc(map[string]string{"client_id": `"https://example.com/other"`})},
		{"client_id differs by trailing slash", doc(map[string]string{"client_id": `"https://example.com/client/"`})},
		{"client_id differs by case", doc(map[string]string{"client_id": `"https://Example.com/client"`})},
		{"client_id not a string", doc(map[string]string{"client_id": `1`})},
		{"client_id null", doc(map[string]string{"client_id": `null`})},
		{"client_name missing", doc(map[string]string{"client_name": ""})},
		{"client_name empty", doc(map[string]string{"client_name": `""`})},
		{"client_name blank", doc(map[string]string{"client_name": `"   "`})},
		{"client_name not a string", doc(map[string]string{"client_name": `["x"]`})},
		{"client_name control char", doc(map[string]string{"client_name": `"Evil\u0007"`})},
		{"client_name bidi override", doc(map[string]string{"client_name": `"Claude‮edoC"`})},
		{"client_name too long", doc(map[string]string{"client_name": `"` + strings.Repeat("a", 201) + `"`})},
		{"redirect_uris missing", doc(map[string]string{"redirect_uris": ""})},
		{"redirect_uris empty", doc(map[string]string{"redirect_uris": `[]`})},
		{"redirect_uris a string", doc(map[string]string{"redirect_uris": `"https://example.com/cb"`})},
		{"redirect_uris null", doc(map[string]string{"redirect_uris": `null`})},
		{"redirect_uris non-string", doc(map[string]string{"redirect_uris": `[1]`})},
		{"redirect_uris null member", doc(map[string]string{"redirect_uris": `[null]`})},
		{"redirect_uris too many", doc(map[string]string{"redirect_uris": `[` + strings.TrimSuffix(strings.Repeat(`"https://example.com/cb",`, 21), ",") + `]`})},
		{"redirect http non-loopback", doc(map[string]string{"redirect_uris": `["http://example.com/cb"]`})},
		{"redirect http private IP", doc(map[string]string{"redirect_uris": `["http://10.0.0.1/cb"]`})},
		{"redirect http 127.0.0.2", doc(map[string]string{"redirect_uris": `["http://127.0.0.2/cb"]`})},
		{"redirect http LOCALHOST", doc(map[string]string{"redirect_uris": `["http://LOCALHOST/cb"]`})},
		{"redirect loopback port 0", doc(map[string]string{"redirect_uris": `["http://127.0.0.1:0/cb"]`})},
		{"redirect loopback userinfo", doc(map[string]string{"redirect_uris": `["http://u@127.0.0.1/cb"]`})},
		{"redirect custom scheme", doc(map[string]string{"redirect_uris": `["myapp://cb"]`})},
		{"redirect relative", doc(map[string]string{"redirect_uris": `["/cb"]`})},
		{"redirect empty", doc(map[string]string{"redirect_uris": `[""]`})},
		{"redirect https no host", doc(map[string]string{"redirect_uris": `["https:///cb"]`})},
		{"redirect https userinfo", doc(map[string]string{"redirect_uris": `["https://u@example.com/cb"]`})},
		{"redirect fragment", doc(map[string]string{"redirect_uris": `["https://example.com/cb#x"]`})},
		{"redirect loopback fragment", doc(map[string]string{"redirect_uris": `["http://localhost/cb#x"]`})},
		{"redirect wildcard", doc(map[string]string{"redirect_uris": `["https://*.example.com/cb"]`})},
		{"redirect whitespace", doc(map[string]string{"redirect_uris": `["https://example.com/c b"]`})},
		{"redirect one bad among good", doc(map[string]string{"redirect_uris": `["https://example.com/cb","javascript:alert(1)"]`})},
		{"auth method client_secret_basic", doc(map[string]string{"token_endpoint_auth_method": `"client_secret_basic"`})},
		{"auth method client_secret_post", doc(map[string]string{"token_endpoint_auth_method": `"client_secret_post"`})},
		{"auth method private_key_jwt", doc(map[string]string{"token_endpoint_auth_method": `"private_key_jwt"`})},
		{"auth method empty", doc(map[string]string{"token_endpoint_auth_method": `""`})},
		{"auth method null", doc(map[string]string{"token_endpoint_auth_method": `null`})},
		{"client_secret", doc(map[string]string{"client_secret": `"s3cret"`})},
		{"client_secret null", doc(map[string]string{"client_secret": `null`})},
		{"client_secret_expires_at", doc(map[string]string{"client_secret_expires_at": `0`})},
		{"grant implicit", doc(map[string]string{"grant_types": `["implicit"]`})},
		{"grant client_credentials", doc(map[string]string{"grant_types": `["authorization_code","client_credentials"]`})},
		{"grant refresh only", doc(map[string]string{"grant_types": `["refresh_token"]`})},
		{"grant empty", doc(map[string]string{"grant_types": `[]`})},
		{"grant not array", doc(map[string]string{"grant_types": `"authorization_code"`})},
		{"response token", doc(map[string]string{"response_types": `["token"]`})},
		{"response code id_token", doc(map[string]string{"response_types": `["code id_token"]`})},
		{"response empty", doc(map[string]string{"response_types": `[]`})},
		{"client_uri http", doc(map[string]string{"client_uri": `"http://example.com"`})},
		{"client_uri not string", doc(map[string]string{"client_uri": `1`})},
		{"logo_uri javascript", doc(map[string]string{"logo_uri": `"javascript:alert(1)"`})},
		{"logo_uri data", doc(map[string]string{"logo_uri": `"data:image/png;base64,AAAA"`})},
		{"logo_uri fragment", doc(map[string]string{"logo_uri": `"https://example.com/l.png#x"`})},
	}
	for _, c := range invalid {
		_, err := parseDocument(id, []byte(c.body))
		if err == nil {
			t.Errorf("%s: parseDocument = nil, want error\n%s", c.name, c.body)
			continue
		}
		if !errors.Is(err, ErrInvalidDocument) {
			t.Errorf("%s: error %v does not wrap ErrInvalidDocument", c.name, err)
		}
	}
}

func TestTruncateKeepsErrorsShort(t *testing.T) {
	long := strings.Repeat("é", 200)
	got := truncate(long)
	if len(got) > 110 || !strings.HasSuffix(got, "…") {
		t.Errorf("truncate produced %d bytes: %q", len(got), got)
	}
}
