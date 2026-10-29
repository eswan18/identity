package cimd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
)

// Captured from https://chatgpt.com/oauth/client.json on 2026-10-29.
// Keep tests offline and deterministic; the real document also advertises a
// JWKS URL, which identity must not fetch when using public-client auth.
func TestParseChatGPTDocument(t *testing.T) {
	body, err := os.ReadFile("testdata/chatgpt-client.json")
	if err != nil {
		t.Fatal(err)
	}
	const stableID = "https://chatgpt.com/oauth/client.json"
	for _, id := range []string{stableID, "https://chatgpt.com/oauth/test-callback-id/client.json"} {
		t.Run(id, func(t *testing.T) {
			var fields map[string]any
			if err := json.Unmarshal(body, &fields); err != nil {
				t.Fatal(err)
			}
			fields["client_id"] = id
			data, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			md, err := parseDocument(id, data)
			if err != nil {
				t.Fatal(err)
			}
			if md.ClientID != id || md.ClientName != "ChatGPT" || !slices.Equal(md.RedirectURIs, []string{"https://chatgpt.com/connector_platform_oauth_redirect"}) {
				t.Fatalf("unexpected metadata: %+v", md)
			}
		})
	}
}

func TestAuthMethodNegotiation(t *testing.T) {
	cases := []struct {
		name, plural, singular string
		valid                  bool
	}{
		{"both absent", "", "", true},
		{"legacy none", "", `"none"`, true},
		{"plural none", `["none"]`, "", true},
		{"ChatGPT preference", `["none","private_key_jwt"]`, `"private_key_jwt"`, true},
		{"order independent", `["private_key_jwt","none"]`, `"private_key_jwt"`, true},
		{"unknown methods with none", `["future_method","none"]`, "", true},
		{"legacy none with alternatives", `["private_key_jwt","none"]`, `"none"`, true},
		{"no overlap", `["private_key_jwt"]`, `"private_key_jwt"`, false},
		{"no fallback from list", `["private_key_jwt"]`, `"none"`, false},
		{"no implicit none", `["private_key_jwt"]`, "", false},
		{"empty list", `[]`, `"none"`, false},
		{"list null", `null`, `"none"`, false},
		{"list string", `"none"`, "", false},
		{"list object", `{}`, "", false},
		{"null element", `["none",null]`, "", false},
		{"number element", `["none",1]`, "", false},
		{"object element", `["none",{}]`, "", false},
		{"empty element", `["none",""]`, "", false},
		{"blank element", `["none"," "]`, "", false},
		{"case sensitive", `["NONE"]`, "", false},
		{"not trimmed", `[" none "]`, "", false},
		{"singular null", `["none"]`, `null`, false},
		{"singular number", `["none"]`, `1`, false},
		{"singular empty", `["none"]`, `""`, false},
		{"singular blank", `["none"]`, `" "`, false},
		{"legacy private key only", "", `"private_key_jwt"`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseDocument(testID, []byte(doc(map[string]string{
				"token_endpoint_auth_methods_supported": c.plural,
				"token_endpoint_auth_method":            c.singular,
			})))
			if c.valid && err != nil {
				t.Fatal(err)
			}
			if !c.valid && !errors.Is(err, ErrInvalidDocument) {
				t.Fatalf("got %v, want invalid document", err)
			}
		})
	}
	// Advertising none cannot make a secret-bearing document public.
	for _, field := range []string{"client_secret", "client_secret_expires_at"} {
		_, err := parseDocument(testID, []byte(doc(map[string]string{
			"token_endpoint_auth_methods_supported": `["none","private_key_jwt"]`, field: `"secret"`,
		})))
		if !errors.Is(err, ErrInvalidDocument) {
			t.Fatalf("%s: got %v", field, err)
		}
	}
}

func TestChatGPTHostAllowlist(t *testing.T) {
	r, err := NewResolver(Config{AllowedHosts: []string{"claude.ai", "chatgpt.com"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"https://chatgpt.com/oauth/client.json", "https://chatgpt.com/oauth/callback-id/client.json", claudeID, claudeCodeID} {
		if !r.HostAllowed(id) {
			t.Errorf("refused %s", id)
		}
	}
	for _, id := range []string{"https://evil.chatgpt.com/oauth/client.json", "https://chatgpt.com.evil.test/oauth/client.json", "https://evil.test/oauth/client.json"} {
		if r.HostAllowed(id) {
			t.Errorf("accepted %s", id)
		}
	}
	// Keep the parser's other security checks in force for this document shape.
	body, err := os.ReadFile("testdata/chatgpt-client.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, replacement := range []string{"https://*.chatgpt.com/callback", "http://chatgpt.com/callback"} {
		invalid := strings.ReplaceAll(string(body), "https://chatgpt.com/connector_platform_oauth_redirect", replacement)
		if _, err := parseDocument("https://chatgpt.com/oauth/client.json", []byte(invalid)); !errors.Is(err, ErrInvalidDocument) {
			t.Fatalf("accepted redirect %s", replacement)
		}
	}
}

// Exercise fetching, parsing and caching together through the real resolver.
// Only the client ID is changed to the TLS harness host; the rest of the live
// ChatGPT document, including the unused jwks_uri, is preserved.
func TestResolveChatGPTDocument(t *testing.T) {
	h := newHarness(t)
	body, err := os.ReadFile("testdata/chatgpt-client.json")
	if err != nil {
		t.Fatal(err)
	}
	data := strings.Replace(string(body), `"client_id":"https://chatgpt.com/oauth/client.json"`, `"client_id":"https://example.com/client"`, 1)
	h.serve(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/client" {
			t.Errorf("unexpected fetch: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=600")
		fmt.Fprint(w, data)
	})
	for range 2 {
		md, err := h.r.Resolve(t.Context(), testID)
		if err != nil {
			t.Fatal(err)
		}
		if md.ClientName != "ChatGPT" {
			t.Fatalf("wrong metadata: %+v", md)
		}
	}
	if h.hits.Load() != 1 {
		t.Fatalf("expected one metadata fetch and no JWKS fetch, got %d", h.hits.Load())
	}
}
