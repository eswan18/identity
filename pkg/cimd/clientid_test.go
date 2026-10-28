package cimd

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateClientIDURL(t *testing.T) {
	valid := []string{
		"https://claude.ai/oauth/claude-code-client-metadata",
		"https://claude.ai/x",
		"https://example.com/client.json",
		"https://sub.example.com/a/b/c",
		"https://example.com/a/", // trailing slash is just part of the string
		"https://example.com/a%20b",
		"https://example.com/...", // three dots is a name, not a dot segment
		"https://example.com/.well-known/client",
		"https://xn--bcher-kva.example/client", // punycode host
		"https://1.2.3.4/client",               // only usable if allow-listed
	}
	for _, s := range valid {
		if err := ValidateClientIDURL(s); err != nil {
			t.Errorf("ValidateClientIDURL(%q) = %v, want nil", s, err)
		}
		if !IsClientIDURL(s) {
			t.Errorf("IsClientIDURL(%q) = false", s)
		}
	}

	invalid := []struct{ in, why string }{
		{"", "empty"},
		{"claude.ai/oauth/x", "no scheme"},
		{"http://claude.ai/oauth/x", "http"},
		{"HTTPS://claude.ai/oauth/x", "uppercase scheme"},
		{"ftp://claude.ai/oauth/x", "other scheme"},
		{"https://claude.ai", "no path"},
		{"https://claude.ai/", "path is only /"},
		{"https://user@claude.ai/x", "userinfo"},
		{"https://user:pw@claude.ai/x", "userinfo with password"},
		{"https://claude.ai/x#frag", "fragment"},
		{"https://claude.ai/x#", "empty fragment"},
		{"https://claude.ai/x?a=b", "query"},
		{"https://claude.ai/x?", "empty query"},
		{"https://claude.ai/./x", "dot segment"},
		{"https://claude.ai/a/../x", "dot-dot segment"},
		{"https://claude.ai/x/.", "trailing dot segment"},
		{"https://claude.ai/x/..", "trailing dot-dot segment"},
		{"https://claude.ai/%2e%2e/x", "encoded dot-dot"},
		{"https://claude.ai/%2E/x", "encoded dot, uppercase"},
		{"https://claude.ai/.%2E/x", "half-encoded dot-dot"},
		{"https://claude.ai:443/x", "explicit default port"},
		{"https://claude.ai:8443/x", "explicit port"},
		{"https://Claude.ai/x", "uppercase host"},
		{"https://claude.ai./x", "trailing dot on host"},
		{"https://.claude.ai/x", "leading dot on host"},
		{"https://claude..ai/x", "empty label"},
		{"https://-claude.ai/x", "label starts with hyphen"},
		{"https://claude_ai.com/x", "underscore in host"},
		{"https://[::1]/x", "IPv6 literal"},
		{"https:///x", "empty host"},
		{"https://claude.ai/a b", "space"},
		{"https://claude.ai/a\\b", "backslash"},
		{"https://claude.ai/a\nb", "newline"},
		{"https://claude.ai/a%zz", "bad percent-encoding"},
		{"https://claude.ai/ü", "non-canonical: raw non-ASCII"},
		{"https://bücher.example/x", "non-ASCII host"},
		{"https://claude.ai/" + strings.Repeat("a", maxClientIDLength), "too long"},
		{"https:claude.ai/x", "opaque"},
		{"5Gx0yFJ1oLqzHd5mVwJ0aw", "a hand-registered client id"},
	}
	for _, c := range invalid {
		err := ValidateClientIDURL(c.in)
		if err == nil {
			t.Errorf("ValidateClientIDURL(%q) [%s] = nil, want error", c.in, c.why)
			continue
		}
		if !errors.Is(err, ErrNotClientIDURL) {
			t.Errorf("ValidateClientIDURL(%q) = %v, want ErrNotClientIDURL", c.in, err)
		}
		if IsClientIDURL(c.in) {
			t.Errorf("IsClientIDURL(%q) [%s] = true", c.in, c.why)
		}
	}
}

func TestHostOf(t *testing.T) {
	if got := hostOf("https://claude.ai/oauth/x"); got != "claude.ai" {
		t.Errorf("hostOf = %q", got)
	}
	md := &Metadata{ClientID: "https://claude.ai/oauth/claude-code-client-metadata"}
	if md.Host() != "claude.ai" {
		t.Errorf("Host() = %q", md.Host())
	}
}

func TestNewResolverAllowedHosts(t *testing.T) {
	r, err := NewResolver(Config{AllowedHosts: []string{"claude.ai", " ", ""}})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Enabled() {
		t.Error("Enabled() = false with claude.ai allowed")
	}
	if !r.HostAllowed("https://claude.ai/oauth/x") {
		t.Error("claude.ai not allowed")
	}
	for _, s := range []string{
		"https://www.claude.ai/oauth/x", // exact host match only
		"https://evilclaude.ai/oauth/x",
		"https://claude.ai.evil.com/oauth/x",
		"https://claude.ai/", // allowed host, invalid URL
	} {
		if r.HostAllowed(s) {
			t.Errorf("HostAllowed(%q) = true", s)
		}
	}

	r, err = NewResolver(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Enabled() {
		t.Error("Enabled() = true with no hosts")
	}

	for _, bad := range []string{"https://claude.ai", "claude.ai:443", "Claude.ai", "claude.ai/x", "*.claude.ai"} {
		if _, err := NewResolver(Config{AllowedHosts: []string{bad}}); err == nil {
			t.Errorf("NewResolver accepted allowed host %q", bad)
		}
	}
}
