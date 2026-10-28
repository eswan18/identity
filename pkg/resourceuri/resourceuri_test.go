package resourceuri

import (
	"errors"
	"testing"
)

func TestCanonicalize(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// Already canonical.
		{"https://sensibility.money/mcp", "https://sensibility.money/mcp"},
		{"https://api.footstrike.run", "https://api.footstrike.run"},
		// Scheme and host lowercase; path case kept.
		{"HTTPS://Sensibility.Money/MCP", "https://sensibility.money/MCP"},
		// Trailing slashes go, including a bare "/".
		{"https://sensibility.money/mcp/", "https://sensibility.money/mcp"},
		{"https://sensibility.money/", "https://sensibility.money"},
		{"https://sensibility.money//", "https://sensibility.money"},
		// The spec's own example.
		{"HTTPS://Sensibility.money/mcp/", "https://sensibility.money/mcp"},
		// Default ports go; others stay.
		{"https://example.com:443/api", "https://example.com/api"},
		{"http://example.com:80/api", "http://example.com/api"},
		{"https://example.com:8443/api", "https://example.com:8443/api"},
		{"http://example.com:443/api", "http://example.com:443/api"},
		{"https://example.com:/api", "https://example.com/api"},
		// IPv6 literals keep their brackets.
		{"https://[::1]:443/x", "https://[::1]/x"},
		{"https://[::1]:8443/x", "https://[::1]:8443/x"},
		// Query and percent-encoding are kept as given.
		{"https://example.com/a%2Fb?x=1", "https://example.com/a%2Fb?x=1"},
		// Opaque URIs: only the scheme is touched. "ethanswan:fitness" is a
		// live audience and must come through unchanged.
		{"ethanswan:fitness", "ethanswan:fitness"},
		{"URN:Example:Thing", "urn:Example:Thing"},
	}
	for _, c := range cases {
		got, err := Canonicalize(c.in)
		if err != nil {
			t.Errorf("Canonicalize(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Canonicalize(%q) = %q, want %q", c.in, got, c.want)
		}
		again, err := Canonicalize(got)
		if err != nil || again != got {
			t.Errorf("Canonicalize is not idempotent on %q: got %q, %v", got, again, err)
		}
	}
}

func TestCanonicalizeRefuses(t *testing.T) {
	cases := []struct {
		in   string
		want error
	}{
		{"", ErrEmpty},
		{"/mcp", ErrNotAbsolute},
		{"sensibility.money/mcp", ErrNotAbsolute},
		{"https://sensibility.money/mcp#frag", ErrFragment},
		{"https://sensibility.money/mcp#", ErrFragment},
		{"https://user:pw@sensibility.money/mcp", ErrUserinfo},
		{"https:///mcp", ErrNoHost},
	}
	for _, c := range cases {
		got, err := Canonicalize(c.in)
		if !errors.Is(err, c.want) {
			t.Errorf("Canonicalize(%q) = %q, %v; want error %v", c.in, got, err, c.want)
		}
	}
	if _, err := Canonicalize("https://exa mple.com"); err == nil {
		t.Error("Canonicalize accepted an unparseable URI")
	}
}

func TestValidateNew(t *testing.T) {
	got, err := ValidateNew("HTTPS://Sensibility.money/mcp/")
	if err != nil || got != "https://sensibility.money/mcp" {
		t.Errorf("ValidateNew = %q, %v; want the canonical https URI", got, err)
	}
	for _, in := range []string{"http://sensibility.money/mcp", "ethanswan:fitness"} {
		if _, err := ValidateNew(in); !errors.Is(err, ErrNotHTTPS) {
			t.Errorf("ValidateNew(%q) error = %v, want ErrNotHTTPS", in, err)
		}
	}
	if _, err := ValidateNew("https://sensibility.money/mcp#x"); !errors.Is(err, ErrFragment) {
		t.Errorf("ValidateNew should pass through Canonicalize's errors, got %v", err)
	}
}
