package config

import (
	"slices"
	"testing"
)

func TestSplitHostList(t *testing.T) {
	tests := map[string][]string{
		"":                        nil,
		" , ,":                    nil,
		"claude.ai":               {"claude.ai"},
		" claude.ai , ":           {"claude.ai"},
		"claude.ai,example.com":   {"claude.ai", "example.com"},
		"claude.ai,,example.com,": {"claude.ai", "example.com"},
	}
	for raw, want := range tests {
		if got := splitHostList(raw); !slices.Equal(got, want) {
			t.Errorf("splitHostList(%q) = %#v, want %#v", raw, got, want)
		}
	}
}

func TestParseCIMDAllowedHosts(t *testing.T) {
	t.Setenv("CIMD_ALLOWED_HOSTS", "claude.ai")
	if got := parseCIMDAllowedHosts(); !slices.Equal(got, []string{"claude.ai"}) {
		t.Errorf("parseCIMDAllowedHosts() = %#v", got)
	}
	t.Setenv("CIMD_ALLOWED_HOSTS", "")
	if got := parseCIMDAllowedHosts(); got != nil {
		t.Errorf("unset should disable CIMD, got %#v", got)
	}
}
