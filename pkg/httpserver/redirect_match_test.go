package httpserver

import "testing"

func TestRedirectURIAllowed(t *testing.T) {
	wild := "https://*.stacks.footstrike.run/auth/callback"
	exact := "https://staging.footstrike.run/auth/callback"

	tests := []struct {
		name       string
		registered []string
		candidate  string
		want       bool
	}{
		{"exact match still works", []string{exact}, exact, true},
		{"unregistered candidate rejected", []string{exact}, "https://evil.example.com/auth/callback", false},
		{"wildcard matches single label", []string{wild}, "https://hae-cadence.stacks.footstrike.run/auth/callback", true},
		{"wildcard alongside exact entries", []string{exact, wild}, "https://api-x.stacks.footstrike.run/auth/callback", true},
		{"wildcard rejects multi-label", []string{wild}, "https://a.b.stacks.footstrike.run/auth/callback", false},
		{"wildcard rejects bare suffix", []string{wild}, "https://stacks.footstrike.run/auth/callback", false},
		{"wildcard rejects empty label", []string{wild}, "https://.stacks.footstrike.run/auth/callback", false},
		{"wildcard rejects cousin domain", []string{wild}, "https://xstacks.footstrike.run/auth/callback", false},
		{"wildcard rejects wrong path", []string{wild}, "https://x.stacks.footstrike.run/other", false},
		{"wildcard rejects http candidate", []string{wild}, "http://x.stacks.footstrike.run/auth/callback", false},
		{"http wildcard entry matches nothing", []string{"http://*.stacks.footstrike.run/auth/callback"}, "http://x.stacks.footstrike.run/auth/callback", false},
		{"wildcard rejects query string", []string{wild}, "https://x.stacks.footstrike.run/auth/callback?a=b", false},
		{"wildcard rejects fragment", []string{wild}, "https://x.stacks.footstrike.run/auth/callback#f", false},
		{"wildcard rejects explicit port mismatch", []string{wild}, "https://x.stacks.footstrike.run:8443/auth/callback", false},
		{"host match is case-insensitive", []string{wild}, "https://X.Stacks.Footstrike.Run/auth/callback", true},
		{"mid-label wildcard entry matches nothing", []string{"https://api-*.stacks.footstrike.run/auth/callback"}, "https://api-x.stacks.footstrike.run/auth/callback", false},
		{"literal wildcard candidate passes only via the exact branch", []string{wild}, "https://*.stacks.footstrike.run/auth/callback", true},
		{"empty registered list rejects", nil, exact, false},
		{"wildcard rejects fullwidth-dot host", []string{wild}, "https://a\uFF0Eb.stacks.footstrike.run/auth/callback", false},
		{"wildcard rejects Kelvin-sign host", []string{wild}, "https://evil.stacks.footstri\u212Ae.run/auth/callback", false},
		{"wildcard rejects userinfo candidate", []string{wild}, "https://evil.com@x.stacks.footstrike.run/auth/callback", false},
		{"wildcard rejects percent-encoded path", []string{wild}, "https://x.stacks.footstrike.run/auth%2Fcallback", false},
		{"wildcard rejects trailing-dot FQDN", []string{wild}, "https://x.stacks.footstrike.run./auth/callback", false},
		{"wildcard rejects explicit port vs portless pattern", []string{wild}, "https://x.stacks.footstrike.run:443/auth/callback", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redirectURIAllowed(tt.registered, tt.candidate); got != tt.want {
				t.Errorf("redirectURIAllowed(%v, %q) = %v, want %v", tt.registered, tt.candidate, got, tt.want)
			}
		})
	}
}
