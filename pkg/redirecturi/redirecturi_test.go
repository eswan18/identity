package redirecturi

import (
	"net/url"
	"strings"
	"testing"
)

// The preview-environment pattern this feature exists to support. Every
// tightening below has to leave this working.
const previewPattern = "https://*.preview.footstrike.run/oauth/callback"

func TestValidateWildcardPattern_BreadthGuard(t *testing.T) {
	tests := []struct {
		name    string
		entry   string
		wantErr bool
		// wantErrContains, when set, asserts the operator-facing message names
		// the actual problem rather than some earlier structural check.
		wantErrContains string
	}{
		// The legitimate case.
		{name: "preview subdomain accepted", entry: previewPattern},
		{name: "other zone preview subdomain accepted", entry: "https://*.preview.haruspex.fyi/auth/callback"},
		{name: "deep subdomain accepted", entry: "https://*.a.b.preview.footstrike.run/cb"},

		// Public suffixes. These all have two or more dots and so passed the
		// previous "at least two dots" heuristic, yet anyone can obtain a host
		// under them.
		{
			name: "s3 bucket namespace rejected", entry: "https://*.s3.amazonaws.com/callback",
			wantErr: true, wantErrContains: "public suffix",
		},
		{
			name: "azure blob namespace rejected", entry: "https://*.blob.core.windows.net/callback",
			wantErr: true, wantErrContains: "public suffix",
		},
		{
			name: "github pages rejected", entry: "https://*.github.io/callback",
			wantErr: true, wantErrContains: "public suffix",
		},
		{
			name: "cloudflare pages rejected", entry: "https://*.pages.dev/callback",
			wantErr: true, wantErrContains: "public suffix",
		},
		{
			name: "vercel apps rejected", entry: "https://*.vercel.app/callback",
			wantErr: true, wantErrContains: "public suffix",
		},
		{
			name: "bare TLD rejected", entry: "https://*.run/callback",
			wantErr: true, wantErrContains: "public suffix",
		},
		{
			name: "multi-label public suffix rejected", entry: "https://*.co.uk/callback",
			wantErr: true, wantErrContains: "public suffix",
		},

		// Registrable domains. A wildcard over a whole domain an attacker can
		// buy is not a bounded namespace.
		{
			name: "registrable domain rejected", entry: "https://*.evil.com/callback",
			wantErr: true, wantErrContains: "registrable domain",
		},
		{
			name: "own apex rejected", entry: "https://*.footstrike.run/callback",
			wantErr: true, wantErrContains: "registrable domain",
		},

		// The trailing-dot bypass: "evil.com." has two dots and denotes the same
		// name as "evil.com", which is rejected. Both spellings must agree.
		{
			name: "trailing dot on registrable domain rejected", entry: "https://*.evil.com./callback",
			wantErr: true, wantErrContains: "registrable domain",
		},
		{
			name: "trailing dot on public suffix rejected", entry: "https://*.s3.amazonaws.com./callback",
			wantErr: true, wantErrContains: "public suffix",
		},
		{name: "trailing dot on valid suffix still accepted", entry: "https://*.preview.footstrike.run./cb"},
		{name: "double trailing dot rejected", entry: "https://*.evil.com../callback", wantErr: true},

		// Structural rules carried over from the original validator.
		{name: "no wildcard rejected", entry: "https://preview.footstrike.run/cb", wantErr: true},
		{name: "two wildcards rejected", entry: "https://*.*.footstrike.run/cb", wantErr: true},
		{name: "mid-label wildcard rejected", entry: "https://api-*.preview.footstrike.run/cb", wantErr: true},
		{name: "http rejected", entry: "http://*.preview.footstrike.run/cb", wantErr: true},
		{name: "missing path rejected", entry: "https://*.preview.footstrike.run", wantErr: true},
		{name: "root path rejected", entry: "https://*.preview.footstrike.run/", wantErr: true},
		{name: "query rejected", entry: "https://*.preview.footstrike.run/cb?a=1", wantErr: true},
		{name: "fragment rejected", entry: "https://*.preview.footstrike.run/cb#f", wantErr: true},
		{name: "userinfo rejected", entry: "https://u:p@*.preview.footstrike.run/cb", wantErr: true},
		{name: "empty suffix rejected", entry: "https://*./cb", wantErr: true},

		// Unicode confusables in the pattern itself.
		{name: "kelvin sign in suffix rejected", entry: "https://*.preview.footstriKe.run/cb", wantErr: true},
		{name: "fullwidth stop in suffix rejected", entry: "https://*.preview．footstrike.run/cb", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWildcardPattern(tt.entry)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateWildcardPattern(%q) error = %v, wantErr %v", tt.entry, err, tt.wantErr)
			}
			if tt.wantErrContains != "" && !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Errorf("ValidateWildcardPattern(%q) error = %q, want it to mention %q",
					tt.entry, err, tt.wantErrContains)
			}
		})
	}
}

// TestAllowed_RejectsOverBroadPatternAtRequestTime is the regression test for
// the core defect: the breadth guard used to live only in identity-cli, which
// is not on the request path, so a too-broad row already in
// oauth_clients.redirect_uris was matched unconditionally. Allowed must refuse
// these regardless of how they got into the database.
func TestAllowed_RejectsOverBroadPatternAtRequestTime(t *testing.T) {
	tests := []struct {
		name      string
		registered string
		candidate string
	}{
		{
			name:       "attacker-owned s3 bucket",
			registered: "https://*.s3.amazonaws.com/callback",
			candidate:  "https://attacker-bucket.s3.amazonaws.com/callback",
		},
		{
			name:       "attacker-owned azure storage account",
			registered: "https://*.blob.core.windows.net/callback",
			candidate:  "https://attacker.blob.core.windows.net/callback",
		},
		{
			name:       "attacker-owned github pages site",
			registered: "https://*.github.io/callback",
			candidate:  "https://attacker.github.io/callback",
		},
		{
			name:       "trailing-dot wildcard over a purchasable domain",
			registered: "https://*.evil.com./callback",
			candidate:  "https://x.evil.com./callback",
		},
		{
			name:       "wildcard over a bare TLD",
			registered: "https://*.run/callback",
			candidate:  "https://anything.run/callback",
		},
		{
			name:       "wildcard over a registrable domain",
			registered: "https://*.evil.com/callback",
			candidate:  "https://x.evil.com/callback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if Allowed([]string{tt.registered}, tt.candidate) {
				t.Errorf("Allowed(%q, %q) = true, want false: an over-broad wildcard must not match at request time",
					tt.registered, tt.candidate)
			}
		})
	}
}

func TestAllowed(t *testing.T) {
	exact := "https://staging.footstrike.run/auth/callback"
	wild := "https://*.preview.footstrike.run/auth/callback"

	tests := []struct {
		name       string
		registered []string
		candidate  string
		want       bool
	}{
		{"exact match", []string{exact}, exact, true},
		{"unregistered candidate rejected", []string{exact}, "https://evil.example.com/auth/callback", false},
		{"wildcard matches single label", []string{wild}, "https://hae-cadence.preview.footstrike.run/auth/callback", true},
		{"wildcard alongside exact entries", []string{exact, wild}, "https://api-x.preview.footstrike.run/auth/callback", true},
		{"wildcard rejects multi-label", []string{wild}, "https://a.b.preview.footstrike.run/auth/callback", false},
		{"wildcard rejects bare suffix", []string{wild}, "https://preview.footstrike.run/auth/callback", false},
		{"wildcard rejects empty label", []string{wild}, "https://.preview.footstrike.run/auth/callback", false},
		{"wildcard rejects cousin domain", []string{wild}, "https://xpreview.footstrike.run/auth/callback", false},
		{"wildcard rejects wrong path", []string{wild}, "https://x.preview.footstrike.run/other", false},
		{"wildcard rejects http candidate", []string{wild}, "http://x.preview.footstrike.run/auth/callback", false},
		{"http wildcard entry matches nothing", []string{"http://*.preview.footstrike.run/auth/callback"}, "http://x.preview.footstrike.run/auth/callback", false},
		{"wildcard rejects query string", []string{wild}, "https://x.preview.footstrike.run/auth/callback?a=b", false},
		{"wildcard rejects fragment", []string{wild}, "https://x.preview.footstrike.run/auth/callback#f", false},
		{"wildcard rejects explicit port mismatch", []string{wild}, "https://x.preview.footstrike.run:8443/auth/callback", false},
		{"host match is case-insensitive", []string{wild}, "https://X.Preview.Footstrike.Run/auth/callback", true},
		{"mid-label wildcard entry matches nothing", []string{"https://api-*.preview.footstrike.run/auth/callback"}, "https://api-x.preview.footstrike.run/auth/callback", false},
		{"literal wildcard candidate passes only via the exact branch", []string{wild}, wild, true},
		{"empty registered list rejects", nil, exact, false},
		{"wildcard rejects fullwidth-dot host", []string{wild}, "https://a．b.preview.footstrike.run/auth/callback", false},
		{"wildcard rejects Kelvin-sign host", []string{wild}, "https://evil.preview.footstriKe.run/auth/callback", false},
		{"wildcard rejects userinfo candidate", []string{wild}, "https://evil.com@x.preview.footstrike.run/auth/callback", false},
		{"wildcard rejects percent-encoded path", []string{wild}, "https://x.preview.footstrike.run/auth%2Fcallback", false},
		{"wildcard rejects trailing-dot FQDN candidate", []string{wild}, "https://x.preview.footstrike.run./auth/callback", false},
		{"wildcard rejects explicit port vs portless pattern", []string{wild}, "https://x.preview.footstrike.run:443/auth/callback", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Allowed(tt.registered, tt.candidate); got != tt.want {
				t.Errorf("Allowed(%v, %q) = %v, want %v", tt.registered, tt.candidate, got, tt.want)
			}
		})
	}
}

// TestValidateWildcardPattern_AgreesWithAllowed asserts the property the split
// into this package exists to guarantee: a pattern the validator refuses can
// never match anything at request time. Drift between the two is the bug class
// that produced the original finding.
func TestValidateWildcardPattern_AgreesWithAllowed(t *testing.T) {
	patterns := []string{
		previewPattern,
		"https://*.s3.amazonaws.com/callback",
		"https://*.evil.com./callback",
		"https://*.evil.com/callback",
		"https://*.run/callback",
		"https://*.github.io/callback",
		"https://api-*.preview.footstrike.run/cb",
		"http://*.preview.footstrike.run/cb",
	}
	// For each pattern, a candidate built by substituting a single label.
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			candidate := strings.Replace(pattern, "*", "probe", 1)
			cand, err := url.Parse(candidate)
			if err != nil {
				t.Fatalf("could not parse candidate %q: %v", candidate, err)
			}
			invalid := ValidateWildcardPattern(pattern) != nil
			matched := wildcardMatch(pattern, cand)
			if invalid && matched {
				t.Errorf("pattern %q is rejected by ValidateWildcardPattern but still matched %q",
					pattern, candidate)
			}
		})
	}
}
