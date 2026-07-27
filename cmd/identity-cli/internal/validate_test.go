package internal

import "testing"

func TestValidateRedirectURIs(t *testing.T) {
	cases := []struct {
		name    string
		uris    []string
		wantErr bool
	}{
		{"non-wildcard URIs pass untouched", []string{"http://localhost:5173/oauth/callback", "https://footstrike.run/oauth/callback", "not-even-a-url"}, false},
		{"valid preview wildcard", []string{"https://*.preview.footstrike.run/oauth/callback"}, false},
		{"wildcard suffix too broad (one dot)", []string{"https://*.run/oauth/callback"}, true},
		{"wildcard must be whole leftmost label", []string{"https://api-*.preview.footstrike.run/oauth/callback"}, true},
		{"two wildcards rejected", []string{"https://*.*.footstrike.run/oauth/callback"}, true},
		{"http wildcard rejected", []string{"http://*.preview.footstrike.run/oauth/callback"}, true},
		{"wildcard without path rejected", []string{"https://*.preview.footstrike.run"}, true},
		{"wildcard with query rejected", []string{"https://*.preview.footstrike.run/cb?x=1"}, true},
		{"wildcard with fragment rejected", []string{"https://*.preview.footstrike.run/cb#f"}, true},
		{"mixed list validates only wildcards", []string{"https://staging.footstrike.run/oauth/callback", "https://*.preview.footstrike.run/oauth/callback"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRedirectURIs(tc.uris)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateRedirectURIs(%v) error = %v, wantErr %v", tc.uris, err, tc.wantErr)
			}
		})
	}
}
