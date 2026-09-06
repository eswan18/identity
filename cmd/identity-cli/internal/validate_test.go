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

func TestValidateAdminScopes(t *testing.T) {
	cases := []struct {
		name           string
		scopes         []string
		isConfidential bool
		wantErr        bool
	}{
		{"public client with no admin scopes", []string{"openid", "profile"}, false, false},
		{"confidential client with admin scopes", []string{"admin:users:write"}, true, false},
		{"confidential client without admin scopes", []string{"openid"}, true, false},
		{"public client with admin write rejected", []string{"openid", "admin:users:write"}, false, true},
		{"public client with admin read rejected", []string{"admin:users:read"}, false, true},
		{"public client with a future admin scope rejected", []string{"admin:clients:write"}, false, true},
		{"public client with a scope named admin is fine", []string{"admin"}, false, false},
		{"no scopes", nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAdminScopes(tc.scopes, tc.isConfidential)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateAdminScopes(%v, %v) error = %v, wantErr %v",
					tc.scopes, tc.isConfidential, err, tc.wantErr)
			}
		})
	}
}
