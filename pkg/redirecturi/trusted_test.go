package redirecturi

import "testing"

func TestUnsafeForTrustedClient(t *testing.T) {
	for _, tc := range []struct {
		uri    string
		unsafe bool
	}{
		{"https://app.footstrike.run/auth/callback", false},
		{"https://staging.footstrike.run/auth/callback", false},
		{"footstrike://oauth/callback", false},
		{"https://10.0.0.5/cb", false},
		{"https://*.preview.footstrike.run/auth/callback", true},
		{"https://bad*.example.com/cb", true},
		{"http://localhost/callback", true},
		{"http://localhost:5173/oauth/callback", true},
		{"https://LOCALHOST./cb", true},
		{"https://app.localhost/cb", true},
		{"http://127.0.0.1:8080/cb", true},
		{"http://127.5.6.7/cb", true},
		{"http://[::1]:3000/cb", true},
		{"http://[::ffff:127.0.0.1]/cb", true},
		{"http://0.0.0.0/cb", true},
		{"http://127.1/cb", true},
		{"http://0x7f.1/cb", true},
		{"http://2130706433/cb", true},
		{"://not a url", true},
	} {
		got := UnsafeForTrustedClient(tc.uri)
		if (got != "") != tc.unsafe {
			t.Errorf("UnsafeForTrustedClient(%q) = %q, want unsafe=%v", tc.uri, got, tc.unsafe)
		}
	}
}
