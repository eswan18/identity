package auth

import (
	"slices"
	"testing"
)

func TestIsAlwaysGrantableScope(t *testing.T) {
	tests := []struct {
		scope string
		want  bool
	}{
		{"offline_access", true},
		// The disclosing scopes stay gated by allowed_scopes.
		{"openid", false},
		{"profile", false},
		{"email", false},
		{"admin:users:read", false},
		{"", false},
		{"OFFLINE_ACCESS", false},
	}
	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			if got := IsAlwaysGrantableScope(tt.scope); got != tt.want {
				t.Errorf("IsAlwaysGrantableScope(%q) = %v, want %v", tt.scope, got, tt.want)
			}
		})
	}
}

// Every always-grantable scope must be one of identity's own scopes, and none
// may be an admin scope: admin authority belongs to the client, never to a
// user-delegated grant.
func TestAlwaysGrantableScopesAreIdentityScopes(t *testing.T) {
	for _, s := range alwaysGrantableScopes {
		if !slices.Contains(IdentityScopes, s) {
			t.Errorf("always-grantable scope %q is not in IdentityScopes", s)
		}
		if IsAdminScope(s) {
			t.Errorf("always-grantable scope %q is an admin scope", s)
		}
	}
}
