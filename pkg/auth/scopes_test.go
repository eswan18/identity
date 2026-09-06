package auth

import (
	"reflect"
	"testing"
)

func TestIsAdminScope(t *testing.T) {
	tests := []struct {
		scope string
		want  bool
	}{
		{"admin:users:read", true},
		{"admin:users:write", true},
		{"admin:clients:write", true}, // a scope that does not exist yet
		{"admin:", true},
		{"openid", false},
		{"profile", false},
		{"email", false},
		// "admin" is not "admin:". The /admin routes require the full scope
		// string, so a scope literally named "admin" grants nothing, and the rule
		// must not widen into a substring match.
		{"admin", false},
		{"administration", false},
		{"not-admin:users:read", false},
		{"openid admin:users:read", false}, // a single scope, not a list
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			if got := IsAdminScope(tt.scope); got != tt.want {
				t.Errorf("IsAdminScope(%q) = %v, want %v", tt.scope, got, tt.want)
			}
		})
	}
}

func TestAdminScopesIn(t *testing.T) {
	tests := []struct {
		name   string
		scopes []string
		want   []string
	}{
		{"none", []string{"openid", "profile", "email"}, nil},
		{"empty", nil, nil},
		{"one", []string{"openid", "admin:users:read"}, []string{"admin:users:read"}},
		{
			"several preserve order",
			[]string{"admin:users:write", "openid", "admin:users:read"},
			[]string{"admin:users:write", "admin:users:read"},
		},
		{"lookalikes excluded", []string{"admin", "administration", "openid"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AdminScopesIn(tt.scopes); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AdminScopesIn(%v) = %v, want %v", tt.scopes, got, tt.want)
			}
		})
	}
}
