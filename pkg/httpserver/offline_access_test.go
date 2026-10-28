package httpserver

import (
	"testing"

	"github.com/eswan18/identity/pkg/db"
)

// offline_access is identity's own scope and grantable to any client on the
// code flow, whatever its allowed_scopes say. Nothing else gets that pass.
func TestValidateAuthorizeParams_OfflineAccess(t *testing.T) {
	client := db.OauthClient{AllowedScopes: []string{"openid", "profile"}}

	tests := []struct {
		name        string
		scope       []string
		wantErrCode string
	}{
		{"offline_access without registration", []string{"openid", "offline_access"}, ""},
		{"offline_access alone", []string{"offline_access"}, ""},
		{"other unregistered scopes are still refused", []string{"openid", "offline_access", "email"}, "invalid_scope"},
		{"admin scopes are still refused", []string{"offline_access", "admin:users:read"}, "invalid_scope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope := append([]string(nil), tt.scope...)
			err := validateAuthorizeParams(client, "code", "challenge", "S256", scope)
			got := ""
			if err != nil {
				got = err.Code
			}
			if got != tt.wantErrCode {
				t.Errorf("error code = %q, want %q (err: %+v)", got, tt.wantErrCode, err)
			}
			// The caller's slice is the scope that gets stored on the code; the
			// check must not have filtered offline_access out of it.
			for i := range tt.scope {
				if scope[i] != tt.scope[i] {
					t.Fatalf("validateAuthorizeParams modified the scope slice: %v, want %v", scope, tt.scope)
				}
			}
		})
	}

	// An admin scope on a client that is registered for it is refused for the
	// code flow, with or without offline_access beside it.
	admin := db.OauthClient{AllowedScopes: []string{"openid", "admin:users:read"}}
	if err := validateAuthorizeParams(admin, "code", "challenge", "S256", []string{"openid", "offline_access", "admin:users:read"}); err == nil || err.Code != "invalid_scope" {
		t.Errorf("admin scope on the code flow: got %+v, want invalid_scope", err)
	}
}

func TestOfflineAccessHasAConsentDescription(t *testing.T) {
	desc, ok := scopeDescriptionMap["offline_access"]
	if !ok || desc == "" || desc == "offline_access" {
		t.Fatalf("offline_access has no plain-language consent description: %q", desc)
	}
}
