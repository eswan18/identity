package httpserver

import (
	"strings"
	"testing"

	"github.com/eswan18/identity/pkg/db"
)

// TestValidateAuthorizeParams exercises the shared validation used by both the
// authorize and consent endpoints. The consent endpoint previously skipped these
// checks, allowing a direct POST to /oauth/consent to obtain a PKCE-less
// authorization code with arbitrary scopes. These cases assert that consent and
// authorize now enforce identical rules.
func TestValidateAuthorizeParams(t *testing.T) {
	allowed := []string{"openid", "profile", "email"}

	tests := []struct {
		name                string
		responseType        string
		codeChallenge       string
		codeChallengeMethod string
		scope               []string
		wantErrCode         string // "" means expect no error
	}{
		{
			name:                "valid request",
			responseType:        "code",
			codeChallenge:       "abc123",
			codeChallengeMethod: "S256",
			scope:               []string{"openid", "profile"},
			wantErrCode:         "",
		},
		{
			name:                "unsupported response type",
			responseType:        "token",
			codeChallenge:       "abc123",
			codeChallengeMethod: "S256",
			scope:               []string{"openid"},
			wantErrCode:         "unsupported_response_type",
		},
		{
			name:                "missing code challenge (PKCE required)",
			responseType:        "code",
			codeChallenge:       "",
			codeChallengeMethod: "",
			scope:               []string{"openid"},
			wantErrCode:         "invalid_request",
		},
		{
			name:                "missing code challenge method",
			responseType:        "code",
			codeChallenge:       "abc123",
			codeChallengeMethod: "",
			scope:               []string{"openid"},
			wantErrCode:         "invalid_request",
		},
		{
			name:                "non-S256 challenge method rejected",
			responseType:        "code",
			codeChallenge:       "abc123",
			codeChallengeMethod: "plain",
			scope:               []string{"openid"},
			wantErrCode:         "invalid_request",
		},
		{
			name:                "scope not allowed for client",
			responseType:        "code",
			codeChallenge:       "abc123",
			codeChallengeMethod: "S256",
			scope:               []string{"openid", "admin"},
			wantErrCode:         "invalid_scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := db.OauthClient{AllowedScopes: allowed}
			got := validateAuthorizeParams(client, tt.responseType, tt.codeChallenge, tt.codeChallengeMethod, tt.scope)
			if tt.wantErrCode == "" {
				if got != nil {
					t.Fatalf("expected no error, got %q (%s)", got.Code, got.Description)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected error %q, got nil", tt.wantErrCode)
			}
			if got.Code != tt.wantErrCode {
				t.Errorf("expected error code %q, got %q (%s)", tt.wantErrCode, got.Code, got.Description)
			}
		})
	}
}

// TestValidateAuthorizeParams_RejectsAdminScopes covers the rule that admin
// scopes may only be obtained through the client_credentials grant.
//
// The cases where the client *does* list an admin scope in allowed_scopes are
// the point: before this rule, that registration made the authorization-code
// flow a second way to obtain admin authority, and for a public client a user
// could redeem the code themselves with no secret at all.
func TestValidateAuthorizeParams_RejectsAdminScopes(t *testing.T) {
	tests := []struct {
		name          string
		allowedScopes []string
		scope         []string
		wantErrCode   string
		wantErrDesc   string
	}{
		{
			name:          "admin scope refused even when the client is allowed it",
			allowedScopes: []string{"openid", "admin:users:write"},
			scope:         []string{"openid", "admin:users:write"},
			wantErrCode:   "invalid_scope",
			wantErrDesc:   "client_credentials",
		},
		{
			name:          "admin read scope refused",
			allowedScopes: []string{"openid", "admin:users:read"},
			scope:         []string{"admin:users:read"},
			wantErrCode:   "invalid_scope",
			wantErrDesc:   "client_credentials",
		},
		{
			name:          "future admin scope refused by prefix",
			allowedScopes: []string{"openid", "admin:clients:write"},
			scope:         []string{"admin:clients:write"},
			wantErrCode:   "invalid_scope",
			wantErrDesc:   "client_credentials",
		},
		{
			// Ordering: a client that was never granted the scope should be told
			// that, which is the more accurate answer.
			name:          "client without the scope gets the not-allowed error",
			allowedScopes: []string{"openid"},
			scope:         []string{"admin:users:write"},
			wantErrCode:   "invalid_scope",
			wantErrDesc:   "not allowed for this client",
		},
		{
			name:          "non-admin scopes still pass for an admin-capable client",
			allowedScopes: []string{"openid", "profile", "admin:users:write"},
			scope:         []string{"openid", "profile"},
			wantErrCode:   "",
		},
		{
			// "admin" is not "admin:" — it grants nothing, since the routes
			// require the full scope string. Pin the prefix semantics so the rule
			// is not quietly widened into a substring match.
			name:          "scope named admin without a colon is not an admin scope",
			allowedScopes: []string{"openid", "admin"},
			scope:         []string{"admin"},
			wantErrCode:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := db.OauthClient{AllowedScopes: tt.allowedScopes}
			got := validateAuthorizeParams(client, "code", "abc123", "S256", tt.scope)
			if tt.wantErrCode == "" {
				if got != nil {
					t.Fatalf("expected no error, got %q (%s)", got.Code, got.Description)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected error %q, got nil", tt.wantErrCode)
			}
			if got.Code != tt.wantErrCode {
				t.Errorf("expected error code %q, got %q (%s)", tt.wantErrCode, got.Code, got.Description)
			}
			if !strings.Contains(got.Description, tt.wantErrDesc) {
				t.Errorf("expected description to mention %q, got %q", tt.wantErrDesc, got.Description)
			}
		})
	}
}
