package httpserver

import (
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
