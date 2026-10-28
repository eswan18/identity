package internal

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/eswan18/identity/pkg/auth"
)

// ParseResourceScopes turns repeated --scope "name=description" flags into the
// {scope: description} map an oauth_resources row stores. The description is
// what the consent screen will show for the scope, so both halves are required.
// A name may not contain whitespace (scopes are space-separated on the wire),
// may not be given twice, and may not be one of identity's own scopes (openid,
// profile, email, offline_access, admin:*), so a scope string always means one
// thing.
func ParseResourceScopes(flags []string) (map[string]string, error) {
	scopes := make(map[string]string, len(flags))
	for _, flag := range flags {
		name, description, ok := strings.Cut(flag, "=")
		name = strings.TrimSpace(name)
		description = strings.TrimSpace(description)
		if !ok || name == "" || description == "" {
			return nil, fmt.Errorf("--scope %q: want name=description, both non-empty", flag)
		}
		if strings.ContainsAny(name, " \t\r\n") {
			return nil, fmt.Errorf("--scope %q: a scope name cannot contain whitespace", flag)
		}
		if auth.IsIdentityScope(name) {
			return nil, fmt.Errorf("--scope %q: %s is one of identity's own scopes and cannot belong to a resource", flag, name)
		}
		if _, dup := scopes[name]; dup {
			return nil, fmt.Errorf("--scope %q: scope %s given twice", flag, name)
		}
		scopes[name] = description
	}
	return scopes, nil
}

// DefaultResourceValue renders a client's default resource for display.
func DefaultResourceValue(defaultResource sql.NullString) string {
	if !defaultResource.Valid {
		return "(none: tokens are for identity itself)"
	}
	return defaultResource.String
}

// ScopesJSON encodes a scope map for the oauth_resources.scopes column.
func ScopesJSON(scopes map[string]string) (json.RawMessage, error) {
	if scopes == nil {
		scopes = map[string]string{}
	}
	return json.Marshal(scopes)
}
