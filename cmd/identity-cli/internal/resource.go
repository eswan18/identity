package internal

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
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

// ParseScopes decodes an oauth_resources.scopes column.
func ParseScopes(raw json.RawMessage) (map[string]string, error) {
	scopes := map[string]string{}
	if err := json.Unmarshal(raw, &scopes); err != nil {
		return nil, fmt.Errorf("unreadable scopes column: %w", err)
	}
	return scopes, nil
}

// MergeScopes returns current with each of additions added, or its
// description replaced if current already has it. Neither input is modified.
func MergeScopes(current, additions map[string]string) map[string]string {
	merged := make(map[string]string, len(current)+len(additions))
	for name, description := range current {
		merged[name] = description
	}
	for name, description := range additions {
		merged[name] = description
	}
	return merged
}

// RemoveScopes returns current without the named scopes, and the names it did
// not have. As with redirect URIs (RemoveValues), callers treat a non-empty
// notFound as an error, so a typo can't look like a successful removal.
// current is not modified.
func RemoveScopes(current map[string]string, names []string) (result map[string]string, notFound []string) {
	result = make(map[string]string, len(current))
	for name, description := range current {
		result[name] = description
	}
	for _, name := range names {
		if _, ok := current[name]; !ok {
			if !slices.Contains(notFound, name) {
				notFound = append(notFound, name)
			}
			continue
		}
		delete(result, name)
	}
	return result, notFound
}

// ScopesJSON encodes a scope map for the oauth_resources.scopes column.
func ScopesJSON(scopes map[string]string) (json.RawMessage, error) {
	if scopes == nil {
		scopes = map[string]string{}
	}
	return json.Marshal(scopes)
}
