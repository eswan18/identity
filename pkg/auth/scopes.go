package auth

import (
	"slices"
	"strings"
)

// AdminScopePrefix marks scopes that grant access to the /admin API. The prefix
// is matched rather than an explicit list so a future admin scope
// ("admin:clients:write", say) is covered the moment it is introduced, instead
// of silently escaping a rule that enumerated only today's scopes.
const AdminScopePrefix = "admin:"

// IsAdminScope reports whether scope grants /admin API access.
func IsAdminScope(scope string) bool {
	return strings.HasPrefix(scope, AdminScopePrefix)
}

// AdminScopesIn returns the admin scopes present in scopes, in order, or nil if
// there are none. Callers use the returned slice to name the offending scopes
// in an error rather than just reporting that one was present.
func AdminScopesIn(scopes []string) []string {
	var found []string
	for _, scope := range scopes {
		if IsAdminScope(scope) {
			found = append(found, scope)
		}
	}
	return found
}

// IsIdentityScope reports whether scope is one identity defines for itself:
// one of IdentityScopes, or an admin scope. A resource in the registry may not
// define a scope with such a name, so a scope string always means one thing.
func IsIdentityScope(scope string) bool {
	return IsAdminScope(scope) || slices.Contains(IdentityScopes, scope)
}
