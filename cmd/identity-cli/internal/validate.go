package internal

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateRedirectURIs rejects malformed wildcard redirect entries before
// they reach the database. Only entries containing "*" are validated —
// non-wildcard URIs (including localhost/http dev entries) pass through
// untouched, matching the server's runtime behavior where exact-match
// entries are compared byte-for-byte. The rules mirror
// pkg/httpserver/redirect_match.go: https only, "*." as the entire leftmost
// label, a real path, no query/fragment — plus a breadth guard: the suffix
// after "*." must contain at least two dots (e.g. preview.footstrike.run),
// so an operator can't accidentally register https://*.run/....
func ValidateRedirectURIs(uris []string) error {
	for _, raw := range uris {
		if !strings.Contains(raw, "*") {
			continue
		}
		if strings.Count(raw, "*") != 1 {
			return fmt.Errorf("redirect URI %q: multiple wildcards", raw)
		}
		u, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("redirect URI %q: %w", raw, err)
		}
		if u.Scheme != "https" {
			return fmt.Errorf("redirect URI %q: wildcard entries must be https", raw)
		}
		suffix, ok := strings.CutPrefix(u.Host, "*.")
		if !ok || strings.Contains(suffix, "*") {
			return fmt.Errorf("redirect URI %q: wildcard must be the entire leftmost host label (\"*.suffix\")", raw)
		}
		if strings.Count(suffix, ".") < 2 {
			return fmt.Errorf("redirect URI %q: wildcard suffix %q too broad — needs at least two dots", raw, suffix)
		}
		if u.Path == "" || u.Path == "/" {
			return fmt.Errorf("redirect URI %q: wildcard entries must include the full callback path", raw)
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("redirect URI %q: wildcard entries must not carry a query or fragment", raw)
		}
	}
	return nil
}
