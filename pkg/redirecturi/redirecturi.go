// Package redirecturi implements OAuth redirect_uri matching, including the
// wildcard form used by preview environments.
//
// It exists as its own package because the same rules have to hold in two
// places that used to hold them independently:
//
//   - identity-cli, which validates a wildcard entry when an operator registers
//     a client (cmd/identity-cli/internal/validate.go), and
//   - the authorize/consent request path, which decides whether an incoming
//     redirect_uri is allowed (pkg/httpserver/redirect_match.go).
//
// Keeping two copies let them drift: the CLI grew a breadth guard on how wide a
// wildcard may be, and the request path never had one at all. The CLI is not on
// the request path, so any row that reached oauth_clients.redirect_uris by some
// other route -- a hand-written INSERT, a restored backup, a row predating the
// guard -- was matched unconditionally. ValidateWildcardPattern is now the
// single definition of a well-formed wildcard entry, and Allowed refuses to
// match any pattern that fails it, so the guard binds at request time rather
// than only at registration.
package redirecturi

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Allowed reports whether candidate is permitted by a client's registered
// redirect URIs.
//
// An entry allows the candidate if it matches byte-for-byte, or if the entry is
// a valid wildcard pattern (see ValidateWildcardPattern) whose "*" is replaced
// by exactly one non-empty DNS label in the candidate. Wildcard entries match
// https candidates only, require identical path and port, and refuse candidates
// carrying a query string, fragment, or userinfo. The pattern's path must equal
// the candidate's path exactly, so register the pattern with the full callback
// path.
func Allowed(registered []string, candidate string) bool {
	if slices.Contains(registered, candidate) {
		return true
	}
	cand, err := url.Parse(candidate)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(registered, func(entry string) bool {
		return wildcardMatch(entry, cand)
	})
}

// wildcardMatch reports whether entry is a valid wildcard pattern that matches
// cand.
//
// The ValidateWildcardPattern call is the load-bearing line: a pattern that
// would be refused at registration can never match here either, so a
// too-broad entry that reached the database by some path other than the CLI
// is inert rather than honoured.
func wildcardMatch(entry string, cand *url.URL) bool {
	if ValidateWildcardPattern(entry) != nil {
		return false
	}
	pat, err := url.Parse(entry)
	if err != nil {
		return false
	}
	if cand.Scheme != "https" || cand.User != nil {
		return false
	}
	if cand.EscapedPath() != pat.EscapedPath() || cand.Port() != pat.Port() {
		return false
	}
	if cand.RawQuery != "" || cand.Fragment != "" {
		return false
	}
	// The pattern's suffix is already known-good ASCII (ValidateWildcardPattern
	// checked it), but the candidate host is attacker-supplied and still has to
	// clear asciiLowerHost before any comparison.
	patSuffix, ok := asciiLowerHost(strings.TrimPrefix(pat.Hostname(), "*."))
	if !ok {
		return false
	}
	candHost, ok := asciiLowerHost(cand.Hostname())
	if !ok {
		return false
	}
	label, ok := strings.CutSuffix(candHost, "."+patSuffix)
	return ok && label != "" && !strings.ContainsAny(label, ".*")
}

// ValidateWildcardPattern reports whether entry is a well-formed wildcard
// redirect URI. It returns nil for a valid pattern and a descriptive error
// otherwise, so identity-cli can tell an operator exactly what is wrong.
//
// Entries containing no "*" are not wildcard patterns and are rejected here;
// callers that accept both forms (see Allowed, and ValidateRedirectURIs in
// identity-cli) check for "*" before calling.
func ValidateWildcardPattern(entry string) error {
	if strings.Count(entry, "*") != 1 {
		return fmt.Errorf("redirect URI %q: a wildcard entry must contain exactly one %q", entry, "*")
	}
	u, err := url.Parse(entry)
	if err != nil {
		return fmt.Errorf("redirect URI %q: %w", entry, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("redirect URI %q: wildcard entries must be https", entry)
	}
	if u.User != nil {
		return fmt.Errorf("redirect URI %q: wildcard entries must not carry userinfo", entry)
	}
	suffix, ok := strings.CutPrefix(u.Hostname(), "*.")
	if !ok || strings.Contains(suffix, "*") {
		return fmt.Errorf("redirect URI %q: wildcard must be the entire leftmost host label (%q)", entry, "*.suffix")
	}
	if u.Path == "" || u.Path == "/" {
		return fmt.Errorf("redirect URI %q: wildcard entries must include the full callback path", entry)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("redirect URI %q: wildcard entries must not carry a query or fragment", entry)
	}
	return validateWildcardSuffix(entry, suffix)
}

// validateWildcardSuffix enforces how wide a wildcard is allowed to be.
//
// The rule is that the suffix must sit strictly below its registrable domain
// (its eTLD+1, per the Public Suffix List). That rejects two distinct classes
// of over-broad entry that the previous "at least two dots" heuristic let
// through:
//
//   - Suffixes that are themselves public suffixes -- "s3.amazonaws.com",
//     "blob.core.windows.net", "github.io", "pages.dev". These have two or more
//     dots, so the old heuristic accepted them, but anyone can create a bucket
//     or storage account or user site and thereby own a host matching the
//     wildcard. publicsuffix.EffectiveTLDPlusOne cannot derive an eTLD+1 for
//     them at all, which is exactly the signal we want.
//   - Bare registrable domains -- "evil.com". A wildcard over the whole of a
//     domain an attacker can simply buy is not a bounded preview namespace.
//
// It also closes the trailing-dot bypass. "evil.com." contains two dots, so it
// satisfied the old heuristic while denoting the same name as "evil.com", which
// the heuristic rejected; the root label is stripped before the lookup here so
// the two spellings get the identical answer.
//
// Residual risk worth naming: the Public Suffix List is a compiled-in snapshot
// and is not exhaustive. A domain that hands out subdomains to the public but
// has not registered itself on the list would still pass. The list is the best
// available signal, not a proof, so keep wildcard registrations rare and
// reviewed -- see the follow-up note in the PR description about pinning an
// explicit operator allowlist on top of this.
func validateWildcardSuffix(entry, suffix string) error {
	// Strip a single trailing dot (the DNS root label) so that "evil.com." and
	// "evil.com" are judged identically rather than differing by one character.
	normalized := strings.TrimSuffix(suffix, ".")
	if normalized == "" {
		return fmt.Errorf("redirect URI %q: wildcard entries must have a host suffix after %q", entry, "*.")
	}
	if strings.HasSuffix(normalized, ".") {
		// More than one trailing dot is not a name at all.
		return fmt.Errorf("redirect URI %q: wildcard suffix %q is not a valid host", entry, suffix)
	}
	// Reject non-ASCII, uppercase-folding and confusable characters in the
	// pattern itself, so a registered entry can never rely on Unicode folding to
	// widen what it matches.
	folded, ok := asciiLowerHost(normalized)
	if !ok {
		return fmt.Errorf("redirect URI %q: wildcard suffix %q must be an ASCII host", entry, suffix)
	}
	if strings.HasPrefix(folded, ".") || strings.Contains(folded, "..") {
		return fmt.Errorf("redirect URI %q: wildcard suffix %q is not a valid host", entry, suffix)
	}

	registrable, err := publicsuffix.EffectiveTLDPlusOne(folded)
	if err != nil {
		// No eTLD+1 exists, which means folded is itself a public suffix
		// ("s3.amazonaws.com", "run", "co.uk") -- the broadest possible wildcard.
		return fmt.Errorf(
			"redirect URI %q: wildcard suffix %q is a public suffix; anyone can register a host under it",
			entry, suffix)
	}
	if folded == registrable {
		return fmt.Errorf(
			"redirect URI %q: wildcard suffix %q is a registrable domain; use a dedicated subdomain such as %q",
			entry, suffix, "preview."+folded)
	}
	return nil
}

// asciiLowerHost ASCII-lowercases host (A-Z to a-z only, no Unicode case
// folding) and reports ok=false if the result contains any byte outside
// [a-z0-9.-]. This rejects hosts that rely on Unicode folding or confusable
// characters to defeat the single-label check in wildcardMatch -- for example
// U+212A KELVIN SIGN, which strings.ToLower folds to "k", or U+FF0E FULLWIDTH
// FULL STOP, which browsers' UTS-46 host mapping treats as "." but which would
// otherwise pass the ASCII-only dot/label scan unnoticed.
func asciiLowerHost(host string) (folded string, ok bool) {
	b := make([]byte, len(host))
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return "", false
		}
		b[i] = c
	}
	return string(b), true
}
