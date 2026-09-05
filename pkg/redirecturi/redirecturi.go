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
	// Exact match, except for a wildcard entry that fails validation.
	//
	// Without that exception the guarantee this package is built on -- an entry
	// refused at registration is inert -- would be false for exactly one
	// candidate: the pattern's own text. That is not purely theoretical. "*" is
	// not a forbidden host code point, and RFC 4592 §2.2 means a DNS query for
	// the literal name "*.evil.com" is answered by the attacker's own wildcard
	// record, so an over-broad entry could still be honoured for that one input.
	//
	// A *valid* pattern is deliberately left able to match itself, preserving
	// long-standing behaviour: its suffix is one the operator controls, so the
	// candidate is not attacker-reachable, and narrowing the exception keeps
	// this change confined to the defect it fixes.
	for _, entry := range registered {
		if entry != candidate {
			continue
		}
		if isWildcardEntry(entry) && ValidateWildcardPattern(entry) != nil {
			continue
		}
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

// InvalidWildcardEntries returns one error per registered entry that looks like
// a wildcard pattern but fails validation, and so can never match anything.
//
// Because the guard now binds at request time, an entry that was registered
// before the rules tightened is refused rather than honoured -- which, from the
// outside, is indistinguishable from a redirect_uri that simply did not match.
// Callers use this to say which entry is unusable and why, so a preview
// environment that stopped working is diagnosable from the logs alone.
func InvalidWildcardEntries(registered []string) []error {
	var errs []error
	for _, entry := range registered {
		if !isWildcardEntry(entry) {
			continue
		}
		if err := ValidateWildcardPattern(entry); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// isWildcardEntry reports whether entry is intended as a wildcard pattern.
// Anything containing "*" is, whether or not it is well-formed -- a malformed
// pattern must be refused, not silently reinterpreted as a literal URI.
func isWildcardEntry(entry string) bool {
	return strings.Contains(entry, "*")
}

// wildcardMatch reports whether entry is a valid wildcard pattern that matches
// cand.
//
// The ValidateWildcardPattern call is the load-bearing line: a pattern that
// would be refused at registration can never match here either, so a
// too-broad entry that reached the database by some path other than the CLI
// is inert rather than honoured.
func wildcardMatch(entry string, cand *url.URL) bool {
	// Entries that are not patterns were already handled by the exact branch in
	// Allowed. Returning early keeps the common case (a client whose redirect
	// URIs are all literal) off the parse-and-validate path entirely.
	if !isWildcardEntry(entry) {
		return false
	}
	// parseWildcardPattern is the load-bearing call: a pattern that would be
	// refused at registration can never match here either, so a too-broad entry
	// that reached the database by some path other than the CLI is inert rather
	// than honoured. It returns the parsed URL and folded suffix so neither is
	// computed twice.
	pat, patSuffix, err := parseWildcardPattern(entry)
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
	// patSuffix is already known-good ASCII, but the candidate host is
	// attacker-supplied and still has to clear asciiLowerHost before comparison.
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
	_, _, err := parseWildcardPattern(entry)
	return err
}

// parseWildcardPattern validates entry and returns the parsed URL alongside the
// ASCII-folded host suffix (the part after "*."). ValidateWildcardPattern and
// wildcardMatch share it so a pattern is parsed and judged exactly once per
// call, and so the two can never apply different rules.
func parseWildcardPattern(entry string) (*url.URL, string, error) {
	if strings.Count(entry, "*") != 1 {
		return nil, "", fmt.Errorf("redirect URI %q: a wildcard entry must contain exactly one %q", entry, "*")
	}
	u, err := url.Parse(entry)
	if err != nil {
		return nil, "", fmt.Errorf("redirect URI %q: %w", entry, err)
	}
	if u.Scheme != "https" {
		return nil, "", fmt.Errorf("redirect URI %q: wildcard entries must be https", entry)
	}
	if u.User != nil {
		return nil, "", fmt.Errorf("redirect URI %q: wildcard entries must not carry userinfo", entry)
	}
	suffix, ok := strings.CutPrefix(u.Hostname(), "*.")
	if !ok || strings.Contains(suffix, "*") {
		return nil, "", fmt.Errorf("redirect URI %q: wildcard must be the entire leftmost host label (%q)", entry, "*.suffix")
	}
	if u.Path == "" || u.Path == "/" {
		return nil, "", fmt.Errorf("redirect URI %q: wildcard entries must include the full callback path", entry)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, "", fmt.Errorf("redirect URI %q: wildcard entries must not carry a query or fragment", entry)
	}
	folded, err := validateWildcardSuffix(entry, suffix)
	if err != nil {
		return nil, "", err
	}
	return u, folded, nil
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
// Residual risk, stated precisely, because this check is easy to overtrust:
//
// The Public Suffix List is a compiled-in snapshot and is not exhaustive. It
// only knows about namespaces whose operators submitted them. A provider that
// hands out subdomains to the public without a PSL entry passes every check
// here. "s3.amazonaws.com" is rejected because Amazon submitted an entry;
// "s3.wasabisys.com" is accepted, and Wasabi buckets are the same sentence.
// The snapshot is also only as fresh as the pinned golang.org/x/net, so a
// namespace listed after that release is invisible until the dependency moves.
//
// The list also cuts the other way. Tailscale registered "ts.net", which makes
// this fleet's own "tailc06f30.ts.net" look like a registrable domain and be
// rejected, even though only tailnet members can obtain a name under it. The
// same applies to any per-tenant namespace under a private-section entry.
//
// So this is a backstop that reliably catches the broad, well-known cases, not
// a decision procedure. The control that would be exact is an explicit operator
// allowlist of permitted wildcard parents -- there is exactly one in use
// ("preview.footstrike.run") -- with this check demoted to a second opinion.
// Until that exists, keep wildcard registrations rare and reviewed.
func validateWildcardSuffix(entry, suffix string) (string, error) {
	// Strip a single trailing dot (the DNS root label) so that "evil.com." and
	// "evil.com" are judged identically rather than differing by one character.
	normalized := strings.TrimSuffix(suffix, ".")
	if normalized == "" {
		return "", fmt.Errorf("redirect URI %q: wildcard entries must have a host suffix after %q", entry, "*.")
	}
	if strings.HasSuffix(normalized, ".") {
		// More than one trailing dot is not a name at all.
		return "", fmt.Errorf("redirect URI %q: wildcard suffix %q is not a valid host", entry, suffix)
	}
	// Reject non-ASCII, uppercase-folding and confusable characters in the
	// pattern itself, so a registered entry can never rely on Unicode folding to
	// widen what it matches.
	folded, ok := asciiLowerHost(normalized)
	if !ok {
		return "", fmt.Errorf("redirect URI %q: wildcard suffix %q must be an ASCII host", entry, suffix)
	}
	if strings.HasPrefix(folded, ".") || strings.Contains(folded, "..") {
		return "", fmt.Errorf("redirect URI %q: wildcard suffix %q is not a valid host", entry, suffix)
	}

	registrable, err := publicsuffix.EffectiveTLDPlusOne(folded)
	if err != nil {
		// No eTLD+1 exists, which means folded is itself a public suffix
		// ("s3.amazonaws.com", "run", "co.uk") -- the broadest possible wildcard.
		return "", fmt.Errorf(
			"redirect URI %q: wildcard suffix %q is a public suffix; anyone can register a host under it",
			entry, suffix)
	}
	if folded == registrable {
		return "", fmt.Errorf(
			"redirect URI %q: wildcard suffix %q is a registrable domain; use a dedicated subdomain such as %q",
			entry, suffix, "preview."+folded)
	}

	// The two checks above ask whether the suffix itself is registrable. That is
	// not quite the question that matters, which is whether every host the
	// wildcard matches belongs to the suffix's registrant. The Public Suffix
	// List answers the second question directly through its *wildcard rules*,
	// and those rules are invisible to the checks above.
	//
	// "*.compute-1.amazonaws.com" is such a rule: the parent is neither a public
	// suffix nor its own eTLD+1, so it passes both checks, yet the rule declares
	// every child an independent registrant -- and anyone with an AWS account
	// gets "ec2-<address>.compute-1.amazonaws.com", exactly one label down,
	// which the single-label restriction does nothing to stop. Same shape for
	// "*.elb.amazonaws.com".
	//
	// Probing one label down asks the right question: if a child of this suffix
	// resolves to a different registrant than the suffix does, the namespace is
	// handed out to third parties and a wildcard over it is not bounded.
	childRegistrable, err := publicsuffix.EffectiveTLDPlusOne(wildcardProbeLabel + "." + folded)
	if err != nil || childRegistrable != registrable {
		return "", fmt.Errorf(
			"redirect URI %q: hosts under wildcard suffix %q are independently registrable "+
				"(the public suffix list carries a wildcard rule for it), so anyone can obtain a matching host",
			entry, suffix)
	}
	return folded, nil
}

// wildcardProbeLabel is a placeholder label used only to ask the Public Suffix
// List what a child of a candidate suffix would resolve to. It never leaves this
// package and is never compared against a real host.
const wildcardProbeLabel = "wildcardprobe"

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
