package httpserver

import (
	"net/url"
	"slices"
	"strings"
)

// redirectURIAllowed reports whether candidate is allowed by a client's
// registered redirect URIs. An entry allows the candidate if it matches
// exactly, or if the entry's host begins with "*." and the candidate differs
// only by replacing the "*" with exactly one non-empty DNS label. Wildcard
// entries match https candidates only, require identical path and port, and
// refuse candidates carrying a query string or fragment. The wildcard
// pattern's path must equal the candidate's path exactly, so register the
// pattern with the full callback path (a pattern with no path only matches a
// candidate with no trailing slash). This exists so ephemeral preview
// environments (https://<app>-<tag>.preview.footstrike.run) can complete
// OAuth without per-preview registration.
func redirectURIAllowed(registered []string, candidate string) bool {
	if slices.Contains(registered, candidate) {
		return true
	}
	cand, err := url.Parse(candidate)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(registered, func(entry string) bool {
		return wildcardRedirectMatch(entry, cand)
	})
}

func wildcardRedirectMatch(entry string, cand *url.URL) bool {
	pat, err := url.Parse(entry)
	if err != nil || pat.Scheme != "https" || !strings.HasPrefix(pat.Host, "*.") {
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

// asciiLowerHost ASCII-lowercases host (A-Z to a-z only, no Unicode case
// folding) and reports ok=false if the result contains any byte outside
// [a-z0-9.-]. This rejects hosts that rely on Unicode folding or confusable
// characters to defeat the single-label check above — for example U+212A
// KELVIN SIGN, which strings.ToLower folds to "k", or U+FF0E FULLWIDTH FULL
// STOP, which browsers' UTS-46 host mapping treats as "." but which would
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
