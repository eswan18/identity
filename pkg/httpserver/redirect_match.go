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
// refuse candidates carrying a query string or fragment. This exists so
// ephemeral stack environments (https://<app>-<tag>.stacks.footstrike.run)
// can complete OAuth without per-stack registration.
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
	if cand.Scheme != "https" || cand.Path != pat.Path || cand.Port() != pat.Port() {
		return false
	}
	if cand.RawQuery != "" || cand.Fragment != "" {
		return false
	}
	dotSuffix := "." + strings.ToLower(strings.TrimPrefix(pat.Hostname(), "*."))
	candHost := strings.ToLower(cand.Hostname())
	label, ok := strings.CutSuffix(candHost, dotSuffix)
	return ok && label != "" && !strings.ContainsAny(label, ".*")
}
