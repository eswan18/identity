package redirecturi

import (
	"net"
	"net/url"
	"strings"
)

// UnsafeForTrustedClient reports why uri must not be a redirect URI of a
// trusted (first-party) client, or "" if it may be. A trusted client skips the
// consent screen, so a signed-in user is sent to its redirect URI with a code
// and no interaction; that is only acceptable when the operator alone controls
// what answers at that URI. Two kinds of entry break that:
//
//   - a wildcard pattern: anyone who can deploy a host matching it (a preview
//     environment, say) receives codes;
//   - a loopback URI (localhost or *.localhost, 127.0.0.0/8, ::1, any scheme
//     and port): any program on the user's machine can listen there.
//
// A host that is numeric but not a plain IP address ("127.1", "0x7f.1") is
// refused too, since browsers may read it as loopback. An unparseable URI is
// refused rather than guessed at. See README, "Trusted (first-party) clients".
func UnsafeForTrustedClient(uri string) string {
	if isWildcardEntry(uri) {
		return "it is a wildcard pattern, so whoever can deploy a matching host would receive codes"
	}
	u, err := url.Parse(uri)
	if err != nil {
		return "it cannot be parsed"
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return "it is a loopback address, so any program on the user's machine could receive codes"
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() {
			return "it is a loopback address, so any program on the user's machine could receive codes"
		}
		return ""
	}
	if looksNumeric(host) {
		return "its host is an unusual numeric address that browsers may treat as loopback"
	}
	return ""
}

// looksNumeric reports whether host is made only of digits, dots and hex
// notation (0x...), the shapes browsers parse as an IPv4 address.
func looksNumeric(host string) bool {
	if host == "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			continue
		}
		l := strings.TrimPrefix(label, "0x")
		if l == "" {
			return true
		}
		for _, c := range l {
			if !(c >= '0' && c <= '9') && !(label != l && (c >= 'a' && c <= 'f')) {
				return false
			}
		}
	}
	return true
}
