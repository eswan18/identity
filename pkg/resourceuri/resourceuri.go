// Package resourceuri defines the canonical form of a resource indicator: the
// URI that names an API tokens can be minted for, and that becomes a token's
// aud (RFC 8707; MCP's "canonical server URI").
//
// Two callers need the same rule. identity-cli stores a new resource in
// canonical form, and the authorization and token endpoints canonicalize an
// incoming resource parameter before looking it up, so that
// "HTTPS://Sensibility.money/mcp/" finds "https://sensibility.money/mcp".
package resourceuri

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	// ErrEmpty is returned for an empty resource URI.
	ErrEmpty = errors.New("resource URI is empty")
	// ErrNotAbsolute is returned for a URI without a scheme (RFC 8707 §2
	// requires an absolute URI).
	ErrNotAbsolute = errors.New("resource URI must be absolute (have a scheme)")
	// ErrFragment is returned for a URI with a fragment, which RFC 8707 §2
	// forbids.
	ErrFragment = errors.New("resource URI must not have a fragment")
	// ErrUserinfo is returned for a URI carrying user:password@.
	ErrUserinfo = errors.New("resource URI must not contain userinfo")
	// ErrNoHost is returned for a hierarchical URI with no host.
	ErrNoHost = errors.New("resource URI must have a host")
	// ErrNotHTTPS is returned by ValidateNew for a scheme other than https.
	ErrNotHTTPS = errors.New("new resource URIs must use https")
)

// Canonicalize returns raw in canonical form: scheme and host lowercased, the
// scheme's default port removed (443 for https, 80 for http), and trailing
// slashes removed from the path. Path case, percent-encoding and any query are
// kept as given. It refuses an empty or relative URI, a fragment, userinfo, and
// a hierarchical URI without a host.
//
// An opaque URI such as "ethanswan:fitness" (a scheme followed by no "//") has
// no host or path to normalize; only its scheme is lowercased. That keeps the
// one grandfathered URN-style audience usable byte for byte.
//
// Canonicalize is idempotent: Canonicalize(Canonicalize(x)) == Canonicalize(x).
func Canonicalize(raw string) (string, error) {
	if raw == "" {
		return "", ErrEmpty
	}
	// url.Parse drops an empty trailing "#", so look at the raw string too.
	if strings.Contains(raw, "#") {
		return "", ErrFragment
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("resource URI %q is not a valid URI: %w", raw, err)
	}
	if u.Scheme == "" {
		return "", ErrNotAbsolute
	}
	scheme := strings.ToLower(u.Scheme)

	var query string
	if u.ForceQuery || u.RawQuery != "" {
		query = "?" + u.RawQuery
	}

	if u.Opaque != "" {
		return scheme + ":" + u.Opaque + query, nil
	}

	if u.User != nil {
		return "", ErrUserinfo
	}
	hostname := strings.ToLower(u.Hostname())
	if hostname == "" {
		return "", ErrNoHost
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	host := hostname
	if strings.Contains(hostname, ":") { // IPv6 literal: put the brackets back
		host = "[" + hostname + "]"
	}
	if port != "" {
		host = net.JoinHostPort(hostname, port)
	}

	path := strings.TrimRight(u.EscapedPath(), "/")
	return scheme + "://" + host + path + query, nil
}

// ValidateNew canonicalizes the URI of a resource being registered and
// additionally requires https. Resources registered before this rule (the
// backfilled audiences) are not checked against it.
func ValidateNew(raw string) (string, error) {
	canonical, err := Canonicalize(raw)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(canonical, "https://") {
		return "", ErrNotHTTPS
	}
	return canonical, nil
}
