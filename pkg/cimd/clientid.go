package cimd

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// The errors Resolve returns, for errors.Is. Each is wrapped with detail.
var (
	// ErrNotClientIDURL: the client_id is not a valid Client Identifier URL.
	ErrNotClientIDURL = errors.New("cimd: not a valid client ID metadata document URL")
	// ErrHostNotAllowed: the URL is well formed but its host is not on the
	// allow-list. Nothing was fetched.
	ErrHostNotAllowed = errors.New("cimd: client ID metadata document host not allowed")
	// ErrFetch: the document could not be retrieved (DNS, a forbidden
	// address, connection, TLS, timeout, status, content type, size).
	ErrFetch = errors.New("cimd: fetching client ID metadata document failed")
	// ErrForbiddenAddress accompanies ErrFetch when the host resolved to, or
	// the connection reached, a special-use address.
	ErrForbiddenAddress = errors.New("cimd: address is special-use")
	// ErrInvalidDocument: the document was retrieved but is not acceptable.
	ErrInvalidDocument = errors.New("cimd: invalid client ID metadata document")
)

// maxClientIDLength bounds the URL. Nothing legitimate comes close.
const maxClientIDLength = 2048

// IsClientIDURL reports whether clientID is a Client Identifier URL this
// package will consider (see ValidateClientIDURL). It does not consult the
// allow-list.
func IsClientIDURL(clientID string) bool {
	return ValidateClientIDURL(clientID) == nil
}

// ValidateClientIDURL checks clientID against CIMD -02 §3, as tightened by
// identity. It returns nil or an error wrapping ErrNotClientIDURL that says
// which rule failed.
//
// From the draft: the scheme is https; there is a path; there is no userinfo,
// no fragment, and no "." or ".." path segment.
//
// Identity's additions, each because a client_id is compared by simple string
// comparison (§3) and checked against a host allow-list, so a URL with two
// spellings is a URL whose identity is ambiguous:
//
//   - No query, not even an empty one. The draft says SHOULD NOT. A query has
//     many spellings of the same meaning (parameter order, encoding), all of
//     which compare unequal, and none of the allow-listed clients uses one.
//   - The scheme and host are lowercase, the host is a plain DNS name (ASCII
//     letters, digits, '-' and '.', no trailing dot), and there is no
//     explicit port, ":443" included. The allow-list then matches the host
//     exactly, and the URL that is fetched is the URL that is compared.
//   - The path is more than "/": a document at the root of a host would make
//     the whole origin one client.
//   - Dot segments are refused also when percent-encoded ("%2e", "%2E"),
//     since a server may decode them.
//   - The URL is in the form net/url would print it (no stray encodings, no
//     backslashes, no spaces), and at most 2048 bytes.
func ValidateClientIDURL(clientID string) error {
	fail := func(reason string) error {
		return fmt.Errorf("%w: %s", ErrNotClientIDURL, reason)
	}
	if len(clientID) > maxClientIDLength {
		return fail("longer than 2048 bytes")
	}
	rest, ok := strings.CutPrefix(clientID, "https://")
	if !ok {
		return fail(`must start with "https://"`)
	}
	if strings.Contains(clientID, "#") {
		return fail("must not contain a fragment")
	}
	if strings.Contains(clientID, "?") {
		return fail("must not contain a query")
	}
	if strings.ContainsAny(clientID, "\\ \t\r\n") {
		return fail("must not contain whitespace or backslashes")
	}
	authority, _, hasPath := strings.Cut(rest, "/")
	if strings.Contains(authority, "@") {
		return fail("must not contain userinfo")
	}
	if strings.Contains(authority, ":") {
		return fail("must not contain a port")
	}
	if !validHostName(authority) {
		return fail("host must be a lowercase DNS name")
	}
	if !hasPath {
		return fail("must have a path")
	}
	u, err := url.Parse(clientID)
	if err != nil {
		return fail(err.Error())
	}
	if u.Scheme != "https" || u.Host != authority || u.User != nil || u.Opaque != "" {
		return fail("does not parse as an https URL with this host")
	}
	path := u.EscapedPath()
	if path == "" || path == "/" {
		return fail("must have a path beyond /")
	}
	for _, seg := range strings.Split(path, "/") {
		s := strings.ReplaceAll(strings.ToLower(seg), "%2e", ".")
		if s == "." || s == ".." {
			return fail(`must not contain "." or ".." path segments`)
		}
	}
	if u.String() != clientID {
		return fail("is not in canonical form")
	}
	return nil
}

// validHostName reports whether h is a lowercase ASCII DNS name: labels of
// [a-z0-9-], not starting or ending with '-', separated by single dots, with
// no leading or trailing dot. IPv4 literals pass (they are only ever usable if
// an operator allow-lists one); IPv6 literals and anything with a port do not.
func validHostName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// hostOf returns the host of a URL that passed ValidateClientIDURL.
func hostOf(clientID string) string {
	rest := strings.TrimPrefix(clientID, "https://")
	host, _, _ := strings.Cut(rest, "/")
	return host
}
