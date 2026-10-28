package cimd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/eswan18/identity/pkg/redirecturi"
)

// Metadata is a validated Client ID Metadata Document, as much of it as
// identity uses. Values are copies; changing them does not affect the cache.
type Metadata struct {
	// ClientID is the client_id URL, equal to the URL fetched.
	ClientID string
	// ClientName is the document's self-asserted name. Show it only as what
	// the client calls itself, beneath Host() (CIMD §8.5).
	ClientName string
	// RedirectURIs are https URIs or loopback http URIs
	// (redirecturi.IsLoopback), none with a fragment or "*". Never empty.
	RedirectURIs []string
	// ClientURI and LogoURI are https URLs or "". Kept, not displayed.
	ClientURI string
	LogoURI   string
	// FetchedAt is when this document was retrieved, to the microsecond (what
	// a timestamptz holds, so it compares equal after a round trip through
	// oauth_clients.metadata_fetched_at). ExpiresAt is when the
	// cache stops serving it.
	FetchedAt time.Time
	ExpiresAt time.Time
}

// Host is the client_id URL's host ("claude.ai"): what the consent screen
// names as the app.
func (m *Metadata) Host() string { return hostOf(m.ClientID) }

func (m *Metadata) clone() *Metadata {
	c := *m
	c.RedirectURIs = slices.Clone(m.RedirectURIs)
	return &c
}

const (
	maxClientNameRunes = 200
	maxRedirectURIs    = 20
	maxURILength       = 2048
)

// parseDocument validates body as the document served at clientID (CIMD -02
// §4, §4.1, as identity applies them) and returns its metadata without the
// time fields. Errors wrap ErrInvalidDocument.
//
// Rules: a single JSON object; client_id a string equal to clientID by simple
// string comparison; client_name a non-empty string without control or
// bidirectional-formatting characters, at most 200 characters (it is shown
// on the consent screen); redirect_uris a non-empty array of at most 20
// strings, each https or a loopback http URI, with no fragment and no "*";
// token_endpoint_auth_method absent or "none" (no secrets, and private_key_jwt
// is not supported yet); no client_secret or client_secret_expires_at at all;
// grant_types, if present, including authorization_code (other values are
// the client's own declarations and are ignored: claude.ai lists jwt-bearer,
// and the token endpoint refuses every grant a CIMD client may not use, so a
// declared but unsupported grant gains nothing); response_types, if present, only "code";
// client_uri and logo_uri, if present, https URLs. Every member identity reads
// must have the expected JSON type -- null included is a type error -- and
// members it does not read are ignored.
func parseDocument(clientID string, body []byte) (*Metadata, error) {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidDocument, fmt.Sprintf(format, args...))
	}
	if !utf8.Valid(body) {
		return nil, fail("not UTF-8")
	}
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fail("not a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	var doc map[string]json.RawMessage
	if err := dec.Decode(&doc); err != nil {
		return nil, fail("malformed JSON: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fail("trailing data after the JSON object")
	}

	str := func(name string) (string, bool, error) {
		raw, ok := doc[name]
		if !ok {
			return "", false, nil
		}
		var s *string
		if err := json.Unmarshal(raw, &s); err != nil || s == nil {
			return "", true, fail("%s must be a string", name)
		}
		return *s, true, nil
	}
	strs := func(name string) ([]string, bool, error) {
		raw, ok := doc[name]
		if !ok {
			return nil, false, nil
		}
		var ss *[]string
		if err := json.Unmarshal(raw, &ss); err != nil || ss == nil {
			return nil, true, fail("%s must be an array of strings", name)
		}
		return *ss, true, nil
	}

	md := &Metadata{}

	id, ok, err := str("client_id")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fail("client_id is missing")
	}
	if id != clientID {
		return nil, fail("client_id %q does not equal the URL fetched", truncate(id))
	}
	md.ClientID = id

	name, ok, err := str("client_name")
	if err != nil {
		return nil, err
	}
	if !ok || strings.TrimSpace(name) == "" {
		return nil, fail("client_name is missing or empty")
	}
	if utf8.RuneCountInString(name) > maxClientNameRunes {
		return nil, fail("client_name is longer than %d characters", maxClientNameRunes)
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return nil, fail("client_name contains a control or bidirectional formatting character")
		}
	}
	md.ClientName = name

	uris, ok, err := strs("redirect_uris")
	if err != nil {
		return nil, err
	}
	if !ok || len(uris) == 0 {
		return nil, fail("redirect_uris is missing or empty")
	}
	if len(uris) > maxRedirectURIs {
		return nil, fail("more than %d redirect_uris", maxRedirectURIs)
	}
	for _, u := range uris {
		if err := checkRedirectURI(u); err != nil {
			return nil, fail("redirect_uri %q: %v", truncate(u), err)
		}
	}
	md.RedirectURIs = uris

	method, ok, err := str("token_endpoint_auth_method")
	if err != nil {
		return nil, err
	}
	if ok && method != "none" {
		return nil, fail("token_endpoint_auth_method %q is not supported; only \"none\" is", truncate(method))
	}
	for _, forbidden := range []string{"client_secret", "client_secret_expires_at"} {
		if _, ok := doc[forbidden]; ok {
			return nil, fail("%s must not be present", forbidden)
		}
	}

	grants, ok, err := strs("grant_types")
	if err != nil {
		return nil, err
	}
	// Only authorization_code is required. Values identity doesn't support are
	// ignored rather than refused, as RFC 7591 §2 allows for client-declared
	// grant types; what a CIMD client can actually do is decided at the token
	// endpoint, which permits it authorization_code and refresh_token only.
	if ok {
		if !slices.Contains(grants, "authorization_code") {
			return nil, fail("grant_types must include authorization_code")
		}
	}
	responses, ok, err := strs("response_types")
	if err != nil {
		return nil, err
	}
	if ok {
		if len(responses) == 0 {
			return nil, fail("response_types must include code")
		}
		for _, r := range responses {
			if r != "code" {
				return nil, fail("response_type %q is not supported", truncate(r))
			}
		}
	}

	for _, f := range []struct {
		name string
		dst  *string
	}{{"client_uri", &md.ClientURI}, {"logo_uri", &md.LogoURI}} {
		v, ok, err := str(f.name)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if err := checkHTTPSURL(v); err != nil {
			return nil, fail("%s %q: %v", f.name, truncate(v), err)
		}
		*f.dst = v
	}
	return md, nil
}

// checkRedirectURI admits an https URI or an http loopback URI as
// redirecturi.IsLoopback defines it, neither with a fragment. "*" is refused
// everywhere: stored in oauth_clients.redirect_uris it would be read as a
// wildcard pattern.
func checkRedirectURI(u string) error {
	if len(u) > maxURILength {
		return fmt.Errorf("longer than %d bytes", maxURILength)
	}
	if strings.Contains(u, "#") {
		return fmt.Errorf("must not contain a fragment")
	}
	if strings.Contains(u, "*") {
		return fmt.Errorf(`must not contain "*"`)
	}
	if strings.ContainsFunc(u, func(r rune) bool { return r <= ' ' || r == '\\' || r == 0x7f }) {
		return fmt.Errorf("must not contain whitespace, control characters or backslashes")
	}
	if redirecturi.IsLoopback(u) {
		return nil
	}
	if strings.HasPrefix(u, "http://") {
		return fmt.Errorf("http is allowed only for loopback hosts 127.0.0.1, [::1] and localhost")
	}
	return checkHTTPSURL(u)
}

// checkHTTPSURL admits an absolute https URL with a host, no userinfo and no
// fragment.
func checkHTTPSURL(s string) error {
	if len(s) > maxURILength {
		return fmt.Errorf("longer than %d bytes", maxURILength)
	}
	if !strings.HasPrefix(s, "https://") {
		return fmt.Errorf("must be an https URL")
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("unparseable: %v", err)
	}
	if u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("has no host")
	}
	if u.User != nil {
		return fmt.Errorf("must not contain userinfo")
	}
	if strings.Contains(s, "#") {
		return fmt.Errorf("must not contain a fragment")
	}
	return nil
}

// truncate keeps attacker-supplied strings in error messages short.
func truncate(s string) string {
	const max = 100
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
