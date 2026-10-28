package redirecturi

// IsLoopback reports whether uri is an http loopback redirect URI in the sense
// Allowed uses for its any-port rule: exactly "http://", then 127.0.0.1, [::1]
// or localhost, optionally ":port" (1-65535), then anything. It is the single
// definition of "loopback redirect URI" for code outside this package -- the
// Client ID Metadata Document validator (pkg/cimd) accepts a document's
// redirect URI only if it is https or passes this check, so a URI it admits is
// one Allowed will treat as loopback, and vice versa.
//
// It says nothing about the rest of the URI; callers that need more (no
// fragment, say) check it themselves.
func IsLoopback(uri string) bool {
	_, _, ok := cutLoopbackPort(uri)
	return ok
}
