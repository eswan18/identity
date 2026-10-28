package cimd

import (
	"net/netip"
)

// forbiddenPrefixes are the address blocks a metadata fetch must never reach
// (CIMD -02 §8.6): the IANA special-purpose registries (RFC 6890 and later
// additions) plus multicast and the reserved class E space. The list errs
// broad -- a block with some globally reachable members (2001::/23) is refused
// whole -- because the only hosts identity fetches from are large public
// services, which are never served from any of these.
var forbiddenPrefixes = mustPrefixes(
	// IPv4.
	"0.0.0.0/8",       // "this network", incl. unspecified 0.0.0.0
	"10.0.0.0/8",      // private (RFC 1918)
	"100.64.0.0/10",   // shared address space / CGNAT (RFC 6598); also Tailscale
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local, incl. cloud metadata 169.254.169.254
	"172.16.0.0/12",   // private (RFC 1918)
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // documentation TEST-NET-1
	"192.31.196.0/24", // AS112-v4
	"192.52.193.0/24", // AMT
	"192.88.99.0/24",  // deprecated 6to4 relay anycast
	"192.168.0.0/16",  // private (RFC 1918)
	"192.175.48.0/24", // AS112 direct delegation
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // documentation TEST-NET-2
	"203.0.113.0/24",  // documentation TEST-NET-3
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved, incl. limited broadcast 255.255.255.255
	// IPv6. IPv4-mapped addresses (::ffff:0:0/96) are unmapped and judged as
	// IPv4 before this list is consulted.
	"::/96",          // unspecified, loopback ::1, deprecated IPv4-compatible
	"64:ff9b::/96",   // NAT64 well-known prefix: embeds an IPv4 address
	"64:ff9b:1::/48", // local-use NAT64
	"100::/64",       // discard-only
	"2001::/23",      // IETF protocol assignments, incl. Teredo 2001::/32
	"2001:db8::/32",  // documentation
	"2002::/16",      // 6to4: embeds an IPv4 address
	"3fff::/20",      // documentation (RFC 9637)
	"5f00::/16",      // SRv6 SIDs
	"fc00::/7",       // unique local
	"fe80::/10",      // link-local
	"fec0::/10",      // deprecated site-local
	"ff00::/8",       // multicast
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

var loopbackPrefixes = mustPrefixes("127.0.0.0/8", "::1/128")

// IsForbiddenAddress reports whether a metadata fetch must refuse addr. An
// invalid address, one with a zone (only meaningful for link-local), and every
// special-use address are forbidden. IPv4-mapped IPv6 addresses are judged as
// the IPv4 address they carry.
func IsForbiddenAddress(addr netip.Addr) bool {
	return forbidden(addr, false)
}

// forbidden is IsForbiddenAddress with the test-only loopback exception: when
// permitLoopback is set, 127.0.0.0/8 and ::1 pass so tests can fetch from an
// httptest server. Only package tests ever set it (see testHooks).
func forbidden(addr netip.Addr, permitLoopback bool) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return true
	}
	addr = addr.Unmap()
	if permitLoopback {
		for _, p := range loopbackPrefixes {
			if p.Contains(addr) {
				return false
			}
		}
	}
	for _, p := range forbiddenPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
