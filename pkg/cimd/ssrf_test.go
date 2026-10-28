package cimd

import (
	"net/netip"
	"testing"
)

// forbiddenSamples has at least one address in every refused range, plus the
// edges of the ranges whose neighbours are public.
var forbiddenSamples = []string{
	// IPv4.
	"0.0.0.0", "0.1.2.3", "0.255.255.255",
	"10.0.0.0", "10.1.2.3", "10.255.255.255",
	"100.64.0.0", "100.100.100.100", "100.127.255.255",
	"127.0.0.1", "127.255.255.254",
	"169.254.0.1", "169.254.169.254",
	"172.16.0.0", "172.20.1.1", "172.31.255.255",
	"192.0.0.1", "192.0.0.255",
	"192.0.2.1",
	"192.31.196.1",
	"192.52.193.1",
	"192.88.99.1",
	"192.168.0.1", "192.168.255.255",
	"192.175.48.1",
	"198.18.0.0", "198.19.255.255",
	"198.51.100.1",
	"203.0.113.1",
	"224.0.0.1", "239.255.255.255",
	"240.0.0.1", "255.255.255.255",
	// IPv6.
	"::", "::1", "::10.0.0.1",
	"64:ff9b::a00:1", "64:ff9b:1::1",
	"100::1",
	"2001::1", "2001:0:4136:e378::1", "2001:1ff:ffff::1",
	"2001:db8::1",
	"2002:a00:1::1",
	"3fff::1",
	"5f00::1",
	"fc00::1", "fd12:3456::1",
	"fe80::1", "febf::1",
	"fec0::1",
	"ff02::1", "ff0e::1",
	// IPv4-mapped IPv6 of forbidden IPv4.
	"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
	"::ffff:192.168.1.1", "::ffff:100.64.0.1", "::ffff:0.0.0.0",
	// Zoned addresses.
	"fe80::1%eth0",
}

var allowedSamples = []string{
	"1.1.1.1", "8.8.8.8", "160.79.104.10", // the last is in Claude's range
	"100.63.255.255", "100.128.0.0", // either side of CGNAT
	"172.15.255.255", "172.32.0.0", // either side of 172.16/12
	"198.17.255.255", "198.20.0.0", // either side of benchmarking
	"192.0.1.1", "192.169.0.1",
	"223.255.255.255",
	"2606:4700:4700::1111", "2a00:1450:4001::1",
	"2001:200::1", // just past 2001::/23
	"::ffff:8.8.8.8",
}

func TestIsForbiddenAddress(t *testing.T) {
	for _, s := range forbiddenSamples {
		a := netip.MustParseAddr(s)
		if !IsForbiddenAddress(a) {
			t.Errorf("IsForbiddenAddress(%s) = false, want true", s)
		}
	}
	for _, s := range allowedSamples {
		a := netip.MustParseAddr(s)
		if IsForbiddenAddress(a) {
			t.Errorf("IsForbiddenAddress(%s) = true, want false", s)
		}
	}
	if !IsForbiddenAddress(netip.Addr{}) {
		t.Error("the zero Addr is not forbidden")
	}
}

func TestForbiddenLoopbackException(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "127.1.2.3", "::1", "::ffff:127.0.0.1"} {
		if forbidden(netip.MustParseAddr(s), true) {
			t.Errorf("forbidden(%s, permitLoopback) = true", s)
		}
	}
	// The exception is loopback only.
	for _, s := range []string{"10.0.0.1", "169.254.169.254", "::", "fe80::1", "0.0.0.0"} {
		if !forbidden(netip.MustParseAddr(s), true) {
			t.Errorf("forbidden(%s, permitLoopback) = false", s)
		}
	}
}

func TestCheckHostPort(t *testing.T) {
	f := newFetcher(DefaultUserAgent, testHooks{})
	for _, hp := range []string{"10.0.0.1:443", "[::1]:443", "127.0.0.1:443", "[fe80::1%25eth0]:443", "nonsense", "claude.ai:443"} {
		if f.checkHostPort(hp) == nil {
			t.Errorf("checkHostPort(%q) = nil", hp)
		}
	}
	for _, hp := range []string{"160.79.104.10:443", "[2606:4700::1]:443"} {
		if err := f.checkHostPort(hp); err != nil {
			t.Errorf("checkHostPort(%q) = %v", hp, err)
		}
	}
}
