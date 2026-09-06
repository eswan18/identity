package httpserver

import (
	"testing"
	"time"
)

// TestNewHTTPServerSetsTimeouts asserts that every connection-lifecycle timeout
// is actually configured.
//
// http.Server applies none of these by default, and the failure mode of
// forgetting one is invisible: the service works perfectly in every functional
// test while a connection that sends nothing is held open indefinitely, each one
// holding a goroutine. Nothing else in the suite would notice a field being
// dropped in a future edit, so this asserts them by name.
func TestNewHTTPServerSetsTimeouts(t *testing.T) {
	srv := newHermeticTestServer(t).newHTTPServer()

	timeouts := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"ReadHeaderTimeout", srv.ReadHeaderTimeout, readHeaderTimeout},
		{"ReadTimeout", srv.ReadTimeout, readTimeout},
		{"WriteTimeout", srv.WriteTimeout, writeTimeout},
		{"IdleTimeout", srv.IdleTimeout, idleTimeout},
	}
	for _, tt := range timeouts {
		if tt.got == 0 {
			t.Errorf("%s is unset; an unbounded connection lifecycle is the defect this guards against", tt.name)
			continue
		}
		if tt.got != tt.want {
			t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}

// TestTimeoutOrderingInvariants pins the relationships between the timeouts.
// Each value on its own looks arbitrary; it is the ordering that makes them
// correct, and a plausible-looking future edit to any single constant can break
// one of these without breaking anything else.
func TestTimeoutOrderingInvariants(t *testing.T) {
	// The chi middleware.Timeout must fire before the connection is severed, so
	// a request that overruns gets a 504 rather than a dropped connection.
	if writeTimeout <= handlerTimeout {
		t.Errorf("writeTimeout (%v) must exceed handlerTimeout (%v), otherwise the connection is cut "+
			"before middleware.Timeout can write its 504", writeTimeout, handlerTimeout)
	}

	// Headers are a small prefix of the request; giving them the same budget as
	// the whole body would defeat the point of having a separate, tighter bound.
	if readHeaderTimeout >= readTimeout {
		t.Errorf("readHeaderTimeout (%v) must be shorter than readTimeout (%v); a tighter header "+
			"deadline is the actual slowloris defense", readHeaderTimeout, readTimeout)
	}

	// A keep-alive connection should outlive a single request, or clients pay a
	// reconnect on every request.
	if idleTimeout <= readTimeout {
		t.Errorf("idleTimeout (%v) should exceed readTimeout (%v) so keep-alive outlives a request",
			idleTimeout, readTimeout)
	}
}
