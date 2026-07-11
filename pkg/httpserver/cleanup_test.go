package httpserver

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestCleanupLoop_RunsPeriodicallyAndStopsOnCancel is a hermetic (no database) test of
// the timing/shutdown behavior behind startCleanupWorker. runExpiryCleanup itself talks
// to Postgres and is hard to unit test without one, so the loop mechanics are factored
// out into cleanupLoop (see cleanup.go), which takes the sweep as a plain
// func(context.Context) and can be exercised with a fake here.
func TestCleanupLoop_RunsPeriodicallyAndStopsOnCancel(t *testing.T) {
	const interval = 10 * time.Millisecond

	var calls int32
	sweep := func(context.Context) {
		atomic.AddInt32(&calls, 1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		cleanupLoop(ctx, interval, sweep)
		close(done)
	}()

	// cleanupLoop runs sweep once immediately and then every interval. Waiting for
	// several multiples of the interval should comfortably yield multiple calls even
	// under CI scheduling jitter, while keeping the test fast.
	time.Sleep(12 * interval)

	callsBeforeCancel := atomic.LoadInt32(&calls)
	if callsBeforeCancel < 3 {
		t.Fatalf("expected at least 3 sweep calls within %s, got %d", 12*interval, callsBeforeCancel)
	}

	cancel()

	select {
	case <-done:
		// cleanupLoop returned promptly after cancellation, as expected.
	case <-time.After(2 * time.Second):
		t.Fatal("cleanupLoop did not return promptly after context cancellation (possible goroutine leak)")
	}

	// Confirm the loop actually stopped sweeping once it reported done, rather than
	// racing a stray tick in afterward.
	callsAtDone := atomic.LoadInt32(&calls)
	time.Sleep(5 * interval)
	if got := atomic.LoadInt32(&calls); got != callsAtDone {
		t.Fatalf("sweep was called again after cleanupLoop returned: at-done=%d after-wait=%d", callsAtDone, got)
	}
}

// TestEffectiveCleanupInterval covers the fallback startCleanupWorker relies on to
// avoid ever handing time.NewTicker a non-positive duration, which panics. This matters
// in practice because several tests in this package (e.g. integration_common_test.go's
// OAuthFlowSuite) build a config.Config as a struct literal rather than via
// config.NewFromEnv, leaving CleanupInterval at its zero value, and then call
// Server.Run (which launches the cleanup worker).
func TestEffectiveCleanupInterval(t *testing.T) {
	tests := []struct {
		name  string
		input time.Duration
		want  time.Duration
	}{
		{name: "positive value is kept as-is", input: 5 * time.Minute, want: 5 * time.Minute},
		{name: "zero falls back to default", input: 0, want: fallbackCleanupInterval},
		{name: "negative falls back to default", input: -1 * time.Second, want: fallbackCleanupInterval},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := effectiveCleanupInterval(tt.input); got != tt.want {
				t.Errorf("effectiveCleanupInterval(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
