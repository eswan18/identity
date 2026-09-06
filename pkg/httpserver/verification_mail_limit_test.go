package httpserver

import (
	"testing"

	"github.com/google/uuid"
)

// TestAllowVerificationMailBudget covers the budget itself: a burst, then
// refusal, and that the budget is per account rather than global.
func TestAllowVerificationMailBudget(t *testing.T) {
	srv := newHermeticTestServer(t)
	user := uuid.New()

	for i := 1; i <= verificationMailBurst; i++ {
		if !srv.allowVerificationMail(user) {
			t.Fatalf("message %d of the burst was refused; the budget is %d", i, verificationMailBurst)
		}
	}
	if srv.allowVerificationMail(user) {
		t.Errorf("message %d was allowed; the burst of %d should be spent",
			verificationMailBurst+1, verificationMailBurst)
	}

	// A different account must be unaffected -- a global budget would let one
	// abusive account deny everyone else their verification mail.
	if !srv.allowVerificationMail(uuid.New()) {
		t.Errorf("a different account was refused; the budget must be per account")
	}
}

// TestVerificationMailEntryTTLOutlastsRefill pins the invariant that makes the
// budget real.
//
// rateLimitStore's cleanup sweep discards entries idle for longer than entryTTL.
// If that TTL were shorter than the time to refill the whole burst, an exhausted
// account would simply wait for eviction and get a fresh burst -- the limit
// would read as "5 per 75 minutes" while behaving as "5 per TTL". Nothing else
// in the suite would notice, because every functional test stays well inside the
// burst.
func TestVerificationMailEntryTTLOutlastsRefill(t *testing.T) {
	fullRefill := verificationMailInterval * verificationMailBurst
	if verificationMailEntryTTL <= fullRefill {
		t.Errorf("verificationMailEntryTTL (%v) must exceed the time to refill the burst (%v = %d x %v); "+
			"otherwise eviction hands back a fresh budget early",
			verificationMailEntryTTL, fullRefill, verificationMailBurst, verificationMailInterval)
	}
}

// TestIPEntryTTLOutlastsRefill applies the same invariant to the global per-IP
// limiter, whose 10-minute TTL predates the TTL being configurable.
func TestIPEntryTTLOutlastsRefill(t *testing.T) {
	// The global limiter is 20 requests/minute with a burst of 20, so a full
	// refill takes one minute.
	const fullRefill = 1 * 60 * 1e9 // 1 minute in nanoseconds
	if ipEntryTTL <= fullRefill {
		t.Errorf("ipEntryTTL (%v) must exceed the per-IP limiter's refill time", ipEntryTTL)
	}
}
