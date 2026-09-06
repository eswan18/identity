package httpserver

import (
	"testing"

	"github.com/google/uuid"
)

// TestMFAAttemptBudgetChargesOnlyFailures is the property that keeps this from
// locking out people who did nothing wrong: checking whether an attempt is
// allowed must not itself cost anything.
func TestMFAAttemptBudgetChargesOnlyFailures(t *testing.T) {
	srv := newHermeticTestServer(t)
	user := uuid.New()

	// Checking repeatedly, without recording a failure, must never exhaust the
	// budget -- this is the successful-login path.
	for i := 0; i < mfaAttemptBurst*3; i++ {
		if !srv.mfaAttemptAllowed(user) {
			t.Fatalf("check %d was refused; checking must not consume budget", i+1)
		}
	}

	// Failures do cost.
	for i := 1; i <= mfaAttemptBurst; i++ {
		if !srv.mfaAttemptAllowed(user) {
			t.Fatalf("attempt %d of the burst was refused; the budget is %d", i, mfaAttemptBurst)
		}
		srv.recordFailedMFAAttempt(user)
	}
	if srv.mfaAttemptAllowed(user) {
		t.Errorf("attempt %d was allowed; the burst of %d should be spent",
			mfaAttemptBurst+1, mfaAttemptBurst)
	}
}

// TestMFAAttemptBudgetIsPerAccount: the budget must not be global. A shared one
// would let a single attacker deny every user their second factor.
func TestMFAAttemptBudgetIsPerAccount(t *testing.T) {
	srv := newHermeticTestServer(t)
	victim := uuid.New()

	for i := 0; i < mfaAttemptBurst; i++ {
		srv.recordFailedMFAAttempt(victim)
	}
	if srv.mfaAttemptAllowed(victim) {
		t.Fatal("the exhausted account should be refused")
	}
	if !srv.mfaAttemptAllowed(uuid.New()) {
		t.Error("a different account was refused; one account's failures must not affect another's")
	}
}

// TestMFAAttemptEntryTTLOutlastsRefill pins the invariant that makes the budget
// real. rateLimitStore evicts entries idle longer than entryTTL; if that were
// shorter than the time to refill the burst, an attacker could pause, have the
// entry swept, and resume with a full budget -- turning "5 per 15 minutes" into
// "5 per TTL". The same trap was nearly shipped with the verification-mail
// budget.
func TestMFAAttemptEntryTTLOutlastsRefill(t *testing.T) {
	fullRefill := mfaAttemptInterval * mfaAttemptBurst
	if mfaAttemptEntryTTL <= fullRefill {
		t.Errorf("mfaAttemptEntryTTL (%v) must exceed the time to refill the burst (%v = %d x %v)",
			mfaAttemptEntryTTL, fullRefill, mfaAttemptBurst, mfaAttemptInterval)
	}
}
