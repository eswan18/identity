package httpserver

import (
	"sync"
	"testing"

	"github.com/google/uuid"
)

// TestSuccessfulMFAClearsTheFailureBudget is the property that keeps this from
// locking out people who did nothing wrong. The budget bounds consecutive
// failures, so a success must wipe the count -- otherwise authenticating a few
// times inside the refill window throttles a user who never got a code wrong.
func TestSuccessfulMFAClearsTheFailureBudget(t *testing.T) {
	srv := newHermeticTestServer(t)
	user := uuid.New()

	// Charge-then-clear, as a successful verification does, many times over.
	for i := 0; i < mfaAttemptBurst*3; i++ {
		if !srv.chargeMFAAttempt(user) {
			t.Fatalf("attempt %d was refused; a cleared budget must be fully restored", i+1)
		}
		srv.clearMFAAttempts(user)
	}

	// Almost spend it, then succeed: the whole burst comes back.
	for i := 0; i < mfaAttemptBurst-1; i++ {
		srv.chargeMFAAttempt(user)
	}
	srv.clearMFAAttempts(user)
	for i := 1; i <= mfaAttemptBurst; i++ {
		if !srv.chargeMFAAttempt(user) {
			t.Fatalf("failure %d of the burst was refused after a success cleared the count", i)
		}
	}
	if srv.chargeMFAAttempt(user) {
		t.Errorf("failure %d was allowed; the burst of %d should be spent",
			mfaAttemptBurst+1, mfaAttemptBurst)
	}
}

// TestMFAAttemptChargeIsAtomic pins the reason this charges with a single Allow
// rather than peeking and then charging on failure. That split is not atomic:
// Allow reports false without consuming when short, so concurrent requests can
// all pass the peek and each get a free code evaluation while only some charge.
// However many arrive at once, no more than the budget may get through.
func TestMFAAttemptChargeIsAtomic(t *testing.T) {
	srv := newHermeticTestServer(t)
	user := uuid.New()

	const concurrency = 256
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0

	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			if srv.chargeMFAAttempt(user) {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowed > mfaAttemptBurst {
		t.Errorf("%d concurrent attempts got through a budget of %d; the charge is not atomic",
			allowed, mfaAttemptBurst)
	}
}

// TestMFAAttemptBudgetIsPerAccount: the budget must not be global. A shared one
// would let a single attacker deny every user their second factor.
func TestMFAAttemptBudgetIsPerAccount(t *testing.T) {
	srv := newHermeticTestServer(t)
	victim := uuid.New()

	for i := 0; i < mfaAttemptBurst; i++ {
		srv.chargeMFAAttempt(victim)
	}
	if srv.chargeMFAAttempt(victim) {
		t.Fatal("the exhausted account should be refused")
	}
	if !srv.chargeMFAAttempt(uuid.New()) {
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
