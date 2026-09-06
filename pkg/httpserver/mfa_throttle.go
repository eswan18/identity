package httpserver

import (
	"log"
	"time"

	"github.com/google/uuid"
)

// Budget for failed MFA verifications, per account.
//
// Why per account rather than per pending row: the pending row is the obvious
// place to count, and it is close to useless there. The global per-IP limiter
// (20 req/min) is already the binding constraint on guessing, so capping
// attempts per pending only forces one extra request -- a fresh password login
// -- every few guesses, cutting throughput by roughly a sixth. Worse, any
// per-pending or per-IP cap scales with the number of IP addresses an attacker
// has, which is the cheapest thing for them to buy.
//
// A per-account budget does not. Against a 6-digit TOTP where totp.Validate
// accepts three codes per window (±1 for clock skew), the odds are 3 in a
// million per guess:
//
//	20 guesses/min from one IP, unbounded per account  -> ~193 hours for even odds
//	20 failures/hour per account, however distributed  -> ~11,500 hours
//
// That is the difference between a weekend and a year and a half.
//
// This cannot be used to lock a stranger out. Reaching any of these endpoints
// requires a valid password or an authenticated session: HandleLoginPost
// validates credentials before creating a pending row, and the setup/disable
// handlers sit behind requireActiveUser. So only someone who already holds the
// password can spend an account's budget.
//
// What such an attacker gets is worth stating precisely, because "for a window"
// understates it: while over budget, requests are refused at the check without
// charging, so the bucket refills at one per interval regardless -- and an
// attacker who keeps consuming each token as it appears can hold the account at
// zero indefinitely. They are already most of the way in at that point, and
// refusing a second factor is the safer failure, but it is not self-healing
// while the attack continues.
//
// The budget is per process. Production runs two replicas
// (k8s/base/deployment.yaml), so an account's real budget is twice what these
// constants say, and it scales with any change to replicas -- nothing ties the
// two together. It also resets when a pod restarts, which on spot nodes is
// routine rather than exceptional. Both are acceptable here only because of the
// size of the gap being closed: a restart returns at most one burst against a
// requirement of ~231,000 guesses. Persisting the counter would be the answer
// if that margin ever narrowed.
const (
	// mfaAttemptBurst is how many failures an account may make in quick
	// succession. Five is generous for a mistyped code and short of the runs of
	// failures that a wrong device -- or a clock too far out of sync for
	// totp.Validate's ±1 window -- produces.
	mfaAttemptBurst = 5

	// mfaAttemptInterval is the sustained refill once the burst is spent: one
	// failure every three minutes, or twenty an hour.
	mfaAttemptInterval = 3 * time.Minute

	// mfaAttemptEntryTTL must exceed the time to refill the whole burst
	// (5 x 3min = 15min), or the cleanup sweep would evict an exhausted
	// account's entry and hand it a fresh burst early. See rateLimitStore.entryTTL.
	mfaAttemptEntryTTL = 30 * time.Minute
)

// chargeMFAAttempt takes one unit of the account's failure budget and reports
// whether there was one to take. Call it before evaluating a code.
//
// It charges every attempt, not only failures, and clearMFAAttempts wipes the
// count on success. That is the conventional shape for a failure counter -- the
// budget bounds *consecutive* failures rather than lifetime use -- and it is the
// only shape that is atomic here.
//
// The obvious alternative, peek then charge on failure, is not atomic:
// rate.Limiter.Allow reports false without consuming when short, so concurrent
// requests can all pass the peek and each get a free code evaluation while only
// some charge. Reserving and cancelling does not work either, and the reason is
// worth recording so nobody tries it again: Reservation.CancelAt restores the
// token only when timeToAct is still in the future, so a reservation that was
// available immediately -- exactly the case here -- cannot be handed back.
func (s *Server) chargeMFAAttempt(userID uuid.UUID) bool {
	if s.mfaAttemptStore == nil {
		return true
	}
	limiter := s.mfaAttemptStore.getLimiter(userID.String(), rateEvery(mfaAttemptInterval), mfaAttemptBurst)
	if !limiter.Allow() {
		log.Printf("chargeMFAAttempt: MFA attempt budget exhausted for user %s", userID)
		return false
	}
	return true
}

// clearMFAAttempts restores an account's full budget. Call it when a code
// verified successfully.
//
// Without this, a user who authenticates five times within the refill window --
// during MFA setup, or logging back in a few times -- would throttle themselves
// having done nothing wrong. An attacker who has the password but not the device
// can never reach it, so it cannot be used to refill a guessing budget.
func (s *Server) clearMFAAttempts(userID uuid.UUID) {
	if s.mfaAttemptStore == nil {
		return
	}
	s.mfaAttemptStore.forget(userID.String())
}
