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
// This cannot be used to lock a stranger out. Reaching the MFA step at all
// requires a valid password: HandleLoginPost validates credentials before
// creating a pending row, so only someone who already holds the password can
// spend an account's budget. An attacker who has the password can deny that
// account its MFA step for a window -- but they are already most of the way in,
// and a temporary refusal is the safer failure.
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

// mfaAttemptAllowed reports whether this account has budget left to attempt an
// MFA code, WITHOUT consuming any.
//
// The check and the charge are separate on purpose: only a failed attempt should
// cost anything. Consuming on entry would make a user who logs in successfully
// five times in a quarter of an hour -- during setup, or while testing -- lock
// themselves out having done nothing wrong.
func (s *Server) mfaAttemptAllowed(userID uuid.UUID) bool {
	if s.mfaAttemptStore == nil {
		return true
	}
	limiter := s.mfaAttemptStore.getLimiter(userID.String(), rateEvery(mfaAttemptInterval), mfaAttemptBurst)
	if limiter.Tokens() < 1 {
		log.Printf("mfaAttemptAllowed: MFA attempt budget exhausted for user %s", userID)
		return false
	}
	return true
}

// recordFailedMFAAttempt charges one unit of the account's budget. Call it only
// when a code was actually wrong.
func (s *Server) recordFailedMFAAttempt(userID uuid.UUID) {
	if s.mfaAttemptStore == nil {
		return
	}
	limiter := s.mfaAttemptStore.getLimiter(userID.String(), rateEvery(mfaAttemptInterval), mfaAttemptBurst)
	limiter.Allow()
}
