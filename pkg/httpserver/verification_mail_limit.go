package httpserver

import (
	"log"
	"time"

	"github.com/google/uuid"
)

// Budget for verification mail sent on behalf of a single account.
//
// Two endpoints cause this service to send mail to an address the account holder
// has not proven they own: change-email writes the new address and mails it, and
// resend-verification mails whatever address is currently on the account. Neither
// was bounded per account, so one registration was an unlimited way to make
// identity's own domain send DKIM-signed mail to arbitrary recipients -- change
// the address, resend, change again. The global per-IP limiter did not help,
// since it bounds requests from one source rather than mail caused by one
// account, and an attacker with several addresses simply spreads out.
//
// The two endpoints deliberately share one budget. Limiting only change-email
// would leave the same primitive intact: set the address to a victim once, then
// hammer resend. What is being rationed is outbound mail attributable to an
// account, not any particular route.
const (
	// verificationMailBurst is how many messages an account may cause in quick
	// succession. Set for the plausible legitimate sequence -- change the
	// address, notice it hasn't arrived, resend a couple of times -- rather than
	// the minimum that would technically work.
	verificationMailBurst = 5

	// verificationMailInterval is the sustained refill rate once the burst is
	// spent: four messages an hour.
	verificationMailInterval = 15 * time.Minute

	// verificationMailEntryTTL must exceed the time to refill the whole burst
	// (5 x 15min = 75min), or the cleanup sweep would evict an exhausted
	// account's entry and hand it a fresh burst early. See rateLimitStore.entryTTL.
	verificationMailEntryTTL = 2 * time.Hour

	// ipEntryTTL preserves the eviction behaviour the global per-IP limiter has
	// always had. Its budget refills in well under a minute, so a ten-minute
	// idle TTL is comfortably longer than a full refill.
	ipEntryTTL = 10 * time.Minute
)

// allowVerificationMail reports whether this account may cause another
// verification email, consuming one unit of its budget when it may.
//
// Call it immediately before the send, not at the start of the handler: only
// mail that is actually sent should cost anything. Charging on entry would let a
// user who mistypes their password exhaust the budget without a single message
// leaving the system.
//
// The budget is in-memory, so it resets on restart and each replica keeps its
// own. That is a deliberate trade for a mitigation with no schema change: it
// removes the unbounded primitive without a migration, but it is a bound on
// convenience rather than a hard guarantee. The complete fix is to stop
// attaching an unverified address to the account at all -- hold it pending and
// apply it when the link is clicked -- which also closes address squatting.
func (s *Server) allowVerificationMail(userID uuid.UUID) bool {
	if s.verificationMailStore == nil {
		return true
	}
	limiter := s.verificationMailStore.getLimiter(
		userID.String(),
		rateEvery(verificationMailInterval),
		verificationMailBurst,
	)
	if !limiter.Allow() {
		log.Printf("allowVerificationMail: verification mail budget exhausted for user %s", userID)
		return false
	}
	return true
}
