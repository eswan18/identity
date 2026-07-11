package httpserver

import (
	"context"
	"log"
	"time"
)

// fallbackCleanupInterval is used if Server.config.CleanupInterval is unset
// (zero), e.g. when a Config is constructed directly as a struct literal (as
// integration tests do) instead of via config.NewFromEnv, which always
// populates it. A zero interval would make time.NewTicker panic, so
// startCleanupWorker substitutes this instead. It mirrors the default applied
// by config.NewFromEnv itself.
const fallbackCleanupInterval = 1 * time.Hour

// cleanupSweepTimeout bounds a single expiry-cleanup sweep (see
// runExpiryCleanup) so that a hung database call can't block the worker -- and
// therefore delay process shutdown -- forever.
const cleanupSweepTimeout = 30 * time.Second

// runExpiryCleanup performs one sweep of the expired-row cleanup queries for
// the auth tables that accumulate short-lived, single-use records:
//
//   - auth_mfa_pending (DeleteExpiredMFAPending)
//   - auth_mfa_enrollment_pending (DeleteExpiredMFAEnrollmentPending)
//   - auth_email_tokens (DeleteExpiredEmailTokens)
//   - auth_email_tokens, password-reset rows specifically (DeleteExpiredPasswordResetTokens)
//
// These queries already existed but were never called anywhere, so expired
// rows accumulated in their tables forever (unbounded growth, not a
// correctness bug -- the read queries all filter on expires_at, so expired
// rows were never usable).
//
// Deliberately NOT covered here: oauth_tokens, auth_sessions, and
// oauth_authorization_codes also have expires_at and will accumulate rows
// over time, but there is no DeleteExpired* query for them yet (and, for
// oauth_tokens, retention may need extra thought, e.g. keeping revoked/expired
// tokens around briefly for auditing). That's left as a conscious follow-up,
// not an oversight.
//
// Each of the four deletes is independent: if one fails, it is logged and the
// remaining three still run rather than bailing out early. The sweep is
// bounded by cleanupSweepTimeout so a hung DB call can't block the worker
// indefinitely. The return value is the last error encountered (nil if all
// four succeeded); callers mainly care that the sweep ran; the operational
// signal is the [ERROR] log line, not this return value.
func (s *Server) runExpiryCleanup(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, cleanupSweepTimeout)
	defer cancel()

	sweeps := []struct {
		table string
		fn    func(context.Context) error
	}{
		{"auth_mfa_pending", s.datastore.Q.DeleteExpiredMFAPending},
		{"auth_mfa_enrollment_pending", s.datastore.Q.DeleteExpiredMFAEnrollmentPending},
		{"auth_email_tokens", s.datastore.Q.DeleteExpiredEmailTokens},
		{"auth_email_tokens (password_reset)", s.datastore.Q.DeleteExpiredPasswordResetTokens},
	}

	var lastErr error
	for _, sw := range sweeps {
		if err := sw.fn(ctx); err != nil {
			log.Printf("[ERROR] expiry cleanup: failed to delete expired rows from %s: %v", sw.table, err)
			lastErr = err
			continue
		}
	}

	s.debugf("expiry cleanup sweep completed")
	return lastErr
}

// startCleanupWorker is the goroutine body that periodically runs
// runExpiryCleanup. It is intended to be launched with `go s.startCleanupWorker(ctx)`
// from Server.Run (never from New, so constructing a Server in tests does not
// spawn background work), and stops as soon as ctx is cancelled.
//
// The actual loop mechanics live in cleanupLoop below so they can be tested
// hermetically (no database) with a fake sweep function and a short interval.
func (s *Server) startCleanupWorker(ctx context.Context) {
	interval := effectiveCleanupInterval(s.config.CleanupInterval)
	cleanupLoop(ctx, interval, func(sweepCtx context.Context) {
		s.runExpiryCleanup(sweepCtx)
	})
}

// effectiveCleanupInterval returns interval, unless it is zero or negative (e.g.
// because config.CleanupInterval was left at its zero value, as happens when a
// Config is built as a struct literal in tests instead of via
// config.NewFromEnv, which always populates it), in which case it returns
// fallbackCleanupInterval. This guards against ever passing a non-positive
// duration to time.NewTicker, which panics.
func effectiveCleanupInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return fallbackCleanupInterval
	}
	return interval
}

// cleanupLoop runs sweep once immediately (so cleanup starts shortly after
// the worker is launched rather than waiting a full interval for the first
// run), then again every time the interval elapses, until ctx.Done() fires.
// The ticker is always stopped before returning.
//
// It is factored out from startCleanupWorker purely for testability: unit
// tests can call cleanupLoop directly with a fake sweep function and a short
// interval/context to verify the loop's timing and shutdown behavior without
// touching a real database.
func cleanupLoop(ctx context.Context, interval time.Duration, sweep func(context.Context)) {
	sweep(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep(ctx)
		}
	}
}
