//go:build integration

package httpserver

import (
	"time"

	"github.com/eswan18/identity/pkg/db"
)

// TestExpiryCleanup_DeletesExpiredRows is an end-to-end (real Postgres, via the shared
// OAuthFlowSuite testcontainer) check that runExpiryCleanup actually deletes rows past
// their expires_at, for one row in each of the four tables it targets. The hermetic unit
// test in cleanup_test.go covers the loop/scheduling behavior without a database; this
// covers the SQL side, which the queries themselves already tested (they're plain
// generated sqlc :exec statements) but which was never wired up to anything before this
// change.
func (s *OAuthFlowSuite) TestExpiryCleanup_DeletesExpiredRows() {
	ctx := s.T().Context()
	user := s.mustRegisterUser(
		s.mustGenerateAlphanumericString(10),
		s.mustGenerateAlphanumericString(10),
		s.mustGenerateAlphanumericString(10)+"@example.com",
	)

	past := time.Now().Add(-1 * time.Hour)

	// auth_mfa_pending
	mfaPendingID := s.mustGenerateAlphanumericString(20)
	err := s.datastore.Q.CreateMFAPending(ctx, db.CreateMFAPendingParams{
		ID:        mfaPendingID,
		UserID:    user.ID,
		ExpiresAt: past,
	})
	s.Require().NoError(err)

	// auth_mfa_enrollment_pending
	err = s.datastore.Q.CreateMFAEnrollmentPending(ctx, db.CreateMFAEnrollmentPendingParams{
		UserID:    user.ID,
		Secret:    "JBSWY3DPEHPK3PXP",
		ExpiresAt: past,
	})
	s.Require().NoError(err)

	// auth_email_tokens (a non-password-reset token type, e.g. email verification)
	err = s.datastore.Q.CreateEmailToken(ctx, db.CreateEmailTokenParams{
		UserID:    user.ID,
		TokenHash: s.mustGenerateAlphanumericString(32),
		TokenType: "email_verification",
		ExpiresAt: past,
	})
	s.Require().NoError(err)

	// auth_email_tokens with token_type = 'password_reset', which
	// DeleteExpiredPasswordResetTokens specifically targets.
	err = s.datastore.Q.CreatePasswordResetToken(ctx, db.CreatePasswordResetTokenParams{
		UserID:    user.ID,
		TokenHash: s.mustGenerateAlphanumericString(32),
		ExpiresAt: past,
	})
	s.Require().NoError(err)

	s.assertRowCount("auth_mfa_pending", "id = $1", mfaPendingID, 1)
	s.assertRowCount("auth_mfa_enrollment_pending", "user_id = $1", user.ID, 1)
	s.assertRowCount("auth_email_tokens", "user_id = $1", user.ID, 2)

	err = s.server.runExpiryCleanup(ctx)
	s.NoError(err)

	s.assertRowCount("auth_mfa_pending", "id = $1", mfaPendingID, 0)
	s.assertRowCount("auth_mfa_enrollment_pending", "user_id = $1", user.ID, 0)
	s.assertRowCount("auth_email_tokens", "user_id = $1", user.ID, 0)
}

// assertRowCount asserts that exactly want rows in table match "WHERE " + whereClause
// (with arg as $1). It's a small raw-SQL helper since sqlc doesn't generate ad hoc count
// queries and adding one purely for this test isn't warranted.
func (s *OAuthFlowSuite) assertRowCount(table, whereClause string, arg any, want int) {
	s.T().Helper()
	var got int
	query := "SELECT COUNT(*) FROM " + table + " WHERE " + whereClause
	err := s.datastore.DB.QueryRowContext(s.T().Context(), query, arg).Scan(&got)
	s.Require().NoError(err)
	s.Equal(want, got, "unexpected row count in %s", table)
}
