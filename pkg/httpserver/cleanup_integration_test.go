//go:build integration

package httpserver

import (
	"database/sql"
	"time"

	"github.com/eswan18/identity/pkg/db"
	"github.com/google/uuid"
)

// TestExpiryCleanup_DeletesExpiredRows is an end-to-end (real Postgres, via the shared
// OAuthFlowSuite testcontainer) check that runExpiryCleanup actually deletes rows past
// their expires_at, for one row in each of the four tables it originally targeted. The
// hermetic unit test in cleanup_test.go covers the loop/scheduling behavior without a
// database; this covers the SQL side, which the queries themselves already tested
// (they're plain generated sqlc :exec statements) but which was never wired up to
// anything before this change.
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

// TestExpiryCleanup_DeletesExpiredSessions covers the auth_sessions sweep
// (DeleteExpiredSessions): a session past its expires_at is deleted, while one that
// hasn't expired yet survives -- proving the sweep doesn't over-delete.
func (s *OAuthFlowSuite) TestExpiryCleanup_DeletesExpiredSessions() {
	ctx := s.T().Context()
	user := s.mustRegisterUser(
		s.mustGenerateAlphanumericString(10),
		s.mustGenerateAlphanumericString(10),
		s.mustGenerateAlphanumericString(10)+"@example.com",
	)

	past := time.Now().Add(-1 * time.Hour)
	future := time.Now().Add(1 * time.Hour)

	expiredSessionID := s.mustGenerateAlphanumericString(20)
	err := s.datastore.Q.CreateSession(ctx, db.CreateSessionParams{
		ID:        expiredSessionID,
		UserID:    user.ID,
		ExpiresAt: past,
	})
	s.Require().NoError(err)

	activeSessionID := s.mustGenerateAlphanumericString(20)
	err = s.datastore.Q.CreateSession(ctx, db.CreateSessionParams{
		ID:        activeSessionID,
		UserID:    user.ID,
		ExpiresAt: future,
	})
	s.Require().NoError(err)

	s.assertRowCount("auth_sessions", "id = $1", expiredSessionID, 1)
	s.assertRowCount("auth_sessions", "id = $1", activeSessionID, 1)

	err = s.server.runExpiryCleanup(ctx)
	s.NoError(err)

	s.assertRowCount("auth_sessions", "id = $1", expiredSessionID, 0)
	s.assertRowCount("auth_sessions", "id = $1", activeSessionID, 1)
}

// TestExpiryCleanup_DeletesDeadAuthorizationCodes covers the oauth_authorization_codes
// sweep (DeleteExpiredAuthorizationCodes): an expired code and a consumed-but-not-expired
// code are both deleted (neither can ever yield tokens again), while a fresh, unconsumed,
// non-expired code survives.
func (s *OAuthFlowSuite) TestExpiryCleanup_DeletesDeadAuthorizationCodes() {
	ctx := s.T().Context()
	user := s.mustRegisterUser(
		s.mustGenerateAlphanumericString(10),
		s.mustGenerateAlphanumericString(10),
		s.mustGenerateAlphanumericString(10)+"@example.com",
	)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateAlphanumericString(12),
		Name:           "cleanup-test-client",
		RedirectUris:   []string{"http://example.com/callback"},
		AllowedScopes:  []string{"openid"},
		IsConfidential: false,
		Audience:       "test-audience",
	})

	past := time.Now().Add(-1 * time.Hour)
	future := time.Now().Add(1 * time.Hour)

	// Expired, unconsumed.
	expiredCode := s.mustGenerateAlphanumericString(32)
	err := s.datastore.Q.InsertAuthorizationCode(ctx, db.InsertAuthorizationCodeParams{
		Code:        expiredCode,
		UserID:      user.ID,
		ClientID:    client.ID,
		RedirectUri: "http://example.com/callback",
		Scope:       []string{"openid"},
		ExpiresAt:   past,
	})
	s.Require().NoError(err)

	// Not expired, but consumed.
	consumedCode := s.mustGenerateAlphanumericString(32)
	err = s.datastore.Q.InsertAuthorizationCode(ctx, db.InsertAuthorizationCodeParams{
		Code:        consumedCode,
		UserID:      user.ID,
		ClientID:    client.ID,
		RedirectUri: "http://example.com/callback",
		Scope:       []string{"openid"},
		ExpiresAt:   future,
	})
	s.Require().NoError(err)
	rows, err := s.datastore.Q.ConsumeAuthorizationCode(ctx, consumedCode)
	s.Require().NoError(err)
	s.Require().Equal(int64(1), rows)

	// Fresh, unconsumed, not expired -- must survive.
	freshCode := s.mustGenerateAlphanumericString(32)
	err = s.datastore.Q.InsertAuthorizationCode(ctx, db.InsertAuthorizationCodeParams{
		Code:        freshCode,
		UserID:      user.ID,
		ClientID:    client.ID,
		RedirectUri: "http://example.com/callback",
		Scope:       []string{"openid"},
		ExpiresAt:   future,
	})
	s.Require().NoError(err)

	s.assertRowCount("oauth_authorization_codes", "code = $1", expiredCode, 1)
	s.assertRowCount("oauth_authorization_codes", "code = $1", consumedCode, 1)
	s.assertRowCount("oauth_authorization_codes", "code = $1", freshCode, 1)

	err = s.server.runExpiryCleanup(ctx)
	s.NoError(err)

	s.assertRowCount("oauth_authorization_codes", "code = $1", expiredCode, 0)
	s.assertRowCount("oauth_authorization_codes", "code = $1", consumedCode, 0)
	s.assertRowCount("oauth_authorization_codes", "code = $1", freshCode, 1)
}

// TestExpiryCleanup_DeletesDeadTokensOnly covers the oauth_tokens sweep
// (DeleteDeadTokens), which is the most delicate one: each row holds both an access
// token (expires_at) and a refresh token (refresh_expires_at, which is NULLable --
// NULL means the refresh token never expires). This asserts the refresh-token caveat
// is honored: a row is deleted only once it can never be used again (revoked, or both
// the access and refresh tokens have expired); a row whose refresh token is still
// valid, or non-expiring, must survive even though its access token has expired.
func (s *OAuthFlowSuite) TestExpiryCleanup_DeletesDeadTokensOnly() {
	ctx := s.T().Context()
	user := s.mustRegisterUser(
		s.mustGenerateAlphanumericString(10),
		s.mustGenerateAlphanumericString(10),
		s.mustGenerateAlphanumericString(10)+"@example.com",
	)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateAlphanumericString(12),
		Name:           "cleanup-test-client",
		RedirectUris:   []string{"http://example.com/callback"},
		AllowedScopes:  []string{"openid"},
		IsConfidential: false,
		Audience:       "test-audience",
	})
	userID := uuid.NullUUID{UUID: user.ID, Valid: true}

	past := time.Now().Add(-1 * time.Hour)
	future := time.Now().Add(1 * time.Hour)

	insert := func(refreshExpiresAt sql.NullTime) db.OauthToken {
		tok, err := s.datastore.Q.InsertToken(ctx, db.InsertTokenParams{
			AccessToken:      sql.NullString{String: s.mustGenerateAlphanumericString(32), Valid: true},
			RefreshToken:     sql.NullString{String: s.mustGenerateAlphanumericString(32), Valid: true},
			UserID:           userID,
			ClientID:         client.ID,
			Scope:            []string{"openid"},
			ExpiresAt:        past,
			RefreshExpiresAt: refreshExpiresAt,
		})
		s.Require().NoError(err)
		return tok
	}

	// (a) Revoked -- must be deleted regardless of expiry.
	revoked, err := s.datastore.Q.InsertToken(ctx, db.InsertTokenParams{
		AccessToken:      sql.NullString{String: s.mustGenerateAlphanumericString(32), Valid: true},
		RefreshToken:     sql.NullString{String: s.mustGenerateAlphanumericString(32), Valid: true},
		UserID:           userID,
		ClientID:         client.ID,
		Scope:            []string{"openid"},
		ExpiresAt:        future,
		RefreshExpiresAt: sql.NullTime{Time: future, Valid: true},
	})
	s.Require().NoError(err)
	err = s.datastore.Q.RevokeTokenByAccessToken(ctx, revoked.AccessToken)
	s.Require().NoError(err)

	// (b) Access expired AND refresh expired -- dead, must be deleted.
	bothExpired := insert(sql.NullTime{Time: past, Valid: true})

	// (c) Access expired but refresh still valid (future) -- must survive.
	refreshStillValid := insert(sql.NullTime{Time: future, Valid: true})

	// (d) Access expired but refresh_expires_at is NULL (non-expiring refresh),
	// not revoked -- must survive.
	refreshNonExpiring := insert(sql.NullTime{Valid: false})

	// (e) Fully valid (access not expired either) -- must survive.
	fullyValid, err := s.datastore.Q.InsertToken(ctx, db.InsertTokenParams{
		AccessToken:      sql.NullString{String: s.mustGenerateAlphanumericString(32), Valid: true},
		RefreshToken:     sql.NullString{String: s.mustGenerateAlphanumericString(32), Valid: true},
		UserID:           userID,
		ClientID:         client.ID,
		Scope:            []string{"openid"},
		ExpiresAt:        future,
		RefreshExpiresAt: sql.NullTime{Time: future, Valid: true},
	})
	s.Require().NoError(err)

	s.assertRowCount("oauth_tokens", "id = $1", revoked.ID, 1)
	s.assertRowCount("oauth_tokens", "id = $1", bothExpired.ID, 1)
	s.assertRowCount("oauth_tokens", "id = $1", refreshStillValid.ID, 1)
	s.assertRowCount("oauth_tokens", "id = $1", refreshNonExpiring.ID, 1)
	s.assertRowCount("oauth_tokens", "id = $1", fullyValid.ID, 1)

	err = s.server.runExpiryCleanup(ctx)
	s.NoError(err)

	s.assertRowCount("oauth_tokens", "id = $1", revoked.ID, 0)
	s.assertRowCount("oauth_tokens", "id = $1", bothExpired.ID, 0)
	s.assertRowCount("oauth_tokens", "id = $1", refreshStillValid.ID, 1)
	s.assertRowCount("oauth_tokens", "id = $1", refreshNonExpiring.ID, 1)
	s.assertRowCount("oauth_tokens", "id = $1", fullyValid.ID, 1)
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
