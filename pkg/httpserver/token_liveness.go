package httpserver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/eswan18/identity/pkg/db"
)

// liveAccessToken looks up the oauth_tokens row for an access token's JTI and
// reports whether that token is still live.
//
// Why this lookup exists at all: an access token is a self-contained JWT, so
// signature, issuer and expiry are all verifiable without touching the database.
// Revocation is not. This row is the only thing that knows a token has been
// revoked, and GetTokenByAccessToken's query filters out rows that are revoked
// or past expires_at -- so "no row" means the token must be refused.
//
// The contract callers must honour:
//
//   - err != nil means the check could not be performed. It is NOT permission to
//     continue. Callers MUST fail closed, because "I could not determine whether
//     this token was revoked" and "this token was not revoked" are different
//     facts and only one of them is safe to act on.
//   - found == false means the token is revoked, expired, or was never issued.
//     Refuse it.
//
// This exists because the three call sites had drifted. UserInfo and
// introspection failed closed on a database error; AdminAuthMiddleware -- the
// most privileged of the three -- explicitly allowed the request through,
// skipping revocation entirely. Sharing the lookup makes the fail-closed
// behaviour a property of the helper rather than something each caller has to
// remember, and gives a new caller one obvious thing to call.
//
// An empty jti is treated as not-live rather than skipped. Every token this
// service issues carries one (see the generators in pkg/jwt), so an empty jti on
// a validly-signed token is not a case that can legitimately arise; two of the
// three call sites previously skipped the revocation check entirely when it was
// empty, which is the wrong direction to guess in.
func (s *Server) liveAccessToken(ctx context.Context, jti string) (token db.OauthToken, found bool, err error) {
	if jti == "" {
		return db.OauthToken{}, false, nil
	}
	token, err = s.datastore.Q.GetTokenByAccessToken(ctx, sql.NullString{String: jti, Valid: true})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return db.OauthToken{}, false, nil
		}
		return db.OauthToken{}, false, fmt.Errorf("liveAccessToken: could not check revocation for jti: %w", err)
	}
	return token, true, nil
}
