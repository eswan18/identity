package httpserver

import (
	"context"
	"database/sql"
	"encoding/binary"
	"log"
	"net/http"
	"time"

	"github.com/eswan18/identity/pkg/db"
	"github.com/google/uuid"
)

// Refresh-token families and reuse detection (issue #144; spec
// docs/superpowers/specs/2026-10-27-resource-indicators-and-mcp-clients-design.md
// §10, RFC 9700 §4.14.2).
//
// A family is the lineage of tokens descended from one sign-in: the code
// exchange starts it, and every refresh mints its replacement into the same
// family (oauth_tokens.family_id). Refresh tokens rotate, so a family has one
// live refresh token at a time. A spent one turning up again means two parties
// hold it and one is probably a thief; identity cannot tell which, so it
// revokes the whole family and both sign in again.
//
// Each revocation records why (oauth_tokens.revoked_reason), because only a
// token that was spent by a refresh -- revokedRotated -- is evidence of reuse.
// One revoked by logout or /oauth/revoke is simply dead.

// revocationReason is what oauth_tokens.revoked_reason records. Rows revoked
// before reasons were recorded have NULL, which counts as none of these: a
// replay of one is refused without revoking anything else.
type revocationReason string

const (
	// revokedRotated: spent by a refresh, which minted its replacement.
	revokedRotated revocationReason = "rotated"
	// revokedReuseDetected: in a family where a rotated refresh token was
	// presented again.
	revokedReuseDetected revocationReason = "reuse_detected"
	// revokedLogout: the user was signed out everywhere (password change or
	// reset, account deactivation).
	revokedLogout revocationReason = "logout"
	// revokedRevoked: revoked by its client at /oauth/revoke (RFC 7009).
	revokedRevoked revocationReason = "revoked"
	// revokedAdmin: revoked by an administrator. Nothing revokes tokens from an
	// admin path yet; one that does records this.
	revokedAdmin revocationReason = "admin"
	// revokedUserDisconnected: the user disconnected the client from their
	// account on the connected-apps page (connected_apps.go).
	revokedUserDisconnected revocationReason = "user_disconnected"
)

// familyMaxLifetime caps a family: however regularly it is refreshed, it cannot
// be refreshed past this long after the sign-in that started it, so a stolen
// but diligently refreshed chain still ends.
const familyMaxLifetime = 90 * 24 * time.Hour

// newFamilyID starts a family, at the code exchange.
//
// Family ids are UUIDv7, whose first 48 bits are the creation time in Unix
// milliseconds. That is where a family's start (for familyMaxLifetime) is kept:
// the first token of a family is spent by its first refresh and deleted by the
// cleanup sweep within the month, so no row can be relied on to remember when
// the family began, and the id is carried on every row of it.
func newFamilyID() (uuid.UUID, error) {
	return uuid.NewV7()
}

// tokenFamily is the family a refresh of token continues: its own, or, for a
// token minted before families existed (NULL family_id), one derived from the
// token itself (legacyFamilyID). RotateRefreshToken writes that onto the old
// row as it spends it, so the lineage is tracked from then on.
func tokenFamily(token db.OauthToken) uuid.UUID {
	if token.FamilyID.Valid {
		return token.FamilyID.UUID
	}
	return legacyFamilyID(token.ID, token.CreatedAt)
}

// legacyFamilyID is the family of a token minted before families existed: a
// UUIDv7 stamped with the token's creation time (that is as far back as its
// lineage can be known, so its familyMaxLifetime runs from there) whose random
// bits are the token's own id's.
//
// It is deterministic on purpose. Two concurrent refreshes of the same old
// token must mint into the same family, or the one that loses the rotation
// race would revoke a family the winner's tokens are not in (see
// handleRefreshTokenGrant).
func legacyFamilyID(tokenID uuid.UUID, createdAt time.Time) uuid.UUID {
	family := tokenID
	var ms [8]byte
	binary.BigEndian.PutUint64(ms[:], uint64(createdAt.UnixMilli()))
	copy(family[0:6], ms[2:8])
	family[6] = (family[6] & 0x0f) | 0x70 // version 7
	family[8] = (family[8] & 0x3f) | 0x80 // RFC 9562 variant
	return family
}

// familyStartedAt is when family began: its UUIDv7 timestamp. ok is false for
// an id that is not a UUIDv7, which this code never writes.
func familyStartedAt(family uuid.UUID) (started time.Time, ok bool) {
	if family.Version() != 7 {
		return time.Time{}, false
	}
	var ms [8]byte
	copy(ms[2:8], family[0:6])
	return time.UnixMilli(int64(binary.BigEndian.Uint64(ms[:]))), true
}

// familyExpired reports whether family is past familyMaxLifetime at now. A
// family whose start cannot be read is treated as expired: its age cannot be
// shown to be within the limit.
func familyExpired(family uuid.UUID, now time.Time) bool {
	started, ok := familyStartedAt(family)
	if !ok {
		return true
	}
	return !now.Before(started.Add(familyMaxLifetime))
}

// refreshTokenExpiry is when a refresh token minted at now into family
// expires: refreshTokenExpiresIn from now, but never past the family's end, so
// what the row (and introspection's exp) says is when the token really stops
// working.
func refreshTokenExpiry(family uuid.UUID, now time.Time) time.Time {
	expiry := now.Add(refreshTokenExpiresIn)
	if started, ok := familyStartedAt(family); ok {
		if end := started.Add(familyMaxLifetime); end.Before(expiry) {
			expiry = end
		}
	}
	return expiry
}

// isRotated reports whether token was revoked by being spent on a refresh --
// the one way of dying that makes presenting it again a replay.
func isRotated(token db.OauthToken) bool {
	return token.RevokedAt.Valid && token.RevokedReason.Valid &&
		token.RevokedReason.String == string(revokedRotated)
}

// refuseRevokedRefreshToken answers a refresh grant presenting token, which is
// already revoked. Every answer is invalid_grant; what differs is whether the
// family goes too.
//
// Rotated: this is reuse. Every live token in the family is revoked -- the
// current refresh token and its access token included, whoever holds them --
// and it is logged. Revoked any other way (or before reasons were recorded):
// the token is just dead, and nothing else is touched.
func (s *Server) refuseRevokedRefreshToken(ctx context.Context, w http.ResponseWriter, client db.OauthClient, token db.OauthToken) {
	if !isRotated(token) {
		s.writeTokenError(w, "invalid_grant", "Refresh token has been revoked")
		return
	}
	s.revokeFamilyForReuse(ctx, client, token.UserID, tokenFamily(token))
	s.writeTokenError(w, "invalid_grant",
		"Refresh token has already been used; every token issued from it has been revoked")
}

// revokeFamilyForReuse revokes every live token in family after a rotated
// refresh token from it was presented again, and logs it. It never logs a token.
//
// A failure is logged and otherwise swallowed: the grant is refused either way
// (the presented token is dead whatever happens here), and invalid_grant is
// still the truthful answer.
func (s *Server) revokeFamilyForReuse(ctx context.Context, client db.OauthClient, userID uuid.NullUUID, family uuid.UUID) {
	user := "none"
	if userID.Valid {
		user = userID.UUID.String()
	}
	revoked, err := s.datastore.Q.RevokeTokenFamily(ctx, db.RevokeTokenFamilyParams{
		FamilyID: family,
		Reason:   string(revokedReuseDetected),
	})
	if err != nil {
		log.Printf("[ERROR] refresh token reuse: client %s, user %s, family %s: failed to revoke the family: %v",
			client.ClientID, user, family, err)
		return
	}
	log.Printf("[WARN] refresh token reuse: client %s, user %s, family %s: a rotated refresh token was presented again; revoked %d live token(s) in the family",
		client.ClientID, user, family, revoked)
}

// refuseLostRotation answers a refresh that minted its replacement tokens
// (unissued, never sent) and then found the presented token already spent:
// someone revoked it between this request's lookup and its rotation.
//
// It looks again to see how. Rotated means a concurrent refresh of the same
// token won, which is reuse, and the family is revoked -- the winner's freshly
// minted tokens and the unissued ones alike, since all are in the same family
// (see handleRefreshTokenGrant for why the winner's are certain to be visible
// here). Otherwise (logout or /oauth/revoke landed mid-request) only the
// unissued tokens are revoked, for the same reason as the presented one.
func (s *Server) refuseLostRotation(ctx context.Context, w http.ResponseWriter, client db.OauthClient, presented, unissued string) {
	spent, err := s.datastore.Q.GetTokenByRefreshTokenIncludingRevoked(ctx, sql.NullString{String: presented, Valid: true})
	if err != nil {
		log.Printf("[ERROR] handleRefreshTokenGrant: client %s: lost a rotation and could not look again at how the token was spent: %v",
			client.ClientID, err)
	}
	if err == nil && isRotated(spent) {
		s.refuseRevokedRefreshToken(ctx, w, client, spent)
		return
	}

	reason := revokedRevoked
	if err == nil && spent.RevokedReason.Valid {
		reason = revocationReason(spent.RevokedReason.String)
	}
	if _, revokeErr := s.datastore.Q.RevokeTokenByRefreshToken(ctx, db.RevokeTokenByRefreshTokenParams{
		RefreshToken: sql.NullString{String: unissued, Valid: true},
		Reason:       string(reason),
	}); revokeErr != nil {
		log.Printf("[ERROR] handleRefreshTokenGrant: client %s: failed to revoke unissued tokens after losing a rotation: %v",
			client.ClientID, revokeErr)
	}
	s.writeTokenError(w, "invalid_grant", "Refresh token has been revoked")
}
