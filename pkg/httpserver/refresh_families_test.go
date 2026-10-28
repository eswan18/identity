package httpserver

import (
	"database/sql"
	"testing"
	"time"

	"github.com/eswan18/identity/pkg/db"
	"github.com/google/uuid"
)

func TestNewFamilyIDStartsNow(t *testing.T) {
	before := time.Now().Truncate(time.Millisecond)
	family, err := newFamilyID()
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now()

	started, ok := familyStartedAt(family)
	if !ok {
		t.Fatalf("a new family id must be a UUIDv7, got version %d", family.Version())
	}
	if started.Before(before) || started.After(after) {
		t.Errorf("family started at %v, want between %v and %v", started, before, after)
	}
}

// A token minted before families existed gets a family derived from itself, so
// that two concurrent refreshes of it agree on the family (the loser of the
// rotation must revoke the family the winner minted into), and whose start is
// the token's creation time.
func TestLegacyFamilyID(t *testing.T) {
	tokenID := uuid.New()
	createdAt := time.Date(2026, 7, 4, 12, 30, 15, 123456789, time.UTC)

	family := legacyFamilyID(tokenID, createdAt)

	if again := legacyFamilyID(tokenID, createdAt); again != family {
		t.Errorf("legacyFamilyID is not deterministic: %s then %s", family, again)
	}
	if family.Version() != 7 {
		t.Errorf("version = %d, want 7", family.Version())
	}
	if family.Variant() != uuid.RFC4122 {
		t.Errorf("variant = %v, want RFC 4122/9562", family.Variant())
	}
	started, ok := familyStartedAt(family)
	if !ok || !started.Equal(createdAt.Truncate(time.Millisecond)) {
		t.Errorf("familyStartedAt = %v, %v; want %v", started, ok, createdAt.Truncate(time.Millisecond))
	}
	if family == tokenID {
		t.Error("the family id must not be the token id itself")
	}
	if other := legacyFamilyID(uuid.New(), createdAt); other == family {
		t.Error("two old tokens created in the same millisecond must not share a family")
	}
}

func TestFamilyExpired(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	family := legacyFamilyID(uuid.New(), start)

	cases := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"just started", start, false},
		{"a millisecond before the limit", start.Add(familyMaxLifetime - time.Millisecond), false},
		{"at the limit", start.Add(familyMaxLifetime), true},
		{"well past it", start.Add(familyMaxLifetime + 24*time.Hour), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := familyExpired(family, c.now); got != c.want {
				t.Errorf("familyExpired = %v, want %v", got, c.want)
			}
		})
	}

	// Its age cannot be read, so it cannot be shown to be within the limit.
	if !familyExpired(uuid.New(), start) {
		t.Error("a family id that is not a UUIDv7 must count as expired")
	}
}

func TestRefreshTokenExpiryIsCappedByFamily(t *testing.T) {
	now := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)

	fresh := legacyFamilyID(uuid.New(), now)
	if got, want := refreshTokenExpiry(fresh, now), now.Add(refreshTokenExpiresIn); !got.Equal(want) {
		t.Errorf("fresh family: expiry %v, want %v", got, want)
	}

	start := now.Add(-80 * 24 * time.Hour)
	old := legacyFamilyID(uuid.New(), start)
	if got, want := refreshTokenExpiry(old, now), start.Add(familyMaxLifetime); !got.Equal(want) {
		t.Errorf("80-day-old family: expiry %v, want the family's end %v", got, want)
	}
}

func TestIsRotated(t *testing.T) {
	revokedAt := sql.NullTime{Time: time.Now(), Valid: true}
	reason := func(r string) sql.NullString { return sql.NullString{String: r, Valid: true} }

	cases := []struct {
		name  string
		token db.OauthToken
		want  bool
	}{
		{"live", db.OauthToken{}, false},
		{"rotated", db.OauthToken{RevokedAt: revokedAt, RevokedReason: reason("rotated")}, true},
		{"revoked at /oauth/revoke", db.OauthToken{RevokedAt: revokedAt, RevokedReason: reason("revoked")}, false},
		{"logout", db.OauthToken{RevokedAt: revokedAt, RevokedReason: reason("logout")}, false},
		{"admin", db.OauthToken{RevokedAt: revokedAt, RevokedReason: reason("admin")}, false},
		{"already revoked for reuse", db.OauthToken{RevokedAt: revokedAt, RevokedReason: reason("reuse_detected")}, false},
		{"revoked before reasons were recorded", db.OauthToken{RevokedAt: revokedAt}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isRotated(c.token); got != c.want {
				t.Errorf("isRotated = %v, want %v", got, c.want)
			}
		})
	}
}
