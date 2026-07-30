package migrations

import (
	"errors"
	"io"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/golang-migrate/migrate/v4/source/iofs"
)

func TestLatestVersion(t *testing.T) {
	v, err := LatestVersion()
	if err != nil {
		t.Fatalf("LatestVersion() error: %v", err)
	}
	// Bump the floor when you add migrations. The important guard is that this
	// never silently returns 0 (which would make Verify accept an empty DB as
	// "up to date").
	if v < 11 {
		t.Errorf("LatestVersion() = %d, want >= 11 (embed matched too few files?)", v)
	}
}

// TestLatestVersionIgnoresDownMigrations pins that the startup check's notion
// of "latest" is decided by version prefixes alone. The embed matches only
// *.up.sql today; if it is ever widened (e.g. to *.sql, which would pull in the
// eleven *.down.sql files sitting in the same directory), LatestVersion — and
// therefore Verify, which compares against it — must return exactly the same
// number.
func TestLatestVersionIgnoresDownMigrations(t *testing.T) {
	upOnly := fstest.MapFS{
		"000001_init.up.sql":         {},
		"000002_add_audience.up.sql": {},
	}
	withDowns := fstest.MapFS{
		"000001_init.up.sql":           {},
		"000001_init.down.sql":         {},
		"000002_add_audience.up.sql":   {},
		"000002_add_audience.down.sql": {},
	}

	upOnlyVersion, err := latestVersionIn(upOnly)
	if err != nil {
		t.Fatalf("latestVersionIn(up-only) error: %v", err)
	}
	withDownsVersion, err := latestVersionIn(withDowns)
	if err != nil {
		t.Fatalf("latestVersionIn(with downs) error: %v", err)
	}
	if upOnlyVersion != 2 {
		t.Errorf("latestVersionIn(up-only) = %d, want 2", upOnlyVersion)
	}
	if withDownsVersion != upOnlyVersion {
		t.Errorf("latestVersionIn(with downs) = %d, want %d (down files must not change the answer)",
			withDownsVersion, upOnlyVersion)
	}
}

// TestEmbeddedSourceEnumeratesEveryVersion checks what golang-migrate's iofs
// source actually sees in the embedded FS, which is what Up walks to decide
// which migrations to apply. It enumerates 1..LatestVersion contiguously and
// can read the body of each — with only *.up.sql embedded, which is what
// answers the "do we also need to embed the down files?" question: iofs indexes
// a version from a file in either direction, and the up path only ever calls
// ReadUp, so up-only is enough.
func TestEmbeddedSourceEnumeratesEveryVersion(t *testing.T) {
	latest, err := LatestVersion()
	if err != nil {
		t.Fatalf("LatestVersion() error: %v", err)
	}

	src, err := iofs.New(upFiles, ".")
	if err != nil {
		t.Fatalf("iofs.New over embedded migrations: %v", err)
	}
	defer src.Close()

	version, err := src.First()
	if err != nil {
		t.Fatalf("First(): %v", err)
	}

	var seen []uint
	for {
		seen = append(seen, version)

		body, identifier, err := src.ReadUp(version)
		if err != nil {
			t.Fatalf("ReadUp(%d): %v", version, err)
		}
		content, err := io.ReadAll(body)
		body.Close()
		if err != nil {
			t.Fatalf("reading up migration %d (%s): %v", version, identifier, err)
		}
		if len(content) == 0 {
			t.Errorf("up migration %d (%s) is empty", version, identifier)
		}

		next, err := src.Next(version)
		if errors.Is(err, fs.ErrNotExist) {
			break
		}
		if err != nil {
			t.Fatalf("Next(%d): %v", version, err)
		}
		version = next
	}

	if len(seen) != latest {
		t.Fatalf("iofs enumerated %d versions (%v), want %d to match LatestVersion",
			len(seen), seen, latest)
	}
	for i, v := range seen {
		if v != uint(i+1) {
			t.Fatalf("iofs enumerated versions %v, want a contiguous 1..%d", seen, latest)
		}
	}
}
