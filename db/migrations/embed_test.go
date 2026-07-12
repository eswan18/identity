package migrations

import "testing"

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
