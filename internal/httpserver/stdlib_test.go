package httpserver

import "testing"

func TestContainsAll(t *testing.T) {
	tests := []struct {
		name     string
		haystack []string
		needles  []string
		want     bool
	}{
		{
			name:     "all needles present",
			haystack: []string{"a", "b", "c", "d"},
			needles:  []string{"a", "c"},
			want:     true,
		},
		{
			name:     "some needles missing",
			haystack: []string{"a", "b", "c"},
			needles:  []string{"a", "d"},
			want:     false,
		},
		{
			name:     "empty needles",
			haystack: []string{"a", "b", "c"},
			needles:  []string{},
			want:     true,
		},
		{
			name:     "empty haystack",
			haystack: []string{},
			needles:  []string{"a"},
			want:     false,
		},
		{
			name:     "both empty",
			haystack: []string{},
			needles:  []string{},
			want:     true,
		},
		{
			name:     "exact match",
			haystack: []string{"openid", "profile", "email"},
			needles:  []string{"openid", "profile", "email"},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, missing := containsAll(tt.haystack, tt.needles)
			if got != tt.want {
				t.Errorf("containsAll(%v, %v) = %v, want %v (missing: %v)", tt.haystack, tt.needles, got, tt.want, missing)
			}
			// Verify missing items are correct when result is false
			if !got && len(missing) == 0 {
				t.Error("containsAll returned false but missing slice is empty")
			}
		})
	}
}

func TestContainsAllInts(t *testing.T) {
	// Test that generics work with other types
	haystack := []int{1, 2, 3, 4, 5}
	needles := []int{2, 4}

	got, missing := containsAll(haystack, needles)
	if !got {
		t.Errorf("containsAll should return true for ints, got false (missing: %v)", missing)
	}
	if len(missing) != 0 {
		t.Errorf("containsAll returned true but missing slice is not empty: %v", missing)
	}

	needles = []int{2, 6}
	got, missing = containsAll(haystack, needles)
	if got {
		t.Error("containsAll should return false when needle is missing")
	}
	// Verify that 6 is in the missing list
	if len(missing) != 1 || missing[0] != 6 {
		t.Errorf("containsAll should report 6 as missing, got: %v", missing)
	}
}
