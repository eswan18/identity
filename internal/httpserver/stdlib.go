package httpserver

// This file contains things that should be in the standard library but somehow aren't.

import (
	"slices"
)

// containsAll returns true if all elements of needles are in haystack.
// If false, it returns the elements of needles that are not in haystack.
func containsAll[T comparable](haystack, needles []T) (bool, []T) {
	missing := []T{}
	for _, n := range needles {
		if !slices.Contains(haystack, n) {
			missing = append(missing, n)
		}
	}
	return len(missing) == 0, missing
}
