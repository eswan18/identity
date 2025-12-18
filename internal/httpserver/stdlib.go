package httpserver

// This file contains things that should be in the standard library but somehow aren't.

import "slices"

func containsAll[T comparable](haystack, needles []T) bool {
	for _, n := range needles {
		if !slices.Contains(haystack, n) {
			return false
		}
	}
	return true
}
