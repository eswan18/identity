package httpserver

// This file contains small helpers that don't belong to any single handler file.

import (
	"encoding/json"
	"net/http"
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

// writeJSONError writes an OAuth2-style JSON error response.
func writeJSONError(w http.ResponseWriter, statusCode int, errorCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}
