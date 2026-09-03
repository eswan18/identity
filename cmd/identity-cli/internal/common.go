package internal

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/eswan18/identity/pkg/config"
	"github.com/eswan18/identity/pkg/store"
)

// GetDatastore connects to the database and returns a store instance
func GetDatastore() (*store.Store, error) {
	cfg := config.NewFromEnv()
	datastore, err := store.New(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	return datastore, nil
}

// AppendUnique returns existing with any additions not already present
// appended, preserving order. Comparison is exact string equality — no URI
// normalization — because consumers (e.g. the OIDC logout handler) match
// these values exactly.
func AppendUnique(existing, additions []string) []string {
	result := make([]string, 0, len(existing)+len(additions))
	seen := make(map[string]bool, len(existing)+len(additions))
	for _, v := range existing {
		result = append(result, v)
		seen[v] = true
	}
	for _, v := range additions {
		if !seen[v] {
			result = append(result, v)
			seen[v] = true
		}
	}
	return result
}

// RemoveValues returns existing with every value in removals dropped, along
// with the removals that were not present. Comparison is exact string
// equality — no URI normalization — for the same reason as AppendUnique:
// consumers match these values exactly. Callers should treat a non-empty
// notFound as an error rather than a partial success; a redirect URI that
// quietly fails to be removed reads as revoked while it is still live.
func RemoveValues(existing, removals []string) (result, notFound []string) {
	doomed := make(map[string]bool, len(removals))
	for _, v := range removals {
		doomed[v] = true
	}

	result = make([]string, 0, len(existing))
	found := make(map[string]bool, len(removals))
	for _, v := range existing {
		if doomed[v] {
			found[v] = true
			continue
		}
		result = append(result, v)
	}

	notFound = make([]string, 0, len(removals))
	reported := make(map[string]bool, len(removals))
	for _, v := range removals {
		if !found[v] && !reported[v] {
			notFound = append(notFound, v)
			reported[v] = true
		}
	}
	return result, notFound
}

// ParseList splits a comma-separated string and trims whitespace
func ParseList(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// GenerateRandomString generates a cryptographically secure random string
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
