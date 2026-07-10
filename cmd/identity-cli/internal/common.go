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
