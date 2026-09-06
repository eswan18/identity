package httpserver

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"
)

// TestLookupFailureCode pins the distinction the token endpoint depends on:
// "this row does not exist" ends a session, "I could not reach the database"
// must not. It is a unit test because the end-to-end route cannot get here —
// client authentication runs first and fails the whole request before either
// the refresh-token or authorization-code lookup is attempted.
func TestLookupFailureCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"row genuinely absent", sql.ErrNoRows, "invalid_grant"},
		{
			// sqlc returns ErrNoRows bare today, but a wrapped one must not
			// silently flip a dead grant into a retryable error.
			name: "absent row, wrapped",
			err:  fmt.Errorf("querying token: %w", sql.ErrNoRows),
			want: "invalid_grant",
		},
		{"connection refused", errors.New("dial tcp: connection refused"), "server_error"},
		{"statement timeout", errors.New("pq: canceling statement due to statement timeout"), "server_error"},
		{"context deadline", context_DeadlineExceeded(), "server_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lookupFailureCode(tt.err); got != tt.want {
				t.Errorf("lookupFailureCode(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func context_DeadlineExceeded() error {
	return fmt.Errorf("query failed: %w", errors.New("context deadline exceeded"))
}
