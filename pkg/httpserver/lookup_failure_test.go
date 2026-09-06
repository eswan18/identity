package httpserver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
)

// TestLookupFailure pins the distinction the token endpoint depends on: "this
// row does not exist" ends a session, "I could not reach the database" must
// not. The description travels with the code because a response whose two
// fields disagree is worse than either alone.
//
// This is the unit half. That the HANDLERS actually consult it is a separate
// question, covered end-to-end in db_outage_test.go — a pure function nothing
// calls would pass every assertion here.
func TestLookupFailure(t *testing.T) {
	tests := []struct {
		name            string
		err             error
		wantCode        string
		wantDescription string
	}{
		{"row genuinely absent", sql.ErrNoRows, "invalid_grant", "Invalid refresh token"},
		{
			// sqlc returns ErrNoRows bare today, but a wrapped one must not
			// silently flip a dead grant into a retryable error.
			name:            "absent row, wrapped",
			err:             fmt.Errorf("querying token: %w", sql.ErrNoRows),
			wantCode:        "invalid_grant",
			wantDescription: "Invalid refresh token",
		},
		{"connection refused", errors.New("dial tcp: connection refused"), "server_error", "Failed to look up refresh token"},
		{"statement timeout", errors.New("pq: canceling statement due to statement timeout"), "server_error", "Failed to look up refresh token"},
		{
			name:            "context deadline exceeded",
			err:             fmt.Errorf("query failed: %w", context.DeadlineExceeded),
			wantCode:        "server_error",
			wantDescription: "Failed to look up refresh token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, description := lookupFailure(tt.err, "refresh token")
			if code != tt.wantCode {
				t.Errorf("code = %q, want %q", code, tt.wantCode)
			}
			if description != tt.wantDescription {
				t.Errorf("description = %q, want %q", description, tt.wantDescription)
			}
		})
	}
}
