// MFA-related database queries
// Note: When sqlc is regenerated, update auth.sql.go to include MFA fields in AuthUser scans

package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// GetUserMFAStatusRow contains just the MFA-related fields
type GetUserMFAStatusRow struct {
	ID         uuid.UUID      `json:"id"`
	MfaEnabled bool           `json:"mfa_enabled"`
	MfaSecret  sql.NullString `json:"mfa_secret"`
}

const getUserMFAStatus = `-- name: GetUserMFAStatus :one
SELECT id, mfa_enabled, mfa_secret FROM auth_users WHERE id = $1
`

func (q *Queries) GetUserMFAStatus(ctx context.Context, id uuid.UUID) (GetUserMFAStatusRow, error) {
	row := q.db.QueryRowContext(ctx, getUserMFAStatus, id)
	var i GetUserMFAStatusRow
	err := row.Scan(&i.ID, &i.MfaEnabled, &i.MfaSecret)
	return i, err
}

const enableMFA = `-- name: EnableMFA :exec
UPDATE auth_users
SET mfa_enabled = true, mfa_secret = $2, mfa_verified_at = now(), updated_at = now()
WHERE id = $1
`

type EnableMFAParams struct {
	ID        uuid.UUID `json:"id"`
	MfaSecret string    `json:"mfa_secret"`
}

func (q *Queries) EnableMFA(ctx context.Context, arg EnableMFAParams) error {
	_, err := q.db.ExecContext(ctx, enableMFA, arg.ID, arg.MfaSecret)
	return err
}

const disableMFA = `-- name: DisableMFA :exec
UPDATE auth_users
SET mfa_enabled = false, mfa_secret = NULL, mfa_verified_at = NULL, updated_at = now()
WHERE id = $1
`

func (q *Queries) DisableMFA(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.ExecContext(ctx, disableMFA, id)
	return err
}

const createMFAPending = `-- name: CreateMFAPending :exec
INSERT INTO auth_mfa_pending (id, user_id, client_id, redirect_uri, state, scope, code_challenge, code_challenge_method, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
`

type CreateMFAPendingParams struct {
	ID                  string         `json:"id"`
	UserID              uuid.UUID      `json:"user_id"`
	ClientID            sql.NullString `json:"client_id"`
	RedirectUri         sql.NullString `json:"redirect_uri"`
	State               sql.NullString `json:"state"`
	Scope               []string       `json:"scope"`
	CodeChallenge       sql.NullString `json:"code_challenge"`
	CodeChallengeMethod sql.NullString `json:"code_challenge_method"`
	ExpiresAt           time.Time      `json:"expires_at"`
}

func (q *Queries) CreateMFAPending(ctx context.Context, arg CreateMFAPendingParams) error {
	_, err := q.db.ExecContext(ctx, createMFAPending,
		arg.ID,
		arg.UserID,
		arg.ClientID,
		arg.RedirectUri,
		arg.State,
		pq.Array(arg.Scope),
		arg.CodeChallenge,
		arg.CodeChallengeMethod,
		arg.ExpiresAt,
	)
	return err
}

const getMFAPending = `-- name: GetMFAPending :one
SELECT id, user_id, client_id, redirect_uri, state, scope, code_challenge, code_challenge_method, created_at, expires_at
FROM auth_mfa_pending
WHERE id = $1 AND expires_at > now()
`

func (q *Queries) GetMFAPending(ctx context.Context, id string) (AuthMfaPending, error) {
	row := q.db.QueryRowContext(ctx, getMFAPending, id)
	var i AuthMfaPending
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.ClientID,
		&i.RedirectUri,
		&i.State,
		pq.Array(&i.Scope),
		&i.CodeChallenge,
		&i.CodeChallengeMethod,
		&i.CreatedAt,
		&i.ExpiresAt,
	)
	return i, err
}

const deleteMFAPending = `-- name: DeleteMFAPending :exec
DELETE FROM auth_mfa_pending WHERE id = $1
`

func (q *Queries) DeleteMFAPending(ctx context.Context, id string) error {
	_, err := q.db.ExecContext(ctx, deleteMFAPending, id)
	return err
}

const deleteExpiredMFAPending = `-- name: DeleteExpiredMFAPending :exec
DELETE FROM auth_mfa_pending WHERE expires_at <= now()
`

func (q *Queries) DeleteExpiredMFAPending(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteExpiredMFAPending)
	return err
}
