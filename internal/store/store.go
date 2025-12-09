package store

import (
	"database/sql"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/eswan18/identity/internal/db"
)

type Store struct {
	DB *sql.DB
	Q  *db.Queries
}

func New(databaseURL string) (*Store, error) {
	dbConn, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}

	// Set sane defaults
	dbConn.SetMaxOpenConns(20)
	dbConn.SetMaxIdleConns(5)
	dbConn.SetConnMaxLifetime(30 * time.Minute)

	// Ensure connection works
	if err := dbConn.Ping(); err != nil {
		return nil, err
	}

	return &Store{
		DB: dbConn,
		Q:  db.New(dbConn),
	}, nil
}
