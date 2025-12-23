package api

import (
	"database/sql"
	"log"
	"os"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/eswan18/identity/internal/config"
	"github.com/eswan18/identity/internal/db"
	"github.com/eswan18/identity/internal/httpserver"
	"github.com/eswan18/identity/internal/store"
)

var (
	dbOnce sync.Once
	dbPool *sql.DB
)

// initDB initializes the database connection pool (reused across invocations)
func initDB() *sql.DB {
	dbOnce.Do(func() {
		databaseURL := os.Getenv("DATABASE_URL")
		if databaseURL == "" {
			log.Fatal("DATABASE_URL environment variable is not set")
		}

		var err error
		dbPool, err = sql.Open("pgx", databaseURL)
		if err != nil {
			log.Fatalf("Failed to open database: %v", err)
		}

		// Configure pool for serverless (lower limits than traditional server)
		dbPool.SetMaxOpenConns(5)
		dbPool.SetMaxIdleConns(2)
		dbPool.SetConnMaxLifetime(5 * time.Minute)

		// Test connection
		if err := dbPool.Ping(); err != nil {
			log.Fatalf("Failed to ping database: %v", err)
		}

		log.Println("Database connection pool initialized")
	})
	return dbPool
}

// getStore returns a store instance using the shared database pool
func getStore() *store.Store {
	dbConn := initDB()
	return &store.Store{
		DB: dbConn,
		Q:  db.New(dbConn),
	}
}

// getServer creates a server instance using the existing New() function
// We'll use our own router, so the server's router and rate limiting are ignored
func getServer() *httpserver.Server {
	datastore := getStore()

	config := &config.Config{
		DatabaseURL:  os.Getenv("DATABASE_URL"),
		TemplatesDir: os.Getenv("TEMPLATES_DIR"),
	}
	if config.TemplatesDir == "" {
		config.TemplatesDir = "templates"
	}

	// Use the existing New() function - it will create its own router with rate limiting,
	// but we'll use our own router instead, so that's fine
	return httpserver.New(config, datastore)
}
