package api

import (
	"log"
	"os"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/eswan18/identity/internal/config"
	"github.com/eswan18/identity/internal/httpserver"
	"github.com/eswan18/identity/internal/store"
)

var (
	storeOnce sync.Once
	datastore *store.Store
)

// getStore returns a store instance, reusing it across serverless invocations
func getStore() *store.Store {
	storeOnce.Do(func() {
		databaseURL := os.Getenv("DATABASE_URL")
		if databaseURL == "" {
			log.Fatal("DATABASE_URL environment variable is not set")
		}

		var err error
		datastore, err = store.New(databaseURL)
		if err != nil {
			log.Fatalf("Failed to create datastore: %v", err)
		}

		// Adjust connection pool settings for serverless (lower limits than default)
		datastore.DB.SetMaxOpenConns(5)
		datastore.DB.SetMaxIdleConns(2)
		datastore.DB.SetConnMaxLifetime(5 * time.Minute)

		log.Println("Database connection pool initialized")
	})
	return datastore
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
