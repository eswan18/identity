package handler

import (
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/eswan18/identity/pkg/config"
	"github.com/eswan18/identity/pkg/httpserver"
	"github.com/eswan18/identity/pkg/store"
)

var handler http.Handler

func init() {
	// Use config.NewFromEnv() but set a dummy HTTP_ADDRESS for Vercel
	// (it's not used since we don't call server.Run())
	if os.Getenv("HTTP_ADDRESS") == "" {
		os.Setenv("HTTP_ADDRESS", ":8080") // Dummy value, not used
	}

	cfg := config.NewFromEnv()

	datastore, err := store.New(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to create datastore: %v", err)
	}

	// Adjust connection pool settings for serverless (lower limits than default)
	datastore.DB.SetMaxOpenConns(5)
	datastore.DB.SetMaxIdleConns(2)
	datastore.DB.SetConnMaxLifetime(5 * time.Minute)

	// Use the existing NewWithoutRateLimiting() function - it creates a router with all routes and middleware
	// We'll use that router directly via server.Router()
	server := httpserver.NewWithoutRateLimiting(cfg, datastore)
	handler = server.Router()

	log.Println("Server initialized for Vercel")
}

// Handler is the entry point for Vercel serverless functions
// Vercel will call this function for all requests
func Handler(w http.ResponseWriter, r *http.Request) {
	handler.ServeHTTP(w, r)
}
