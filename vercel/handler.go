package vercel

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
	serverOnce sync.Once
	server     *httpserver.Server
)

// getServer returns a server instance, reusing it across serverless invocations
func getServer() *httpserver.Server {
	serverOnce.Do(func() {
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
		server = httpserver.NewWithoutRateLimiting(cfg, datastore)

		log.Println("Server initialized for Vercel")
	})
	return server
}
