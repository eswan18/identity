// Package main Identity Service.
//
// @title           Identity Service
// @version         1.0
//
// @contact.name    Ethan Swan
//
// @host      localhost:8080
// @BasePath  /
package main

import (
	"context"
	"log"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/eswan18/identity/db/migrations"
	"github.com/eswan18/identity/pkg/config"
	"github.com/eswan18/identity/pkg/email"
	"github.com/eswan18/identity/pkg/httpserver"
	"github.com/eswan18/identity/pkg/storage"
	"github.com/eswan18/identity/pkg/store"
)

func main() {
	// Subcommand dispatch. `auth-service` with no arguments serves, exactly as
	// it always has: that is what the prod and staging Deployments run, and
	// they pass no arguments, so this switch is never entered for them. The one
	// subcommand has to be asked for explicitly and never runs as part of
	// starting the server.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "migrate":
			if len(os.Args) > 2 {
				log.Fatalf("Unexpected arguments after `migrate`: %v", os.Args[2:])
			}
			runMigrate()
			return
		default:
			log.Fatalf("Unknown command %q (supported: migrate); run with no arguments to start the server", os.Args[1])
		}
	}

	serve()
}

// runMigrate is the entrypoint for `auth-service migrate`. It applies all
// pending migrations to DATABASE_URL and returns, so the process exits 0.
//
// This exists for preview environments: each preview gets its own database
// branch cut from staging's schema, and bifrost runs this binary as a migrate
// initContainer — same image, same env, so DATABASE_URL already points at the
// preview's own branch — to completion before the app container starts.
// Applying migrations is still a deliberate, separate step: startup does not
// call this, and prod/staging never invoke it.
//
// It reads DATABASE_URL straight from the environment rather than through
// config.NewFromEnv: applying migrations needs nothing but a database, and an
// unrelated missing or malformed serving variable (JWT_PRIVATE_KEY, say) should
// not be able to block a migration.
func runMigrate() {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("Migration failed: DATABASE_URL is not set")
	}

	latest, err := migrations.LatestVersion()
	if err != nil {
		log.Fatalf("Migration failed: %v", err)
	}

	log.Printf("Applying migrations up to version %d", latest)
	if err := migrations.Up(databaseURL); err != nil {
		log.Fatalf("Migration failed: %v", err)
	}
	// Reached whether migrations were applied or the database was already at
	// the latest version; both are a success.
	log.Printf("Database schema is at migration version %d", latest)
}

// serve is the default path: the whole of what `auth-service` did, and does,
// when invoked with no arguments.
func serve() {
	cfg := config.NewFromEnv()
	datastore, err := store.New(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to create datastore: %v", err)
	}

	// Refuse to start if the database schema isn't at the migration version
	// this binary was built for. This is a check, not an auto-migration: a
	// forgotten `make migrate-up` fails fast with a clear message instead of
	// silently serving against an unexpected schema.
	if err := migrations.Verify(context.Background(), datastore.DB); err != nil {
		log.Fatalf("Database schema check failed: %v", err)
	}
	log.Println("Database schema is up to date")

	// Create email sender based on configuration
	var emailSender email.Sender
	switch cfg.EmailProvider {
	case "resend":
		emailSender = email.NewResendSender(cfg.ResendAPIKey, cfg.EmailFrom)
		log.Println("Using Resend email provider")
	default:
		emailSender = email.NewLogSender()
		log.Println("Using log email provider (emails will be logged, not sent)")
	}

	// Create storage provider based on configuration
	var storageProvider storage.Storage
	switch cfg.StorageProvider {
	case "s3":
		var err error
		storageProvider, err = storage.NewS3Storage(
			cfg.StorageEndpoint,
			cfg.StorageBucket,
			cfg.StorageAccessKey,
			cfg.StorageSecretKey,
			cfg.StoragePublicURL,
			cfg.StorageRegion,
		)
		if err != nil {
			log.Fatalf("Failed to create S3 storage: %v", err)
		}
		log.Println("Using S3 storage provider")
	default:
		storageProvider = storage.NewLogStorage()
		log.Println("Using log storage provider (uploads will be logged, not stored)")
	}

	server := httpserver.New(cfg, datastore, emailSender, storageProvider)

	if err := server.Run(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
