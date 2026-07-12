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

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/eswan18/identity/db/migrations"
	"github.com/eswan18/identity/pkg/config"
	"github.com/eswan18/identity/pkg/email"
	"github.com/eswan18/identity/pkg/httpserver"
	"github.com/eswan18/identity/pkg/storage"
	"github.com/eswan18/identity/pkg/store"
)

func main() {

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
