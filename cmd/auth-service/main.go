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
	"log"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/eswan18/identity/internal/config"
	"github.com/eswan18/identity/internal/httpserver"
	"github.com/eswan18/identity/internal/store"
)

func main() {

	config := config.NewFromEnv()
	datastore, err := store.New(config.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to create datastore: %v", err)
	}
	server := httpserver.New(config, datastore)

	if err := server.Run(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
