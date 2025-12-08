// Package main Forecasting Authentication Service.
//
// @title           Forecasting Authentication Service
// @version         1.0
//
// @contact.name    Ethan Swan
//
// @host      localhost:8080
// @BasePath  /
package main

import (
	"log"

	"github.com/eswan18/fcast-auth/internal/config"
	"github.com/eswan18/fcast-auth/internal/httpserver"
)

func main() {

	server := httpserver.New(&config.Config{
		Port: "8080",
	})

	err := server.Run()
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
