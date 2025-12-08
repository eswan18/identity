package main

import (
	"log"

	"github.com/eswan18/fcast-service/internal/config"
	"github.com/eswan18/fcast-service/internal/httpserver"
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
