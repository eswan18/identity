package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	HTTPAddress string
	DatabaseURL string
}

func NewFromEnv() *Config {
	env := os.Getenv("ENV")
	if env == "" {
		env = "local"
	}
	godotenv.Load(".env." + env)
	log.Println("Loaded environment variables from .env." + env)

	config := &Config{
		HTTPAddress: os.Getenv("HTTP_ADDRESS"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
	}
	if config.HTTPAddress == "" {
		log.Fatal("HTTP_ADDRESS is not set")
	}
	if config.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is not set")
	}
	return config
}
