package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

// These will be set at build time via -ldflags
// Example: go build -ldflags "-X github.com/eswan18/identity/pkg/config.isVercel=true -X github.com/eswan18/identity/pkg/config.databaseURL=postgres://... -X github.com/eswan18/identity/pkg/config.templatesDir=templates"
var (
	isVercel     = "false"
	databaseURL  = ""
	templatesDir = ""
)

type Config struct {
	HTTPAddress  string
	DatabaseURL  string
	TemplatesDir string
}

func NewFromEnv() *Config {
	// If built for Vercel (detected at build time), use build-time or runtime environment variables
	if isVercel == "true" {
		log.Println("Loading environment variables for Vercel (build-time detection)")

		// Use build-time values if set, otherwise fall back to runtime environment variables
		dbURL := databaseURL
		tmplDir := templatesDir

		return &Config{
			DatabaseURL:  dbURL,
			TemplatesDir: tmplDir,
		}
	}

	// Local development: load from .env files
	env := os.Getenv("ENV")
	if env == "" {
		env = "local"
	}
	godotenv.Load(".env." + env)
	log.Println("Loaded environment variables from .env." + env)

	config := &Config{
		HTTPAddress:  os.Getenv("HTTP_ADDRESS"),
		DatabaseURL:  os.Getenv("DATABASE_URL"),
		TemplatesDir: os.Getenv("TEMPLATES_DIR"),
	}
	if config.HTTPAddress == "" {
		log.Fatal("HTTP_ADDRESS is not set")
	}
	if config.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is not set")
	}
	if config.TemplatesDir == "" {
		log.Fatal("TEMPLATES_DIR is not set")
	}
	return config
}
