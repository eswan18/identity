package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	HTTPAddress  string
	DatabaseURL  string
	TemplatesDir string
}

func NewFromEnv() *Config {
	// If running on Vercel, use environment variables directly (no .env file loading)
	if _, ok := os.LookupEnv("KOYEB_APP_ID"); ok {
		log.Println("Loading environment variables directly from Koyeb")
		return &Config{
			DatabaseURL:  os.Getenv("DATABASE_URL"),
			TemplatesDir: os.Getenv("TEMPLATES_DIR"),
			HTTPAddress:  os.Getenv("HTTP_ADDRESS"),
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
