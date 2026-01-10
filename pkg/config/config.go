package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	HTTPAddress   string
	DatabaseURL   string
	TemplatesDir  string
	JWTPrivateKey string
	JWTIssuer     string
}

func NewFromEnv() *Config {
	var config *Config

	// If running on Koyeb, use environment variables directly (no .env file loading)
	if _, ok := os.LookupEnv("KOYEB_APP_ID"); ok {
		log.Println("Loading environment variables directly from Koyeb")
		config = &Config{
			DatabaseURL:   os.Getenv("DATABASE_URL"),
			TemplatesDir:  os.Getenv("TEMPLATES_DIR"),
			HTTPAddress:   os.Getenv("HTTP_ADDRESS"),
			JWTPrivateKey: os.Getenv("JWT_PRIVATE_KEY"),
			JWTIssuer:     os.Getenv("JWT_ISSUER"),
		}
	} else {
		// Local development: load from .env files
		env := os.Getenv("ENV")
		if env == "" {
			env = "local"
		}
		godotenv.Load(".env." + env)
		log.Println("Loaded environment variables from .env." + env)

		config = &Config{
			HTTPAddress:   os.Getenv("HTTP_ADDRESS"),
			DatabaseURL:   os.Getenv("DATABASE_URL"),
			TemplatesDir:  os.Getenv("TEMPLATES_DIR"),
			JWTPrivateKey: os.Getenv("JWT_PRIVATE_KEY"),
			JWTIssuer:     os.Getenv("JWT_ISSUER"),
		}
	}

	// Validate required fields (applies to both Koyeb and local environments)
	if config.HTTPAddress == "" {
		log.Fatal("HTTP_ADDRESS is not set")
	}
	if config.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is not set")
	}
	if config.TemplatesDir == "" {
		log.Fatal("TEMPLATES_DIR is not set")
	}
	if config.JWTPrivateKey == "" {
		log.Fatal("JWT_PRIVATE_KEY is not set")
	}
	if config.JWTIssuer == "" {
		log.Fatal("JWT_ISSUER is not set")
	}
	return config
}
