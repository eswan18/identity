package config

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/url"
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

	// Validate JWT_PRIVATE_KEY is a valid PEM-encoded ECDSA private key
	if err := validateECDSAPrivateKey(config.JWTPrivateKey); err != nil {
		log.Fatalf("JWT_PRIVATE_KEY is invalid: %v", err)
	}

	// Validate JWT_ISSUER is a valid URL
	if err := validateIssuerURL(config.JWTIssuer); err != nil {
		log.Fatalf("JWT_ISSUER is invalid: %v", err)
	}

	return config
}

// validateECDSAPrivateKey checks that the given string is a valid PEM-encoded ECDSA private key.
func validateECDSAPrivateKey(keyPEM string) error {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return &configError{"failed to parse PEM block"}
	}
	_, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return &configError{"failed to parse ECDSA private key: " + err.Error()}
	}
	return nil
}

// validateIssuerURL checks that the given string is a valid URL with http or https scheme.
func validateIssuerURL(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil {
		return &configError{"failed to parse URL: " + err.Error()}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return &configError{"scheme must be http or https"}
	}
	if u.Host == "" {
		return &configError{"host is required"}
	}
	return nil
}

type configError struct {
	msg string
}

func (e *configError) Error() string {
	return e.msg
}
