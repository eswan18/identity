package config

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	HTTPAddress   string
	DatabaseURL   string
	TemplatesDir  string
	JWTPrivateKey string
	JWTIssuer     string

	// Email configuration
	EmailProvider string // "resend" or "log"
	ResendAPIKey  string // Required when EmailProvider is "resend"
	EmailFrom     string // Sender address (e.g., "noreply@example.com")

	// Storage configuration
	StorageProvider  string // "s3" or "log"
	StorageEndpoint  string // S3-compatible endpoint (e.g., "https://xxx.r2.cloudflarestorage.com")
	StorageBucket    string // Bucket name
	StorageAccessKey string
	StorageSecretKey string
	StoragePublicURL string // Public URL base for serving files
	StorageRegion    string // AWS region (default: "auto" for R2)
}

func NewFromEnv() *Config {
	var config *Config

	// If running on Koyeb, use environment variables directly (no .env file loading)
	if _, ok := os.LookupEnv("KOYEB_APP_ID"); ok {
		log.Println("Loading environment variables directly from Koyeb")
		config = &Config{
			DatabaseURL:      os.Getenv("DATABASE_URL"),
			TemplatesDir:     os.Getenv("TEMPLATES_DIR"),
			HTTPAddress:      os.Getenv("HTTP_ADDRESS"),
			JWTPrivateKey:    os.Getenv("JWT_PRIVATE_KEY"),
			JWTIssuer:        os.Getenv("JWT_ISSUER"),
			EmailProvider:    os.Getenv("EMAIL_PROVIDER"),
			ResendAPIKey:     os.Getenv("RESEND_API_KEY"),
			EmailFrom:        os.Getenv("EMAIL_FROM"),
			StorageProvider:  os.Getenv("STORAGE_PROVIDER"),
			StorageEndpoint:  os.Getenv("STORAGE_ENDPOINT"),
			StorageBucket:    os.Getenv("STORAGE_BUCKET"),
			StorageAccessKey: os.Getenv("STORAGE_ACCESS_KEY"),
			StorageSecretKey: os.Getenv("STORAGE_SECRET_KEY"),
			StoragePublicURL: os.Getenv("STORAGE_PUBLIC_URL"),
			StorageRegion:    os.Getenv("STORAGE_REGION"),
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
			HTTPAddress:      os.Getenv("HTTP_ADDRESS"),
			DatabaseURL:      os.Getenv("DATABASE_URL"),
			TemplatesDir:     os.Getenv("TEMPLATES_DIR"),
			JWTPrivateKey:    os.Getenv("JWT_PRIVATE_KEY"),
			JWTIssuer:        os.Getenv("JWT_ISSUER"),
			EmailProvider:    os.Getenv("EMAIL_PROVIDER"),
			ResendAPIKey:     os.Getenv("RESEND_API_KEY"),
			EmailFrom:        os.Getenv("EMAIL_FROM"),
			StorageProvider:  os.Getenv("STORAGE_PROVIDER"),
			StorageEndpoint:  os.Getenv("STORAGE_ENDPOINT"),
			StorageBucket:    os.Getenv("STORAGE_BUCKET"),
			StorageAccessKey: os.Getenv("STORAGE_ACCESS_KEY"),
			StorageSecretKey: os.Getenv("STORAGE_SECRET_KEY"),
			StoragePublicURL: os.Getenv("STORAGE_PUBLIC_URL"),
			StorageRegion:    os.Getenv("STORAGE_REGION"),
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

	// Decode JWT_PRIVATE_KEY if it's base64-encoded (for environments that don't support multiline values)
	config.JWTPrivateKey = decodePrivateKey(config.JWTPrivateKey)

	// Validate JWT_PRIVATE_KEY is a valid PEM-encoded ECDSA private key
	if err := validateECDSAPrivateKey(config.JWTPrivateKey); err != nil {
		log.Fatalf("JWT_PRIVATE_KEY is invalid: %v", err)
	}

	// Validate JWT_ISSUER is a valid URL
	if err := validateIssuerURL(config.JWTIssuer); err != nil {
		log.Fatalf("JWT_ISSUER is invalid: %v", err)
	}

	// Default email provider to "log" for development
	if config.EmailProvider == "" {
		config.EmailProvider = "log"
	}

	// Validate email configuration
	if config.EmailProvider == "resend" {
		if config.ResendAPIKey == "" {
			log.Fatal("RESEND_API_KEY is required when EMAIL_PROVIDER is 'resend'")
		}
		if config.EmailFrom == "" {
			log.Fatal("EMAIL_FROM is required when EMAIL_PROVIDER is 'resend'")
		}
	} else if config.EmailProvider != "log" {
		log.Fatalf("EMAIL_PROVIDER must be 'resend' or 'log', got: %s", config.EmailProvider)
	}

	// Default storage provider to "log" for development
	if config.StorageProvider == "" {
		config.StorageProvider = "log"
	}

	// Validate storage configuration
	if config.StorageProvider == "s3" {
		if config.StorageEndpoint == "" {
			log.Fatal("STORAGE_ENDPOINT is required when STORAGE_PROVIDER is 's3'")
		}
		if config.StorageBucket == "" {
			log.Fatal("STORAGE_BUCKET is required when STORAGE_PROVIDER is 's3'")
		}
		if config.StorageAccessKey == "" {
			log.Fatal("STORAGE_ACCESS_KEY is required when STORAGE_PROVIDER is 's3'")
		}
		if config.StorageSecretKey == "" {
			log.Fatal("STORAGE_SECRET_KEY is required when STORAGE_PROVIDER is 's3'")
		}
		if config.StoragePublicURL == "" {
			log.Fatal("STORAGE_PUBLIC_URL is required when STORAGE_PROVIDER is 's3'")
		}
		// Default region to "auto" for R2 compatibility
		if config.StorageRegion == "" {
			config.StorageRegion = "auto"
		}
	} else if config.StorageProvider != "log" {
		log.Fatalf("STORAGE_PROVIDER must be 's3' or 'log', got: %s", config.StorageProvider)
	}

	return config
}

// decodePrivateKey decodes a private key that may be base64-encoded.
// If the key starts with "-----BEGIN", it's already PEM format and returned as-is.
// Otherwise, it's assumed to be base64-encoded and is decoded.
func decodePrivateKey(key string) string {
	// If it already looks like PEM, return as-is
	if strings.HasPrefix(key, "-----BEGIN") {
		return key
	}

	// Try to decode as base64
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		// Not valid base64, return original (will fail validation with clear error)
		return key
	}

	return string(decoded)
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
