package config

import (
	"log"
	"os"
)

type Config struct {
	Port        string
	DatabaseURL string
}

func NewFromEnv() *Config {
	config := &Config{
		Port:        os.Getenv("PORT"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
	}
	if config.Port == "" {
		log.Fatal("PORT is not set")
	}
	if config.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is not set")
	}
	return config
}
