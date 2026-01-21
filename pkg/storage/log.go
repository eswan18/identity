package storage

import (
	"context"
	"fmt"
	"io"
	"log"
)

// LogStorage logs storage operations instead of actually storing files.
// Useful for development when no storage backend is configured.
type LogStorage struct{}

// NewLogStorage creates a new LogStorage instance.
func NewLogStorage() *LogStorage {
	return &LogStorage{}
}

// Upload logs the upload operation and returns a fake URL.
func (s *LogStorage) Upload(ctx context.Context, key string, body io.Reader, contentType string, size int64) (string, error) {
	// Read and discard the body to simulate upload
	written, err := io.Copy(io.Discard, body)
	if err != nil {
		return "", fmt.Errorf("failed to read body: %w", err)
	}

	log.Printf("[STORAGE] Upload: key=%s, contentType=%s, size=%d (read %d bytes)", key, contentType, size, written)

	// Return a fake URL
	return fmt.Sprintf("https://storage.example.com/%s", key), nil
}

// Delete logs the delete operation.
func (s *LogStorage) Delete(ctx context.Context, key string) error {
	log.Printf("[STORAGE] Delete: key=%s", key)
	return nil
}
