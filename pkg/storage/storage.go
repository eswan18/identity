// Package storage provides object storage functionality with pluggable providers.
package storage

import (
	"context"
	"io"
)

// Storage is the interface for object storage providers.
type Storage interface {
	// Upload stores an object and returns the public URL.
	Upload(ctx context.Context, key string, body io.Reader, contentType string, size int64) (url string, err error)
	// Delete removes an object by key.
	Delete(ctx context.Context, key string) error
}
