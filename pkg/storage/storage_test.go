package storage

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogStorage_Upload(t *testing.T) {
	storage := NewLogStorage()
	ctx := context.Background()

	body := bytes.NewReader([]byte("test file content"))
	url, err := storage.Upload(ctx, "test/key.jpg", body, "image/jpeg", 17)

	require.NoError(t, err)
	assert.Equal(t, "https://storage.example.com/test/key.jpg", url)
}

func TestLogStorage_Upload_EmptyBody(t *testing.T) {
	storage := NewLogStorage()
	ctx := context.Background()

	body := bytes.NewReader([]byte{})
	url, err := storage.Upload(ctx, "empty.jpg", body, "image/jpeg", 0)

	require.NoError(t, err)
	assert.Equal(t, "https://storage.example.com/empty.jpg", url)
}

func TestLogStorage_Delete(t *testing.T) {
	storage := NewLogStorage()
	ctx := context.Background()

	err := storage.Delete(ctx, "test/key.jpg")

	require.NoError(t, err)
}

func TestLogStorage_ImplementsInterface(t *testing.T) {
	// Compile-time check that LogStorage implements Storage interface
	var _ Storage = (*LogStorage)(nil)
}
