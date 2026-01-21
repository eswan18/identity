// Package avatar provides avatar image processing and validation.
package avatar

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"path"
	"strings"

	"github.com/disintegration/imaging"
	"github.com/eswan18/identity/pkg/storage"
)

const (
	// MaxAvatarSize is the maximum file size for avatar uploads (5MB).
	MaxAvatarSize = 5 * 1024 * 1024
	// AvatarSize is the target dimension for resized avatars.
	AvatarSize = 256
)

// AllowedMimeTypes are the content types accepted for avatar uploads.
var AllowedMimeTypes = map[string]bool{
	"image/jpeg": true,
	"image/png":  true,
	"image/gif":  true,
	"image/webp": true,
}

// Service handles avatar operations.
type Service struct {
	storage storage.Storage
}

// NewService creates a new avatar service.
func NewService(storage storage.Storage) *Service {
	return &Service{storage: storage}
}

// Upload validates, resizes, and stores an avatar image.
// Returns the public URL of the stored avatar.
func (s *Service) Upload(ctx context.Context, userID string, file io.Reader, contentType string, size int64) (string, error) {
	// Validate the upload
	if err := ValidateImage(contentType, size); err != nil {
		return "", err
	}

	// Read the file into memory for processing
	data, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	// Resize the image
	resizedData, outputContentType, err := ResizeImage(bytes.NewReader(data), contentType)
	if err != nil {
		return "", fmt.Errorf("failed to resize image: %w", err)
	}

	// Generate storage key
	ext := extensionForContentType(outputContentType)
	key := fmt.Sprintf("avatars/%s%s", userID, ext)

	// Upload to storage
	url, err := s.storage.Upload(ctx, key, bytes.NewReader(resizedData), outputContentType, int64(len(resizedData)))
	if err != nil {
		return "", fmt.Errorf("failed to upload avatar: %w", err)
	}

	return url, nil
}

// Delete removes a user's avatar from storage.
func (s *Service) Delete(ctx context.Context, currentURL string) error {
	if currentURL == "" {
		return nil
	}

	// Extract key from URL (last two path components: avatars/userid.ext)
	key := extractKeyFromURL(currentURL)
	if key == "" {
		return nil
	}

	return s.storage.Delete(ctx, key)
}

// ValidateImage checks if the uploaded file is a valid image.
func ValidateImage(contentType string, size int64) error {
	if size > MaxAvatarSize {
		return &ValidationError{fmt.Sprintf("file size %d exceeds maximum of %d bytes", size, MaxAvatarSize)}
	}

	if !AllowedMimeTypes[contentType] {
		return &ValidationError{fmt.Sprintf("content type %s is not allowed", contentType)}
	}

	return nil
}

// ResizeImage resizes an image to the standard avatar dimensions.
// Returns the resized image data and content type (always JPEG for consistency).
func ResizeImage(input io.Reader, contentType string) ([]byte, string, error) {
	var img image.Image
	var err error

	// Decode based on content type
	switch contentType {
	case "image/jpeg":
		img, err = jpeg.Decode(input)
	case "image/png":
		img, err = png.Decode(input)
	case "image/gif", "image/webp":
		// Use imaging library for gif/webp which handles more formats
		img, err = imaging.Decode(input)
	default:
		return nil, "", fmt.Errorf("unsupported content type: %s", contentType)
	}
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode image: %w", err)
	}

	// Resize to fit within AvatarSize x AvatarSize, maintaining aspect ratio
	// Then crop to square from center
	resized := imaging.Fill(img, AvatarSize, AvatarSize, imaging.Center, imaging.Lanczos)

	// Encode as JPEG for consistent output
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, resized, &jpeg.Options{Quality: 85}); err != nil {
		return nil, "", fmt.Errorf("failed to encode image: %w", err)
	}

	return buf.Bytes(), "image/jpeg", nil
}

// extensionForContentType returns the file extension for a content type.
func extensionForContentType(contentType string) string {
	switch contentType {
	case "image/jpeg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/gif":
		return ".gif"
	case "image/webp":
		return ".webp"
	default:
		return ".jpg"
	}
}

// extractKeyFromURL extracts the storage key from a full URL.
func extractKeyFromURL(url string) string {
	// URL format: https://storage.example.com/avatars/userid.jpg
	// We want: avatars/userid.jpg
	parts := strings.Split(url, "/")
	if len(parts) < 2 {
		return ""
	}
	// Get last two parts
	return path.Join(parts[len(parts)-2], parts[len(parts)-1])
}

// ValidationError represents an avatar validation error.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}
