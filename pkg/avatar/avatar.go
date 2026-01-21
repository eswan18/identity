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
	"net/http"
	"net/url"
	"strings"

	"github.com/disintegration/imaging"
	"github.com/eswan18/identity/pkg/storage"
	"github.com/google/uuid"
)

const (
	// MaxAvatarSize is the maximum file size for avatar uploads (5MB).
	MaxAvatarSize = 5 * 1024 * 1024
	// AvatarSize is the target dimension for resized avatars.
	AvatarSize = 256
	// MaxImageDimension is the maximum width/height allowed to prevent decompression bombs.
	MaxImageDimension = 10000
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
	// Validate userID is a valid UUID to prevent path traversal
	if _, err := uuid.Parse(userID); err != nil {
		return "", &ValidationError{"Invalid user ID"}
	}

	// Validate file size first (before reading into memory)
	if size > MaxAvatarSize {
		return "", &ValidationError{"File size exceeds the maximum of 5MB"}
	}

	// Read the file into memory for processing
	data, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	// Detect actual content type from file magic bytes (don't trust client header)
	detectedType := http.DetectContentType(data)
	if !AllowedMimeTypes[detectedType] {
		return "", &ValidationError{"File type not allowed. Please upload a JPEG, PNG, GIF, or WebP image."}
	}

	// Resize the image (this also validates it's a real image and checks dimensions)
	resizedData, outputContentType, err := ResizeImage(bytes.NewReader(data), detectedType)
	if err != nil {
		return "", err
	}

	// Generate storage key
	ext := extensionForContentType(outputContentType)
	key := fmt.Sprintf("avatars/%s%s", userID, ext)

	// Upload to storage
	avatarURL, err := s.storage.Upload(ctx, key, bytes.NewReader(resizedData), outputContentType, int64(len(resizedData)))
	if err != nil {
		return "", fmt.Errorf("failed to upload avatar: %w", err)
	}

	return avatarURL, nil
}

// Delete removes a user's avatar from storage.
func (s *Service) Delete(ctx context.Context, currentURL string) error {
	if currentURL == "" {
		return nil
	}

	// Extract key from URL
	key := extractKeyFromURL(currentURL)
	if key == "" {
		return nil
	}

	return s.storage.Delete(ctx, key)
}

// ValidateImage checks if the uploaded file is a valid image.
// Deprecated: Use the detection in Upload instead. This is kept for backwards compatibility.
func ValidateImage(contentType string, size int64) error {
	if size > MaxAvatarSize {
		return &ValidationError{"File size exceeds the maximum of 5MB"}
	}

	if !AllowedMimeTypes[contentType] {
		return &ValidationError{"File type not allowed. Please upload a JPEG, PNG, GIF, or WebP image."}
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
		return nil, "", &ValidationError{"Unsupported image format"}
	}
	if err != nil {
		return nil, "", &ValidationError{"Failed to decode image. Please ensure the file is a valid image."}
	}

	// Check image dimensions to prevent decompression bombs
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()
	if width > MaxImageDimension || height > MaxImageDimension {
		return nil, "", &ValidationError{fmt.Sprintf("Image dimensions too large. Maximum allowed is %dx%d pixels.", MaxImageDimension, MaxImageDimension)}
	}
	if width <= 0 || height <= 0 {
		return nil, "", &ValidationError{"Invalid image dimensions"}
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
func extractKeyFromURL(rawURL string) string {
	// Parse the URL properly to handle query params, fragments, etc.
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	// Get the path and extract last two components
	urlPath := parsed.Path
	if urlPath == "" {
		return ""
	}

	// Split path and get last two parts (e.g., "avatars/userid.jpg")
	parts := splitPath(urlPath)
	if len(parts) < 2 {
		return ""
	}

	return parts[len(parts)-2] + "/" + parts[len(parts)-1]
}

// splitPath splits a URL path into its components, filtering empty strings.
func splitPath(p string) []string {
	var parts []string
	for _, part := range strings.Split(p, "/") {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

// ValidationError represents an avatar validation error.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}
