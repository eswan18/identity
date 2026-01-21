package avatar

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestJPEG creates a minimal valid JPEG image for testing
func createTestJPEG(width, height int) ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: 100, G: 150, B: 200, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 85}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// createTestPNG creates a minimal valid PNG image for testing
func createTestPNG(width, height int) ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: 100, G: 150, B: 200, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func TestResizeImage_ValidJPEG(t *testing.T) {
	imgData, err := createTestJPEG(512, 512)
	require.NoError(t, err)

	resized, contentType, err := ResizeImage(bytes.NewReader(imgData), "image/jpeg")
	require.NoError(t, err)

	assert.Equal(t, "image/jpeg", contentType)
	assert.NotEmpty(t, resized)

	// Verify the resized image dimensions
	decoded, _, err := image.Decode(bytes.NewReader(resized))
	require.NoError(t, err)
	bounds := decoded.Bounds()
	assert.Equal(t, AvatarSize, bounds.Dx())
	assert.Equal(t, AvatarSize, bounds.Dy())
}

func TestResizeImage_ValidPNG(t *testing.T) {
	imgData, err := createTestPNG(300, 400)
	require.NoError(t, err)

	resized, contentType, err := ResizeImage(bytes.NewReader(imgData), "image/png")
	require.NoError(t, err)

	assert.Equal(t, "image/jpeg", contentType) // Output is always JPEG
	assert.NotEmpty(t, resized)

	// Verify the resized image dimensions
	decoded, _, err := image.Decode(bytes.NewReader(resized))
	require.NoError(t, err)
	bounds := decoded.Bounds()
	assert.Equal(t, AvatarSize, bounds.Dx())
	assert.Equal(t, AvatarSize, bounds.Dy())
}

func TestResizeImage_OversizedDimensions(t *testing.T) {
	// Create a very wide image that exceeds MaxImageDimension
	// We can't actually create a 10001x100 image easily, so we'll test the boundary
	imgData, err := createTestJPEG(MaxImageDimension+1, 100)
	require.NoError(t, err)

	_, _, err = ResizeImage(bytes.NewReader(imgData), "image/jpeg")
	require.Error(t, err)

	validationErr, ok := err.(*ValidationError)
	require.True(t, ok)
	assert.Contains(t, validationErr.Message, "dimensions too large")
}

func TestResizeImage_InvalidImageData(t *testing.T) {
	invalidData := []byte("this is not an image")

	_, _, err := ResizeImage(bytes.NewReader(invalidData), "image/jpeg")
	require.Error(t, err)

	validationErr, ok := err.(*ValidationError)
	require.True(t, ok)
	assert.Contains(t, validationErr.Message, "Failed to decode")
}

func TestResizeImage_UnsupportedFormat(t *testing.T) {
	imgData, err := createTestJPEG(100, 100)
	require.NoError(t, err)

	_, _, err = ResizeImage(bytes.NewReader(imgData), "image/bmp")
	require.Error(t, err)

	validationErr, ok := err.(*ValidationError)
	require.True(t, ok)
	assert.Contains(t, validationErr.Message, "Unsupported image format")
}

func TestExtractKeyFromURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "simple URL",
			url:      "https://example.com/avatars/user123.jpg",
			expected: "avatars/user123.jpg",
		},
		{
			name:     "URL with query params",
			url:      "https://example.com/avatars/user123.jpg?v=1234",
			expected: "avatars/user123.jpg",
		},
		{
			name:     "URL with fragment",
			url:      "https://example.com/avatars/user123.jpg#section",
			expected: "avatars/user123.jpg",
		},
		{
			name:     "URL with port",
			url:      "http://localhost:9000/bucket/avatars/user123.jpg",
			expected: "avatars/user123.jpg",
		},
		{
			name:     "empty URL",
			url:      "",
			expected: "",
		},
		{
			name:     "URL with single path segment",
			url:      "https://example.com/file.jpg",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractKeyFromURL(tt.url)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSplitPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected []string
	}{
		{
			name:     "simple path",
			path:     "/avatars/user123.jpg",
			expected: []string{"avatars", "user123.jpg"},
		},
		{
			name:     "multiple segments",
			path:     "/bucket/avatars/user123.jpg",
			expected: []string{"bucket", "avatars", "user123.jpg"},
		},
		{
			name:     "empty path",
			path:     "",
			expected: nil,
		},
		{
			name:     "trailing slash",
			path:     "/avatars/user123.jpg/",
			expected: []string{"avatars", "user123.jpg"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtensionForContentType(t *testing.T) {
	tests := []struct {
		contentType string
		expected    string
	}{
		{"image/jpeg", ".jpg"},
		{"image/png", ".png"},
		{"image/gif", ".gif"},
		{"image/webp", ".webp"},
		{"unknown/type", ".jpg"},
	}

	for _, tt := range tests {
		t.Run(tt.contentType, func(t *testing.T) {
			result := extensionForContentType(tt.contentType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidationError(t *testing.T) {
	err := &ValidationError{Message: "test error message"}
	assert.Equal(t, "test error message", err.Error())
}
