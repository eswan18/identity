package storage

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3Storage implements Storage using S3-compatible APIs (works with AWS S3, Cloudflare R2, MinIO).
type S3Storage struct {
	client        *s3.Client
	bucket        string
	publicURLBase string // e.g., "https://avatars.example.com" or "http://localhost:9000/avatars"
}

// NewS3Storage creates a new S3-compatible storage client.
func NewS3Storage(endpoint, bucket, accessKey, secretKey, publicURLBase, region string) (*S3Storage, error) {
	if region == "" {
		region = "auto" // Default for R2
	}

	client := s3.New(s3.Options{
		Region: region,
		Credentials: credentials.NewStaticCredentialsProvider(
			accessKey,
			secretKey,
			"",
		),
		BaseEndpoint: aws.String(endpoint),
		UsePathStyle: true, // Required for MinIO and some S3-compatible services
	})

	return &S3Storage{
		client:        client,
		bucket:        bucket,
		publicURLBase: publicURLBase,
	}, nil
}

// Upload stores an object and returns the public URL.
func (s *S3Storage) Upload(ctx context.Context, key string, body io.Reader, contentType string, size int64) (string, error) {
	input := &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		Body:          body,
		ContentType:   aws.String(contentType),
		ContentLength: aws.Int64(size),
	}

	_, err := s.client.PutObject(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to upload object: %w", err)
	}

	// Return the public URL
	url := fmt.Sprintf("%s/%s", s.publicURLBase, key)
	return url, nil
}

// Delete removes an object by key.
func (s *S3Storage) Delete(ctx context.Context, key string) error {
	input := &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	}

	_, err := s.client.DeleteObject(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to delete object: %w", err)
	}

	return nil
}

// CreateBucket creates a bucket if it doesn't exist. Useful for testing.
func (s *S3Storage) CreateBucket(ctx context.Context) error {
	_, err := s.client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(s.bucket),
	})
	if err != nil {
		// Ignore "bucket already exists" errors, but return other errors
		var alreadyOwned *types.BucketAlreadyOwnedByYou
		var alreadyExists *types.BucketAlreadyExists
		if errors.As(err, &alreadyOwned) || errors.As(err, &alreadyExists) {
			return nil
		}
		return fmt.Errorf("failed to create bucket: %w", err)
	}
	return nil
}
