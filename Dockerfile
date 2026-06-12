# Tailwind CSS build stage
FROM node:22-alpine AS tailwind

WORKDIR /build

# Copy package files and install dependencies
COPY package.json package-lock.json ./
RUN npm ci

# Copy source files needed for Tailwind
COPY static/input.css ./static/
COPY templates ./templates

# Build Tailwind CSS
RUN npx @tailwindcss/cli -i static/input.css -o static/style.css --minify

# Go build stage
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

WORKDIR /build

# Copy go mod files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Pre-compile the heavy dependencies so they land in the Go build cache in a
# layer that only invalidates when go.mod/go.sum change. Env and flags must
# match the final go build exactly, or the cache entries won't be reused.
RUN CGO_ENABLED=0 GOOS=linux go build \
    github.com/aws/aws-sdk-go-v2/service/s3 \
    github.com/aws/aws-sdk-go-v2/credentials \
    github.com/jackc/pgx/v5/stdlib \
    github.com/golang-migrate/migrate/v4 \
    github.com/swaggo/swag \
    github.com/swaggo/http-swagger \
    github.com/disintegration/imaging \
    github.com/golang-jwt/jwt/v5 \
    github.com/go-chi/chi/v5 \
    github.com/pquerna/otp/totp \
    github.com/resend/resend-go/v2 \
    github.com/spf13/cobra \
    github.com/lib/pq \
    golang.org/x/crypto/argon2

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o auth-service ./cmd/auth-service

# Runtime stage
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /build/auth-service .

# Copy templates directory
COPY --from=builder /build/templates ./templates

# Copy static directory with built CSS from tailwind stage
COPY --from=tailwind /build/static ./static

# Create non-root user
RUN adduser -D -u 1000 appuser

# Expose port (default 8080, can be overridden via HTTP_ADDRESS)
EXPOSE 8080

# Set environment variables (can be overridden at runtime)
ENV HTTP_ADDRESS=:8080
ENV TEMPLATES_DIR=/app/templates

# Switch to non-root user
USER appuser

# Run the server
CMD ["./auth-service"]

