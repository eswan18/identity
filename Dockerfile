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

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o auth-service ./cmd/auth-service

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

# Expose port (default 8080, can be overridden via HTTP_ADDRESS)
EXPOSE 8080

# Set environment variables (can be overridden at runtime)
ENV HTTP_ADDRESS=:8080
ENV TEMPLATES_DIR=/app/templates

# Run the server
CMD ["./auth-service"]

