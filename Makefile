SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
GO_SOURCES := $(shell find . -name '*.go' -not -path './docs/*' -not -path './vendor/*')
TEMPLATES := $(wildcard templates/*.html)
TEMPL_SOURCES := $(wildcard pkg/views/*.templ)
MIGRATIONS := $(wildcard db/migrations/*.up.sql)
ENV ?= local

.DEFAULT_GOAL := build

docs: docs/docs.go docs/swagger.json docs/swagger.yaml

docs/docs.go docs/swagger.json docs/swagger.yaml: $(GO_SOURCES)
	swag init -g cmd/auth-service/main.go

# templ compiles pkg/views/*.templ into committed *_templ.go files. The generated
# files ARE committed so `go build`/CI don't need the templ binary; run this after
# editing a .templ file. Install with: go install github.com/a-h/templ/cmd/templ@latest
.PHONY: templ
templ:
	templ generate

css: static/style.css

static/style.css: static/input.css $(TEMPLATES) $(TEMPL_SOURCES)
	npx @tailwindcss/cli -i static/input.css -o static/style.css --minify

css-watch:
	npx @tailwindcss/cli -i static/input.css -o static/style.css --watch

run: templ docs css
	@echo "Running with ENV=$(ENV)"
	go run cmd/auth-service/main.go

build: templ docs css
	go build -o identity-cli ./cmd/identity-cli
	go build -o identity cmd/auth-service/main.go

migrate-new:
	migrate create -ext sql -dir db/migrations -seq "${name}"

migrate-up:
	@if [ -z "${DATABASE_URL}" ]; then \
		echo "Error: DATABASE_URL is not set"; \
		exit 1; \
	fi
	migrate -database "${DATABASE_URL}" -path db/migrations up

migrate-down:
	@if [ -z "${DATABASE_URL}" ]; then \
		echo "Error: DATABASE_URL is not set"; \
		exit 1; \
	fi
	migrate -database "${DATABASE_URL}" -path db/migrations down

test:
	go test ./...

# Integration tests are gated behind the `integration` build tag because they
# spin up Postgres/MinIO containers via testcontainers and require Docker.
test-integration:
	go test -tags integration ./...

lint:
	go vet ./...

sqlc: db/schema.sql
	sqlc generate

db/schema.sql: $(MIGRATIONS)
	@if [ -z "${DATABASE_URL}" ]; then \
		echo "Error: DATABASE_URL is not set"; \
		exit 1; \
	fi
	pg_dump --schema-only --no-owner "${DATABASE_URL}" | grep -v '^\\' > db/schema.sql
