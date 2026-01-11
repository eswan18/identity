SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
GO_SOURCES := $(shell find . -name '*.go' -not -path './docs/*' -not -path './vendor/*')
TEMPLATES := $(wildcard templates/*.html)
MIGRATIONS := $(wildcard db/migrations/*.up.sql)
ENV ?= local

.DEFAULT_GOAL := build

docs: docs/docs.go docs/swagger.json docs/swagger.yaml

docs/docs.go docs/swagger.json docs/swagger.yaml: $(GO_SOURCES)
	swag init -g cmd/auth-service/main.go

css: static/style.css

static/style.css: static/input.css $(TEMPLATES)
	npx @tailwindcss/cli -i static/input.css -o static/style.css --minify

css-watch:
	npx @tailwindcss/cli -i static/input.css -o static/style.css --watch

run: docs css
	@echo "Running with ENV=$(ENV)"
	go run cmd/auth-service/main.go

build: docs css
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

sqlc: db/schema.sql
	sqlc generate

db/schema.sql: $(MIGRATIONS)
	@if [ -z "${DATABASE_URL}" ]; then \
		echo "Error: DATABASE_URL is not set"; \
		exit 1; \
	fi
	pg_dump --schema-only --no-owner "${DATABASE_URL}" | grep -v '^\\' > db/schema.sql
