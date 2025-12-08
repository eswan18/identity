SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
GO_SOURCES := $(shell find . -name '*.go' -not -path './docs/*' -not -path './vendor/*')
MIGRATIONS := $(wildcard db/migrations/*.up.sql)

docs: docs/docs.go docs/swagger.json docs/swagger.yaml

docs/docs.go docs/swagger.json docs/swagger.yaml: $(GO_SOURCES)
	swag init -g cmd/auth-service/main.go

run: docs
	go run cmd/auth-service/main.go

build: docs
	go build -o fcast-auth cmd/auth-service/main.go

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