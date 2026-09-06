SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
GO_SOURCES := $(shell find . -name '*.go' -not -path './docs/*' -not -path './vendor/*')
TEMPL_SOURCES := $(wildcard pkg/views/*.templ)
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

static/style.css: static/input.css $(TEMPL_SOURCES)
	npx @tailwindcss/cli -i static/input.css -o static/style.css --minify

css-watch:
	npx @tailwindcss/cli -i static/input.css -o static/style.css --watch

run: templ docs css
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

test:
	go test ./...

# Integration tests are gated behind the `integration` build tag because they
# spin up Postgres/MinIO containers via testcontainers and require Docker.
test-integration:
	go test -tags integration ./...

lint:
	go vet ./...

# sqlc reads db/migrations directly (see sqlc.yaml), so codegen needs no database
# and no pg_dump.
#
# The version is pinned here and nowhere else. CI runs these same targets rather
# than invoking sqlc itself, so there is one source of truth for which version
# produced the committed output. Without that, a contributor on a different
# release regenerates identical code with a different version banner, CI reports
# the tree as stale, and re-running `make sqlc` -- which is what the error tells
# them to do -- changes nothing.
SQLC_VERSION := v1.30.0
SQLC := go run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION)

.PHONY: sqlc
sqlc:
	$(SQLC) generate

# sqlc-check is what CI runs. It uses `sqlc diff`, not `generate` followed by a
# git diff: the latter cannot see a *new* generated file, because git diff does
# not report untracked paths. Adding a query is the most likely reason to need
# this guard at all, and it is exactly the case that slipped through.
.PHONY: sqlc-check
sqlc-check:
	@$(SQLC) diff || { \
		echo "pkg/db is out of date with db/migrations and db/queries."; \
		echo "Run 'make sqlc' (sqlc $(SQLC_VERSION)) and commit the result."; \
		exit 1; \
	}
