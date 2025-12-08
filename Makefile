# Dynamically find all Go source files (excluding generated docs)
GO_SOURCES := $(shell find . -name '*.go' -not -path './docs/*' -not -path './vendor/*')

docs: docs/docs.go docs/swagger.json docs/swagger.yaml

docs/docs.go docs/swagger.json docs/swagger.yaml: $(GO_SOURCES)
	swag init -g cmd/auth-service/main.go

run: docs
	go run cmd/auth-service/main.go

build: docs
	go build -o fcast-auth cmd/auth-service/main.go