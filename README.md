This project requires a few CLI tools...
```shell
# swaggo/swag for generating openapi docs
go install github.com/swaggo/swag/cmd/swag@latest

# sqlc-dev/sqlc for ... something
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
# golang-migrate/migrate for migrations
go install github.com/golang-migrate/migrate/v4/cmd/migrate@latest
```

## Commands

Build binary:
```shell
make build
```

Build docs:
```shell
make docs
```

Create a new migration:
```shell
# Use underscores in migration names
make migrate-new name=create_table_users
```

Run migrations:
```shell
DATABASE_URL="postgresql://..." make migrate-up
DATABASE_URL="postgresql://..." make migrate-down
```