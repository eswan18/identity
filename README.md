This project requires a few CLI tools...
```shell
# swaggo/swag for generating openapi docs
go install github.com/swaggo/swag/cmd/swag@latest
# sqlc-dev/sqlc for ... something
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
# golang-migrate/migrate for migrations
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
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

Regenerate sqlc queries and types.
```shell
make sqlc
```

## Adding a new client

1. `make build`
2. `ENV=dev ./identity-cli client create --name mycoolapp --redirect-uris http://localhost/redirect --scopes openid`

Or for a confidential client:
```shell
ENV=dev ./identity-cli client create --name mycoolapp --redirect-uris http://localhost/redirect --scopes openid --confidential
```

Other client commands:
- `./identity-cli client list` - List all clients
- `./identity-cli client get <client-id>` - Get client details
- `./identity-cli client update <client-id> --name "New Name"` - Update client
- `./identity-cli client delete <client-id>` - Delete client
