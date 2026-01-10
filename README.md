# Identity Provider

OAuth 2.0 / OpenID Connect identity provider built with Go, PostgreSQL, and HTMX.

## Features

- OAuth 2.0 Authorization Code flow with PKCE
- OpenID Connect UserInfo endpoint
- User registration and authentication
- Client management via CLI
- Session management with secure cookies
- Token refresh and revocation

## Prerequisites

This project requires a few CLI tools:
```shell
# swaggo/swag for generating openapi docs
go install github.com/swaggo/swag/cmd/swag@latest
# sqlc-dev/sqlc for generating type-safe database code
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
# golang-migrate/migrate for migrations
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
```

## Environment Variables

Create a `.env` file (or `.env.dev` for development) in the project root:

```env
# Database connection (required)
DATABASE_URL=postgresql://user:password@localhost:5432/identity?sslmode=disable

# HTTP server address (optional, defaults shown)
HTTP_ADDRESS=http://localhost:8080  # dev
# HTTP_ADDRESS=https://identity.example.com  # production

# Session configuration (optional)
SESSION_SECRET=your-random-secret-key-at-least-32-chars
```

## Setup

1. **Start PostgreSQL** (via Docker or local install):
   ```shell
   docker run -d --name identity-db \
     -e POSTGRES_USER=identity \
     -e POSTGRES_PASSWORD=identity \
     -e POSTGRES_DB=identity \
     -p 5432:5432 \
     postgres:15
   ```

2. **Run database migrations:**
   ```shell
   DATABASE_URL="postgresql://identity:identity@localhost:5432/identity?sslmode=disable" make migrate-up
   ```

3. **Build the server and CLI:**
   ```shell
   make build
   ```

4. **Start the server:**
   ```shell
   ENV=dev ./identity
   ```

   The server will be available at `http://localhost:8080`.

## User Management

### Creating Users

Users can register via the web UI:
```
http://localhost:8080/oauth/register
```

Or create users programmatically using the database directly.

### User Login

Login page (standalone or via OAuth flow):
```
http://localhost:8080/login
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

## OAuth Client Management

### Adding a New Client

1. **Build the CLI:**
   ```shell
   make build
   ```

2. **Create a public client** (for SPAs like React apps):
   ```shell
   ENV=dev ./identity-cli client create \
     --name "My App (Dev)" \
     --redirect-uris "http://localhost:5173/oauth/callback" \
     --scopes "openid,profile,email"
   ```

   Or **create a confidential client** (for backend services):
   ```shell
   ENV=dev ./identity-cli client create \
     --name "My Service" \
     --redirect-uris "https://myservice.com/callback" \
     --scopes "openid,profile,email" \
     --confidential
   ```

   Save the returned `client_id` (and `client_secret` if confidential).

### Other Client Commands

- `./identity-cli client list` - List all clients
- `./identity-cli client get <client-id>` - Get client details
- `./identity-cli client update <client-id> --name "New Name"` - Update client
- `./identity-cli client delete <client-id>` - Delete client

## OAuth Endpoints

### Authorization & Token Endpoints

- `GET /oauth/authorize` - Start OAuth authorization flow
  - Query params: `client_id`, `redirect_uri`, `state`, `scope`, `code_challenge`, `code_challenge_method`
- `POST /oauth/token` - Exchange authorization code for tokens
  - Form params: `grant_type`, `code`, `client_id`, `redirect_uri`, `code_verifier`
- `POST /oauth/token` - Refresh access token
  - Form params: `grant_type=refresh_token`, `refresh_token`, `client_id`

### User Info & Session

- `GET /oauth/userinfo` - Get user info from access token
  - Header: `Authorization: Bearer <access_token>`
  - Returns: `sub`, `username`, `email`, `email_verified`
- `GET /login` - Login page (standalone or via OAuth)
- `POST /login` - Process login credentials
- `GET /oauth/register` - User registration page
- `POST /oauth/register` - Create new user account
- `GET /oauth/success` - Post-login success page

### Health & Documentation

- `GET /health` - Health check endpoint
- `GET /docs` - API documentation (Swagger/OpenAPI)

## OAuth Flow Example

For a Single Page Application (SPA) using PKCE:

1. **Generate PKCE values** in your client:
   ```javascript
   const codeVerifier = generateRandomString(32);
   const codeChallenge = await sha256(codeVerifier);
   ```

2. **Redirect to authorization endpoint:**
   ```
   http://localhost:8080/oauth/authorize?
     client_id=YOUR_CLIENT_ID&
     redirect_uri=http://localhost:5173/oauth/callback&
     response_type=code&
     state=RANDOM_STATE&
     scope=openid profile email&
     code_challenge=CODE_CHALLENGE&
     code_challenge_method=S256
   ```

3. **User logs in** and is redirected back with authorization code:
   ```
   http://localhost:5173/oauth/callback?
     code=AUTHORIZATION_CODE&
     state=RANDOM_STATE
   ```

4. **Exchange code for tokens:**
   ```http
   POST /oauth/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code&
   code=AUTHORIZATION_CODE&
   client_id=YOUR_CLIENT_ID&
   redirect_uri=http://localhost:5173/oauth/callback&
   code_verifier=CODE_VERIFIER
   ```

5. **Receive tokens:**
   ```json
   {
     "access_token": "...",
     "refresh_token": "...",
     "expires_in": 3600,
     "token_type": "Bearer",
     "scope": ["openid", "profile", "email"]
   }
   ```

6. **Use access token** to call protected APIs:
   ```http
   GET /oauth/userinfo
   Authorization: Bearer ACCESS_TOKEN
   ```

## Development

Start the server in development mode:
```shell
ENV=dev ./identity
```

Watch logs for debugging:
```shell
ENV=dev LOG_LEVEL=debug ./identity
```
