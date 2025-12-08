# Auth Service Requirements Document

## Overview

Build a standalone OAuth2/OIDC authentication service in Go that handles user authentication for the forecasting application. The service will implement the OAuth2 authorization code flow with PKCE and expose OIDC-compliant endpoints.

**Learning Goals:**
- Understand OAuth2/OIDC protocol implementation
- Build a production-grade auth service in Go
- Implement secure token management and cryptography
- Design cross-service authentication patterns

## Technical Stack

- **Language:** Go 1.21+
- **HTTP Framework:** Gin or Chi (lightweight, idiomatic Go)
- **Database:** PostgreSQL (shared with main Next.js app)
- **Database Client:** pgx or GORM
- **JWT Library:** golang-jwt/jwt
- **Password Hashing:** crypto/argon2 (standard library + golang.org/x/crypto)
- **Configuration:** Environment variables (godotenv for local dev)
- **Containerization:** Docker

## Core Requirements

### 1. OAuth2 Authorization Code Flow with PKCE

Implement the standard OAuth2 authorization code flow as defined in RFC 6749, with PKCE extension (RFC 7636).

**Flow:**
1. Client initiates login → redirects to `/authorize`
2. User authenticates → auth service validates credentials
3. Auth service redirects back with authorization code
4. Client exchanges code for tokens at `/token`
5. Client uses access token to authenticate with main app
6. Client refreshes tokens when expired

### 2. OpenID Connect (OIDC) Layer

Add OIDC on top of OAuth2 to provide identity information (RFC 7519).

**Requirements:**
- ID tokens (JWT) containing user claims
- UserInfo endpoint for fetching user profile
- Discovery endpoint for client configuration
- JWKS endpoint for public key distribution

## API Endpoints

### Authentication Endpoints

#### `GET /authorize`
OAuth2 authorization endpoint (user-facing).

**Query Parameters:**
- `response_type` (required): Must be `code`
- `client_id` (required): Registered client identifier
- `redirect_uri` (required): Where to send the user after auth
- `scope` (required): Requested scopes (e.g., `openid profile email`)
- `state` (required): CSRF protection token
- `code_challenge` (required): PKCE code challenge (SHA256 hash)
- `code_challenge_method` (required): Must be `S256`

**Behavior:**
1. Validate all parameters
2. Check if user is already authenticated (session cookie)
3. If not authenticated, render login page
4. If authenticated, generate authorization code and redirect to `redirect_uri`

**Success Response:**
```
HTTP/1.1 302 Found
Location: {redirect_uri}?code={auth_code}&state={state}
```

**Error Response:**
```
HTTP/1.1 302 Found
Location: {redirect_uri}?error=invalid_request&error_description={description}&state={state}
```

#### `POST /token`
OAuth2 token endpoint (machine-to-machine).

**Request Body (application/x-www-form-urlencoded):**

For authorization code exchange:
```
grant_type=authorization_code
code={authorization_code}
redirect_uri={redirect_uri}
client_id={client_id}
client_secret={client_secret}
code_verifier={code_verifier}  // PKCE verifier
```

For refresh token:
```
grant_type=refresh_token
refresh_token={refresh_token}
client_id={client_id}
client_secret={client_secret}
```

**Success Response:**
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGc...",
  "id_token": "eyJhbGc...",
  "scope": "openid profile email"
}
```

**Error Response:**
```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code is invalid or expired"
}
```

#### `POST /login`
Process login form submission (called from login page).

**Request Body (application/x-www-form-urlencoded):**
```
username={username}
password={password}
```

**Plus original OAuth parameters from hidden form fields:**
```
client_id, redirect_uri, state, scope, code_challenge, code_challenge_method
```

**Behavior:**
1. Validate username/password against database
2. Create authenticated session (secure HTTP-only cookie)
3. Generate authorization code
4. Redirect to client with authorization code

#### `POST /logout`
Invalidate user session and tokens.

**Request:**
```
POST /logout
Cookie: session_id={session_id}
```

**Optional Query Parameters:**
- `post_logout_redirect_uri`: Where to redirect after logout
- `state`: State to include in redirect

**Behavior:**
1. Delete session cookie
2. Invalidate refresh tokens in database
3. Redirect to logout URI or default page

### OIDC Discovery Endpoints

#### `GET /.well-known/openid-configuration`
OIDC discovery document.

**Response:**
```json
{
  "issuer": "https://auth.yourapp.com",
  "authorization_endpoint": "https://auth.yourapp.com/authorize",
  "token_endpoint": "https://auth.yourapp.com/token",
  "userinfo_endpoint": "https://auth.yourapp.com/userinfo",
  "jwks_uri": "https://auth.yourapp.com/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "token_endpoint_auth_methods_supported": ["client_secret_post"],
  "code_challenge_methods_supported": ["S256"]
}
```

#### `GET /.well-known/jwks.json`
JSON Web Key Set (public keys for JWT verification).

**Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "2024-12-07",
      "n": "0vx7agoebGcQSuuPiLJXZpt...",
      "e": "AQAB"
    }
  ]
}
```

#### `GET /userinfo`
OIDC UserInfo endpoint (requires valid access token).

**Request:**
```
GET /userinfo
Authorization: Bearer {access_token}
```

**Response:**
```json
{
  "sub": "123",
  "username": "john_doe",
  "email": "john@example.com",
  "email_verified": true
}
```

### Health & Monitoring

#### `GET /health`
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "database": "connected",
  "version": "1.0.0"
}
```

## Database Requirements

### Dedicated Database

The auth service has its own PostgreSQL database. This service handles all authentication and identity management, including user creation, authentication, and OAuth/OIDC flows.

### Required Tables

#### `users` (or `auth_users`)
Auth service manages this table for user accounts:
- `id`: User identifier (UUID)
- `username`: Unique username for login
- `password_hash`: Argon2id hash for password verification
- `email`: User email address (for OIDC claims and account management)
- `is_active`: Account status flag
- `created_at`: Account creation timestamp
- `updated_at`: Last update timestamp

#### `oauth_clients` (new table)
Store registered OAuth2 clients.

```sql
CREATE TABLE oauth_clients (
  id VARCHAR(255) PRIMARY KEY,
  client_secret_hash TEXT NOT NULL,
  redirect_uris TEXT[] NOT NULL,
  allowed_scopes TEXT[] NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
```

**Initial client:** The Next.js forecasting app needs to be registered.

#### `oauth_authorization_codes` (new table)
Temporary storage for authorization codes (short-lived, ~10 minutes).

```sql
CREATE TABLE oauth_authorization_codes (
  code VARCHAR(255) PRIMARY KEY,
  client_id VARCHAR(255) NOT NULL REFERENCES oauth_clients(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method VARCHAR(10) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_codes_expires ON oauth_authorization_codes(expires_at);
```

#### `oauth_refresh_tokens` (new table)
Long-lived refresh tokens.

```sql
CREATE TABLE oauth_refresh_tokens (
  token_hash VARCHAR(255) PRIMARY KEY,
  client_id VARCHAR(255) NOT NULL REFERENCES oauth_clients(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  scope TEXT NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_user ON oauth_refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires ON oauth_refresh_tokens(expires_at);
```

#### `auth_sessions` (new table)
Web sessions for the login flow (before authorization code is issued).

```sql
CREATE TABLE auth_sessions (
  id VARCHAR(255) PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_expires ON auth_sessions(expires_at);
```

### Database Connection

**Connection String Format:**
```
postgresql://user:password@host:port/database?sslmode=require
```

Use environment variable: `DATABASE_URL`

## Token Requirements

### Access Token (JWT)

**Algorithm:** RS256 (RSA signature with SHA-256)
**Expiration:** 1 hour
**Issuer:** `https://auth.yourapp.com`

**Claims:**
```json
{
  "iss": "https://auth.yourapp.com",
  "sub": "123",
  "aud": "forecasting-app",
  "exp": 1701964800,
  "iat": 1701961200,
  "scope": "openid profile email"
}
```

### ID Token (JWT)

**Algorithm:** RS256
**Expiration:** 1 hour

**Claims:**
```json
{
  "iss": "https://auth.yourapp.com",
  "sub": "123",
  "aud": "forecasting-app",
  "exp": 1701964800,
  "iat": 1701961200,
  "username": "john_doe",
  "email": "john@example.com",
  "email_verified": true
}
```

### Refresh Token

**Format:** Opaque random string (not JWT)
**Storage:** Hashed in database (use SHA-256)
**Expiration:** 30 days
**Rotation:** Issue new refresh token on each use (optional but recommended)

### RSA Key Pair

**Requirements:**
- 2048-bit RSA key pair
- Private key for signing JWTs
- Public key exposed via JWKS endpoint
- Key ID (kid) in JWT header for key rotation support

**Generation (one-time setup):**
```bash
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

**Storage:**
- Private key: Environment variable or file (never commit to git)
- Public key: Can be committed or derived from private key

## Security Requirements

### Password Handling
- Never log passwords
- Use Argon2id for password hashing (existing in main app)
- Minimum password length: 8 characters (enforced by main app)

### PKCE (Proof Key for Code Exchange)
- Required for all authorization code flows
- Only support S256 (SHA-256) challenge method
- Verify code_verifier matches code_challenge on token exchange

### CSRF Protection
- Validate `state` parameter in OAuth flow
- Use secure session cookies with SameSite=Lax

### Token Security
- Access tokens: Short-lived (1 hour)
- Refresh tokens: Hashed in database, long-lived (30 days)
- Authorization codes: Single-use, expire in 10 minutes
- Implement token revocation on logout

### Session Security
- HTTP-only cookies
- Secure flag (HTTPS only)
- SameSite=Lax
- Random session IDs (cryptographically secure)

### Rate Limiting
- `/login`: 5 attempts per IP per minute
- `/token`: 10 requests per client per minute
- `/authorize`: 20 requests per IP per minute

### Input Validation
- Validate all OAuth parameters against spec
- Sanitize inputs to prevent injection attacks
- Validate redirect_uri against registered URIs (exact match)

## Configuration

### Environment Variables

```bash
# Server
PORT=8080
BASE_URL=http://localhost:8080

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/forecasting

# JWT Keys
JWT_PRIVATE_KEY_PATH=/path/to/private_key.pem
# Or inline:
# JWT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n..."

# Security
SESSION_SECRET=random-secret-for-session-cookies

# CORS (for Next.js app)
ALLOWED_ORIGINS=http://localhost:3000,https://yourapp.com

# Optional
LOG_LEVEL=info
ENVIRONMENT=development
```

## Integration with Next.js App

### User Management

The Next.js app should use the auth service's API endpoints for:
- User registration (POST /register)
- User authentication (via OAuth2 flow)
- User profile management (via OIDC UserInfo endpoint)

### Client Registration

The Next.js app must be registered as an OAuth client:

```sql
INSERT INTO oauth_clients (id, client_secret_hash, redirect_uris, allowed_scopes)
VALUES (
  'forecasting-app',
  '{argon2_hash_of_secret}',
  ARRAY['http://localhost:3000/api/auth/callback', 'https://yourapp.com/api/auth/callback'],
  ARRAY['openid', 'profile', 'email']
);
```

### Next.js Changes Required

1. **User Registration:** `/app/api/auth/register/route.ts`
   - Call auth service `/register` endpoint
   - Handle registration response

2. **New API route:** `/app/api/auth/callback/route.ts`
   - Handle OAuth callback
   - Exchange authorization code for tokens
   - Store tokens in session
   - Redirect to app

3. **New login flow:** `/app/login/page.tsx`
   - Redirect to auth service `/authorize` endpoint
   - Include PKCE parameters

4. **Token validation:**
   - Fetch JWKS from auth service
   - Validate JWT signature on each request
   - Extract user_id from `sub` claim

5. **Session mapping:**
   - Map OAuth `sub` to local user ID
   - Could add `oauth_sub` column to users table, or use user.id as sub

### Example Integration Flow

```typescript
// Next.js - Initiate login
export async function GET() {
  const codeVerifier = generateRandomString(64);
  const codeChallenge = await sha256(codeVerifier);
  const state = generateRandomString(32);

  // Store verifier and state in session
  cookies().set('pkce_verifier', codeVerifier);
  cookies().set('oauth_state', state);

  const authUrl = new URL('http://localhost:8080/authorize');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', 'forecasting-app');
  authUrl.searchParams.set('redirect_uri', 'http://localhost:3000/api/auth/callback');
  authUrl.searchParams.set('scope', 'openid profile email');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  return redirect(authUrl.toString());
}

// Next.js - Handle callback
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const code = searchParams.get('code');
  const state = searchParams.get('state');

  // Validate state
  const storedState = cookies().get('oauth_state');
  if (state !== storedState?.value) {
    throw new Error('Invalid state');
  }

  // Exchange code for tokens
  const codeVerifier = cookies().get('pkce_verifier')?.value;
  const response = await fetch('http://localhost:8080/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code!,
      redirect_uri: 'http://localhost:3000/api/auth/callback',
      client_id: 'forecasting-app',
      client_secret: process.env.OAUTH_CLIENT_SECRET!,
      code_verifier: codeVerifier!
    })
  });

  const tokens = await response.json();

  // Decode ID token to get user info
  const idToken = jwt.decode(tokens.id_token);
  const userId = idToken.sub;

  // Create session with user ID
  await createSession(userId, tokens.access_token, tokens.refresh_token);

  return redirect('/dashboard');
}
```

## UI Requirements

### Login Page

The auth service must serve an HTML login page at `/login` or render it in `/authorize` flow.

**Requirements:**
- Form with username and password fields
- CSRF protection
- Display error messages (invalid credentials, etc.)
- Preserve OAuth parameters through login process (hidden form fields)
- Simple, functional UI (doesn't need to match main app styling)

**Template (Go html/template):**
```html
<!DOCTYPE html>
<html>
<head>
  <title>Login - Forecasting App</title>
</head>
<body>
  <h1>Sign In</h1>
  {{if .Error}}
    <div class="error">{{.Error}}</div>
  {{end}}
  <form method="POST" action="/login">
    <input type="text" name="username" placeholder="Username" required>
    <input type="password" name="password" placeholder="Password" required>

    <!-- Preserve OAuth params -->
    <input type="hidden" name="client_id" value="{{.ClientID}}">
    <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
    <input type="hidden" name="state" value="{{.State}}">
    <input type="hidden" name="scope" value="{{.Scope}}">
    <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
    <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">

    <button type="submit">Sign In</button>
  </form>
</body>
</html>
```

## Error Handling

### OAuth2 Error Codes

Follow RFC 6749 error codes:
- `invalid_request`: Missing or malformed parameters
- `unauthorized_client`: Client not authorized
- `access_denied`: User denied authorization
- `unsupported_response_type`: Server doesn't support response type
- `invalid_scope`: Invalid or unknown scope
- `server_error`: Internal server error
- `invalid_grant`: Invalid authorization code or refresh token
- `invalid_client`: Client authentication failed

### Error Response Format

For `/token` endpoint (JSON):
```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code has expired"
}
```

For `/authorize` endpoint (redirect):
```
{redirect_uri}?error=access_denied&error_description=User%20cancelled&state={state}
```

## Out of Scope (For Initial Version)

These features are not required for the initial learning implementation:

- Password reset flow
- Email verification
- Multi-factor authentication (MFA)
- Social login (Google, GitHub, etc.)
- Client credentials grant type
- Implicit flow (deprecated, don't implement)
- Admin API for managing clients
- Account management (password change, etc.)
- Consent screen (assume user consents to own app)
- Dynamic client registration
- Key rotation automation

## Testing Requirements

### Manual Testing Checklist

- [ ] Complete OAuth flow from Next.js app
- [ ] Login with valid credentials
- [ ] Login with invalid credentials
- [ ] Authorization code can only be used once
- [ ] Authorization code expires after 10 minutes
- [ ] Access token expires after 1 hour
- [ ] Refresh token works to get new access token
- [ ] PKCE validation fails with wrong code_verifier
- [ ] State parameter prevents CSRF
- [ ] Invalid redirect_uri is rejected
- [ ] Logout invalidates session and tokens
- [ ] JWKS endpoint returns valid public key
- [ ] Next.js app can validate JWT signature

### Go Unit Tests

Recommended test coverage:
- Token generation and validation
- PKCE challenge/verifier matching
- Password verification
- Authorization code lifecycle
- Refresh token rotation
- Input validation
- Error handling

## Deployment

### Docker Container

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o auth-service .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/auth-service .
COPY --from=builder /app/templates ./templates
EXPOSE 8080
CMD ["./auth-service"]
```

### Local Development

```bash
# Run PostgreSQL (if not already running)
docker compose -f local-pg-container.yaml up

# Run auth service
cd auth-service
go run main.go

# Run Next.js app
cd forecasting
ENV=local npm run dev
```

Auth service runs on: `http://localhost:8080`
Next.js app runs on: `http://localhost:3000`

## Success Criteria

The auth service is complete when:

1. ✅ User can log in via Next.js app using OAuth2 flow
2. ✅ JWT tokens are properly signed and validated
3. ✅ PKCE prevents authorization code interception
4. ✅ Refresh tokens work to extend sessions
5. ✅ Logout properly invalidates tokens
6. ✅ OIDC discovery endpoints are functional
7. ✅ Database properly stores OAuth state
8. ✅ All security requirements are met
9. ✅ Error handling follows OAuth2 spec
10. ✅ You understand how the OAuth2 flow works end-to-end!

## Resources

- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [PKCE RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [JWT RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
