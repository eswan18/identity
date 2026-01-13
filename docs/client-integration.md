# Client Application Integration Guide

This guide explains how to integrate your application with this Identity Provider (IdP), including how to handle user authentication, store user data, and manage authorization (roles/permissions) within your app.

## Key Concepts

### Authentication vs Authorization

- **Authentication (AuthN):** "Who is this user?" — handled by this IdP
- **Authorization (AuthZ):** "What can this user do in my app?" — handled by your app

This IdP authenticates users and tells your app *who* they are. Your app decides what permissions they have.

## Step 1: Register Your Client Application

Before integrating, register your app as an OAuth client:

```shell
./identity-cli client create \
  --name "My App" \
  --redirect-uris "https://myapp.com/oauth/callback" \
  --scopes "openid,profile,email"
```

Save the returned `client_id` (and `client_secret` if using `--confidential`).

## Step 2: Implement the OAuth Flow

See the main [README](../README.md#oauth-flow-example) for the full OAuth/PKCE flow. In summary:

1. Redirect user to `/oauth/authorize` with your `client_id` and PKCE challenge
2. User logs in (and enters MFA code if they have two-factor authentication enabled)
3. User is redirected back with an authorization code
4. Exchange the code for tokens at `/oauth/token`
5. Use the access token to call `/oauth/userinfo` or your own APIs

**Note:** MFA is handled entirely within the IdP. Your client application doesn't need to do anything special — the user will be prompted for their MFA code during the login flow before being redirected back to your app.

## Step 3: Understanding the Access Token

The access token is a JWT containing these claims:

| Claim | Description | Example |
|-------|-------------|---------|
| `sub` | User's unique ID (UUID) | `550e8400-e29b-41d4-a716-446655440000` |
| `username` | User's username | `alice` |
| `email` | User's email address | `alice@example.com` |
| `scope` | Granted scopes (space-separated) | `openid profile email` |
| `aud` | Audience (your client_id) | `my-app-client-id` |
| `iss` | Issuer URL | `https://identity.example.com` |
| `exp` | Expiration timestamp | `1699900800` |

**Important:** Use the `sub` claim as the stable user identifier. Email and username can change; `sub` never will.

## Step 4: Store Users in Your Application

Your app should maintain its own users table that references the IdP user.

### Recommended Schema

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Link to IdP (use the 'sub' claim from the token)
    idp_user_id UUID NOT NULL UNIQUE,

    -- Cached profile info (for display purposes)
    -- Treat as potentially stale; update on each login
    email TEXT,
    username TEXT,

    -- App-specific authorization
    role TEXT NOT NULL DEFAULT 'viewer',  -- e.g., 'viewer', 'editor', 'admin'

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_users_idp_user_id ON users(idp_user_id);
```

### Why This Structure?

- **`idp_user_id`**: The `sub` from the JWT. This is your foreign key to the IdP. Never changes.
- **`email` / `username`**: Cached for display. Update these on each login in case they changed.
- **`role`**: Your app's authorization. The IdP doesn't know or care about this.

## Step 5: Handle User Login in Your App

When a user completes the OAuth flow:

```python
# Pseudocode - adapt to your language/framework

def handle_oauth_callback(authorization_code):
    # 1. Exchange code for tokens
    tokens = exchange_code_for_tokens(authorization_code)

    # 2. Decode the access token (or call /oauth/userinfo)
    claims = decode_jwt(tokens.access_token)

    # 3. Look up or create user in your database
    user = db.query("SELECT * FROM users WHERE idp_user_id = ?", claims.sub)

    if user is None:
        # First login - create user record
        user = db.insert("INSERT INTO users (idp_user_id, email, username, role) VALUES (?, ?, ?, 'viewer')",
                         claims.sub, claims.email, claims.username)
    else:
        # Returning user - update cached profile info
        db.update("UPDATE users SET email = ?, username = ?, updated_at = now() WHERE id = ?",
                  claims.email, claims.username, user.id)

    # 4. Create session for user
    create_session(user)
```

## Step 6: Implement Authorization (Roles/Permissions)

Authorization is your app's responsibility. Common patterns:

### Simple Role Check

```python
def require_admin(user):
    if user.role != 'admin':
        raise ForbiddenError("Admin access required")

@app.route("/admin/settings")
def admin_settings():
    require_admin(current_user)
    # ... admin-only logic
```

### Role Hierarchy

```python
ROLE_LEVELS = {'viewer': 1, 'editor': 2, 'admin': 3}

def require_role(user, minimum_role):
    if ROLE_LEVELS.get(user.role, 0) < ROLE_LEVELS[minimum_role]:
        raise ForbiddenError(f"{minimum_role} access required")
```

## Step 7: Bootstrap Your First Admin

The first admin must be set manually. Choose one of these approaches:

### Option A: Environment Variable

```python
# On login, check if user should be auto-promoted
INITIAL_ADMIN_EMAILS = os.getenv("INITIAL_ADMIN_EMAILS", "").split(",")

def maybe_promote_initial_admin(user):
    if user.email in INITIAL_ADMIN_EMAILS and user.role == 'viewer':
        user.role = 'admin'
        db.save(user)
```

### Option B: Database Seed/Migration

```sql
-- Run after your first admin has logged in once
UPDATE users SET role = 'admin' WHERE email = 'founder@example.com';
```

### Option C: First User Becomes Admin

```python
def create_user(idp_user_id, email, username):
    user_count = db.query("SELECT COUNT(*) FROM users")[0]
    role = 'admin' if user_count == 0 else 'viewer'
    return db.insert("INSERT INTO users (..., role) VALUES (..., ?)", role)
```

## Step 8: Build an Admin UI (Optional)

Once you have one admin, let them manage others through your app:

```
/admin/users           - List all users with their roles
/admin/users/:id/edit  - Change a user's role
```

This is just a simple CRUD interface that updates the `role` column.

## Complete Integration Checklist

- [ ] Register your app as an OAuth client
- [ ] Implement OAuth flow with PKCE
- [ ] Create a `users` table with `idp_user_id` and `role` columns
- [ ] On login: look up user by `sub`, create if new, update cached profile
- [ ] Add role checks to protected routes/actions
- [ ] Bootstrap your first admin via env var, seed, or first-user logic
- [ ] (Optional) Build admin UI for managing user roles

## Service-to-Service Authentication (Client Credentials)

For server-side operations like user migration or automated tasks, use the OAuth2 client credentials grant. This allows your service to authenticate as itself (not on behalf of a user).

### Prerequisites

1. Register a **confidential** client with the required admin scopes:

```shell
./identity-cli client create \
  --name "Migration Service" \
  --redirect-uris "https://myapp.com/oauth/callback" \
  --scopes "admin:users:write,admin:users:read" \
  --confidential
```

2. Save both the `client_id` and `client_secret`.

### Getting a Service Token

```bash
curl -X POST https://identity.example.com/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "scope=admin:users:write"
```

Response:
```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Note:** Client credentials tokens:
- Expire in 15 minutes (shorter than user tokens)
- Do not include a refresh token (per OAuth2 spec)
- Have `client_id` as the `sub` claim (not a user ID)

### Admin API: Create Users

Use this to migrate existing users from a legacy system:

```bash
curl -X POST https://identity.example.com/admin/users \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "email": "alice@example.com",
    "password": "SecurePassword123!"
  }'
```

Response (201 Created):
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "alice",
  "email": "alice@example.com",
  "is_active": true,
  "email_verified": false,
  "created_at": "2024-01-15T10:30:00Z"
}
```

Error responses:
- `400 Bad Request` - Invalid input (weak password, invalid email format, etc.)
- `401 Unauthorized` - Missing or invalid token
- `403 Forbidden` - Token lacks `admin:users:write` scope
- `409 Conflict` - Username or email already exists

### User Migration Example

```python
import requests

class IdentityClient:
    def __init__(self, base_url, client_id, client_secret):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None

    def get_token(self):
        resp = requests.post(f"{self.base_url}/oauth/token", data={
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "admin:users:write"
        })
        resp.raise_for_status()
        self.token = resp.json()["access_token"]

    def create_user(self, username, email, password):
        if not self.token:
            self.get_token()

        resp = requests.post(
            f"{self.base_url}/admin/users",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"username": username, "email": email, "password": password}
        )

        if resp.status_code == 401:
            # Token expired, refresh and retry
            self.get_token()
            resp = requests.post(
                f"{self.base_url}/admin/users",
                headers={"Authorization": f"Bearer {self.token}"},
                json={"username": username, "email": email, "password": password}
            )

        return resp.json(), resp.status_code

# Usage
idp = IdentityClient("https://identity.example.com", "client_id", "client_secret")

for legacy_user in legacy_users:
    result, status = idp.create_user(
        legacy_user.username,
        legacy_user.email,
        legacy_user.password  # Or generate a temp password and force reset
    )
    if status == 201:
        print(f"Migrated {legacy_user.username}")
    elif status == 409:
        print(f"User {legacy_user.username} already exists")
    else:
        print(f"Failed to migrate {legacy_user.username}: {result}")
```

## FAQ

### Should I store the access token?

Only if you need to make API calls on behalf of the user. For simple authentication, you can discard it after extracting the claims and creating a session.

### What if a user's email changes?

That's why you use `sub` (the UUID) as your reference, not email. Update the cached email on each login, but your foreign key relationship remains stable.

### Can I have different roles in different apps?

Yes. Each app has its own `users` table with its own `role` column. User "alice" might be an admin in App A and a viewer in App B.

### How do I revoke access?

In your app, you can:
1. Set the user's role to something like `'disabled'`
2. Delete their row from your users table
3. Invalidate their session

The user can still authenticate with the IdP, but your app will deny them access.
