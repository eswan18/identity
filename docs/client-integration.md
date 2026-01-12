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
