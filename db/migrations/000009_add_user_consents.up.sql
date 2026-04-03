CREATE TABLE oauth_user_consents (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    client_id uuid NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scopes text[] NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    updated_at timestamptz DEFAULT now() NOT NULL,
    UNIQUE(user_id, client_id)
);
CREATE INDEX idx_oauth_user_consents_user_client ON oauth_user_consents(user_id, client_id);
