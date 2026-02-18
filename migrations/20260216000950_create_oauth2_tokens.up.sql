-- Up migration
CREATE TABLE IF NOT EXISTS oauth2_tokens (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    access_token_hash  TEXT NOT NULL UNIQUE,
    refresh_token_hash TEXT,
    client_id          TEXT NOT NULL,
    user_id            UUID,
    scopes             TEXT[] NOT NULL,
    issued_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at         TIMESTAMPTZ,
    revoked            BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_oauth2_access_hash ON oauth2_tokens(access_token_hash);
CREATE INDEX IF NOT EXISTS idx_oauth2_refresh_hash ON oauth2_tokens(refresh_token_hash);
