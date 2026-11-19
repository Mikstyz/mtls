ALTER TABLE credentials ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE password_resets (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES credentials (user_id) ON DELETE CASCADE,
    password_revision BIGINT NOT NULL CHECK (password_revision > 0),
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    token_nonce BYTEA,
    token_ciphertext BYTEA,
    expires_at TIMESTAMPTZ NOT NULL,
    available_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lease_id UUID,
    lease_until TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    CHECK ((token_nonce IS NULL) = (token_ciphertext IS NULL)),
    CHECK (token_nonce IS NULL OR octet_length(token_nonce) = 12),
    CHECK ((lease_id IS NULL) = (lease_until IS NULL))
);

CREATE INDEX password_resets_user_id_idx ON password_resets (user_id);
CREATE INDEX password_resets_expires_at_idx ON password_resets (expires_at);
