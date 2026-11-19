CREATE TABLE registration_mail_jobs (
    user_id UUID PRIMARY KEY REFERENCES registrations (user_id) ON DELETE CASCADE,
    token_nonce BYTEA NOT NULL CHECK (octet_length(token_nonce) = 12),
    token_ciphertext BYTEA NOT NULL,
    available_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lease_id UUID,
    lease_until TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    CHECK ((lease_id IS NULL) = (lease_until IS NULL))
);

CREATE INDEX registration_mail_jobs_available_at_idx ON registration_mail_jobs (available_at);
