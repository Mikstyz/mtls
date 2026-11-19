CREATE TABLE media_uploads (
    asset_id UUID PRIMARY KEY REFERENCES media_assets(id),
    byte_size BIGINT NOT NULL CHECK (byte_size > 0 AND byte_size <= 1099511627776),
    sha256 BYTEA NOT NULL CHECK (octet_length(sha256) = 32),
    uploaded BOOLEAN NOT NULL DEFAULT FALSE
);
