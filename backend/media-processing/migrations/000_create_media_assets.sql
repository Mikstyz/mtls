CREATE TABLE media_assets (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL,
    request_id UUID NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('photo', 'video')),
    state TEXT NOT NULL DEFAULT 'reserved' CHECK (state IN ('reserved', 'processing', 'processed', 'deleting')),
    lease_token UUID,
    lease_until TIMESTAMPTZ,
    processed_lease_token UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (owner_id, request_id),
    CHECK ((state = 'processing') = (lease_token IS NOT NULL AND lease_until IS NOT NULL)),
    CHECK ((lease_token IS NULL) = (lease_until IS NULL)),
    CHECK (state <> 'processed' OR processed_lease_token IS NOT NULL)
);

CREATE INDEX media_assets_owner_idx ON media_assets (owner_id, id);

CREATE TABLE media_variants (
    asset_id UUID NOT NULL REFERENCES media_assets(id),
    name TEXT NOT NULL CHECK (name IN ('original.jpg', 'preview.jpg', 'original.png', 'preview.png')),
    byte_size BIGINT NOT NULL CHECK (byte_size > 0 AND byte_size <= 33554432),
    sha256 BYTEA NOT NULL CHECK (octet_length(sha256) = 32),
    PRIMARY KEY (asset_id, name)
);
