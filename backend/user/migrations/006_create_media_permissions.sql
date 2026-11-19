CREATE TABLE media_permissions (
    media_id UUID PRIMARY KEY,
    owner_id UUID NOT NULL,
    visibility TEXT NOT NULL DEFAULT 'private' CHECK (visibility IN ('private', 'public')),
    ready BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX media_permissions_owner_id_idx ON media_permissions (owner_id);

CREATE TABLE media_permission_grants (
    media_id UUID NOT NULL REFERENCES media_permissions (media_id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    PRIMARY KEY (media_id, user_id)
);

CREATE INDEX media_permission_grants_user_id_idx ON media_permission_grants (user_id);
