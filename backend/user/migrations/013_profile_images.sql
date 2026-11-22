CREATE TABLE user_profile_images (
    owner_id UUID NOT NULL,
    slot TEXT NOT NULL CHECK (slot IN ('avatar','banner')),
    media_id UUID NOT NULL REFERENCES media_permissions(media_id) ON DELETE CASCADE,
    PRIMARY KEY (owner_id,slot)
);

CREATE TABLE user_profile_image_history (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_id UUID NOT NULL,
    slot TEXT NOT NULL CHECK (slot IN ('avatar','banner')),
    operation TEXT NOT NULL CHECK (operation IN ('added','replaced','removed')),
    media_id UUID NOT NULL,
    previous_media_id UUID,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX user_profile_image_history_owner_idx ON user_profile_image_history(owner_id,id DESC);
