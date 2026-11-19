ALTER TABLE users ADD COLUMN presence_visibility TEXT NOT NULL DEFAULT 'everyone'
    CHECK (presence_visibility IN ('everyone', 'nobody'));

ALTER TABLE deleted_users ADD COLUMN presence_visibility TEXT NOT NULL DEFAULT 'everyone'
    CHECK (presence_visibility IN ('everyone', 'nobody'));
