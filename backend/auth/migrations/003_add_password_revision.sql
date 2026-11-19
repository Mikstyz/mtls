ALTER TABLE credentials ADD COLUMN password_revision BIGINT NOT NULL DEFAULT 1 CHECK (password_revision > 0);
