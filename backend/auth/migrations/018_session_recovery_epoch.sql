CREATE TABLE session_epoch (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    generation BIGINT NOT NULL CHECK (generation >= 0)
);

INSERT INTO session_epoch (id, generation) VALUES (TRUE, 0);

ALTER TABLE sessions ADD COLUMN recovery_generation BIGINT NOT NULL DEFAULT 0
    CHECK (recovery_generation >= 0);
