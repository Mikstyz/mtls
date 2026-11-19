BEGIN;

CREATE TABLE search_version_floors (
    kind TEXT PRIMARY KEY CHECK (kind IN ('user', 'content')),
    min_version BIGINT NOT NULL CHECK (min_version >= 0)
);

INSERT INTO search_version_floors (kind, min_version) VALUES ('user', 0), ('content', 0);

COMMIT;
