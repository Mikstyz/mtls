BEGIN;

CREATE TABLE search_documents (
    kind text NOT NULL CHECK (kind IN ('user', 'content')),
    id uuid NOT NULL,
    source_version bigint NOT NULL CHECK (source_version > 0),
    deleted boolean NOT NULL,
    search_text text NOT NULL CHECK (octet_length(search_text) <= 4096),
    document tsvector GENERATED ALWAYS AS (to_tsvector('simple', search_text)) STORED,
    PRIMARY KEY (kind, id),
    CHECK (NOT deleted OR search_text = '')
);

CREATE INDEX search_documents_document_gin
    ON search_documents USING gin (document)
    WHERE NOT deleted;

COMMIT;
