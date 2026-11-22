BEGIN;

CREATE INDEX search_documents_kind_version_idx
    ON search_documents (kind, source_version DESC);

COMMIT;
