CREATE TABLE security_journal_events (
    event_id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    event_type TEXT NOT NULL,
    payload BYTEA NOT NULL CHECK (octet_length(payload) <= 4096),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (user_id, version)
);

CREATE TABLE security_journal_offsets (
    topic TEXT NOT NULL,
    topic_id UUID NOT NULL,
    partition INTEGER NOT NULL CHECK (partition >= 0),
    next_offset BIGINT NOT NULL CHECK (next_offset >= 0),
    PRIMARY KEY (topic, partition)
);

CREATE TABLE security_journal_deliveries (
    topic TEXT NOT NULL,
    partition INTEGER NOT NULL,
    offset_value BIGINT NOT NULL CHECK (offset_value >= 0),
    event_id UUID NOT NULL REFERENCES security_journal_events (event_id),
    PRIMARY KEY (topic, partition, offset_value),
    FOREIGN KEY (topic, partition) REFERENCES security_journal_offsets (topic, partition)
);
