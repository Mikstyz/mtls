CREATE INDEX account_deletions_purge_deadline_idx
    ON account_deletions ((((deleted_at AT TIME ZONE 'UTC') + INTERVAL '2 months') AT TIME ZONE 'UTC'))
    WHERE state = 'deleted';
