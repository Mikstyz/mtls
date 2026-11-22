ALTER TABLE user_profile_moderation_outbox
    ADD COLUMN delivered_at TIMESTAMPTZ,
    ADD CONSTRAINT user_profile_points_delivered_has_no_lease
        CHECK (delivered_at IS NULL OR lease_token IS NULL);

-- Older publishers deleted acknowledgments. Reconstruct the durable source
-- from decisions and appeals. The receiver deduplicates by case.
INSERT INTO user_profile_moderation_outbox(case_id,owner_id,operation,reason,created_at)
SELECT r.case_id,r.owner_id,'deduct',r.reason,d.decided_at
FROM user_profile_image_reports r JOIN user_profile_image_decisions d USING(case_id)
WHERE d.action='remove'
ORDER BY d.decided_at,r.case_id
ON CONFLICT (case_id,operation) DO NOTHING;

INSERT INTO user_profile_moderation_outbox(case_id,owner_id,operation,reason,created_at)
SELECT r.case_id,r.owner_id,'reverse',r.reason,a.reviewed_at
FROM user_profile_image_reports r JOIN user_profile_image_appeals a USING(case_id)
WHERE a.outcome='reversed'
ORDER BY a.reviewed_at,r.case_id
ON CONFLICT (case_id,operation) DO NOTHING;

CREATE INDEX user_profile_points_undelivered_idx ON user_profile_moderation_outbox(id)
    WHERE delivered_at IS NULL;

CREATE OR REPLACE FUNCTION user_claim_profile_points_event()
RETURNS TABLE(id BIGINT,case_id UUID,owner_id UUID,operation TEXT,reason TEXT,lease_token UUID)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    WITH candidate AS (
        SELECT e.id FROM public.user_profile_moderation_outbox e
        WHERE e.delivered_at IS NULL
            AND (e.lease_until IS NULL OR e.lease_until<=statement_timestamp())
        ORDER BY e.id LIMIT 1 FOR UPDATE SKIP LOCKED
    )
    UPDATE public.user_profile_moderation_outbox e
    SET lease_token=gen_random_uuid(),lease_until=clock_timestamp()+INTERVAL '30 seconds'
    FROM candidate c WHERE e.id=c.id
    RETURNING e.id,e.case_id,e.owner_id,e.operation,e.reason,e.lease_token
$$;

CREATE OR REPLACE FUNCTION user_ack_profile_points_event(event_id BIGINT, token UUID) RETURNS VOID
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    UPDATE public.user_profile_moderation_outbox
    SET delivered_at=clock_timestamp(),lease_token=NULL,lease_until=NULL
    WHERE id=event_id AND lease_token=token AND delivered_at IS NULL
$$;
