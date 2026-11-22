ALTER TABLE user_profile_moderation_outbox
    ADD COLUMN lease_token UUID,
    ADD COLUMN lease_until TIMESTAMPTZ,
    ADD CHECK ((lease_token IS NULL)=(lease_until IS NULL));

CREATE FUNCTION user_claim_profile_points_event()
RETURNS TABLE(id BIGINT,case_id UUID,owner_id UUID,operation TEXT,reason TEXT,lease_token UUID)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    WITH candidate AS (
        SELECT e.id FROM public.user_profile_moderation_outbox e
        WHERE e.lease_until IS NULL OR e.lease_until<=statement_timestamp()
        ORDER BY e.id LIMIT 1 FOR UPDATE SKIP LOCKED
    )
    UPDATE public.user_profile_moderation_outbox e
    SET lease_token=gen_random_uuid(),lease_until=clock_timestamp()+INTERVAL '30 seconds'
    FROM candidate c WHERE e.id=c.id
    RETURNING e.id,e.case_id,e.owner_id,e.operation,e.reason,e.lease_token
$$;

CREATE FUNCTION user_ack_profile_points_event(event_id BIGINT, token UUID) RETURNS VOID
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DELETE FROM public.user_profile_moderation_outbox
    WHERE id=event_id AND lease_token=token
$$;

REVOKE ALL ON FUNCTION user_claim_profile_points_event(),user_ack_profile_points_event(BIGINT,UUID) FROM PUBLIC;
