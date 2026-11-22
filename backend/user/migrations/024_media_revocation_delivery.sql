ALTER TABLE user_media_revocation_outbox
    ADD COLUMN lease_token UUID,
    ADD COLUMN lease_until TIMESTAMPTZ,
    ADD COLUMN delivered_at TIMESTAMPTZ,
    ADD CHECK ((lease_token IS NULL)=(lease_until IS NULL)),
    ADD CHECK (delivered_at IS NULL OR lease_token IS NULL);

CREATE INDEX user_media_revocation_pending_idx ON user_media_revocation_outbox(revoked_at,media_id)
    WHERE delivered_at IS NULL;

CREATE FUNCTION user_claim_media_revocation()
RETURNS TABLE(media_id UUID,owner_id UUID,lease_token UUID)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    WITH candidate AS (
        SELECT e.media_id FROM public.user_media_revocation_outbox e
        WHERE e.delivered_at IS NULL AND (e.lease_until IS NULL OR e.lease_until<=statement_timestamp())
        ORDER BY e.revoked_at,e.media_id LIMIT 1 FOR UPDATE SKIP LOCKED
    )
    UPDATE public.user_media_revocation_outbox e SET
        lease_token=gen_random_uuid(),lease_until=clock_timestamp()+INTERVAL '30 seconds'
    FROM candidate c WHERE e.media_id=c.media_id
    RETURNING e.media_id,e.owner_id,e.lease_token
$$;

CREATE FUNCTION user_ack_media_revocation(asset UUID, token UUID) RETURNS VOID
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    UPDATE public.user_media_revocation_outbox SET
        delivered_at=clock_timestamp(),lease_token=NULL,lease_until=NULL
    WHERE media_id=asset AND lease_token=token AND delivered_at IS NULL
$$;

REVOKE ALL ON FUNCTION user_claim_media_revocation(),user_ack_media_revocation(UUID,UUID) FROM PUBLIC;
