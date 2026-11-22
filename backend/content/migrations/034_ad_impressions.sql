ALTER TABLE content_ad_deliveries ADD COLUMN impressed_at TIMESTAMPTZ
    CHECK (impressed_at IS NULL OR impressed_at >= delivered_at);

ALTER TABLE content_ad_campaigns ADD COLUMN reported_impressions BIGINT NOT NULL DEFAULT 0
    CHECK (reported_impressions BETWEEN 0 AND deliveries);

CREATE FUNCTION content_report_ad_impression(viewer UUID, operation UUID) RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    delivery public.content_ad_deliveries%ROWTYPE;
    campaign public.content_ad_campaigns%ROWTYPE;
    observed_at TIMESTAMPTZ;
BEGIN
    IF viewer IS NULL OR operation IS NULL THEN RETURN 400; END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:'||viewer::text,0));
    SELECT * INTO delivery FROM public.content_ad_deliveries
    WHERE viewer_id=viewer AND request_id=operation
        AND NOT EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id=viewer);
    IF NOT FOUND THEN RETURN 404; END IF;
    IF delivery.impressed_at IS NOT NULL THEN RETURN 204; END IF;

    SELECT * INTO campaign FROM public.content_ad_campaigns
    WHERE id=delivery.campaign_id AND enabled AND placement=delivery.placement
    FOR UPDATE;
    IF NOT FOUND THEN RETURN 404; END IF;

    observed_at := clock_timestamp();
    IF observed_at < campaign.starts_at OR observed_at >= campaign.ends_at THEN RETURN 404; END IF;
    IF observed_at < delivery.delivered_at + INTERVAL '2 seconds' THEN RETURN 409; END IF;
    IF observed_at >= delivery.delivered_at + INTERVAL '2 minutes' THEN RETURN 410; END IF;

    UPDATE public.content_ad_deliveries SET impressed_at=observed_at
        WHERE viewer_id=viewer AND request_id=operation;
    UPDATE public.content_ad_campaigns SET reported_impressions=reported_impressions+1
        WHERE id=campaign.id;
    RETURN 204;
END;
$$;

REVOKE ALL ON FUNCTION content_report_ad_impression(UUID,UUID) FROM PUBLIC;
