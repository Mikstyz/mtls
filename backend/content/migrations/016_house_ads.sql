CREATE TABLE content_ad_campaigns (
    id UUID PRIMARY KEY,
    placement TEXT NOT NULL CHECK (placement IN ('mixed_feed', 'photo_feed', 'video_feed')),
    headline TEXT NOT NULL CHECK (char_length(headline) BETWEEN 1 AND 140 AND btrim(headline) <> ''),
    destination TEXT NOT NULL CHECK (destination IN ('mixed_feed', 'photo_feed', 'video_feed')),
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL CHECK (ends_at > starts_at),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    delivery_budget BIGINT NOT NULL CHECK (delivery_budget > 0),
    deliveries BIGINT NOT NULL DEFAULT 0 CHECK (deliveries BETWEEN 0 AND delivery_budget)
);

CREATE INDEX content_ad_campaigns_placement_idx
    ON content_ad_campaigns(placement, starts_at, id) WHERE enabled;

CREATE TABLE content_ad_deliveries (
    viewer_id UUID NOT NULL,
    request_id UUID NOT NULL,
    placement TEXT NOT NULL CHECK (placement IN ('mixed_feed', 'photo_feed', 'video_feed')),
    campaign_id UUID NOT NULL REFERENCES content_ad_campaigns(id),
    headline TEXT NOT NULL,
    destination TEXT NOT NULL,
    delivered_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (viewer_id, request_id)
);

CREATE INDEX content_ad_deliveries_recent_idx
    ON content_ad_deliveries (viewer_id, delivered_at DESC);

-- Freeze a successful response for retries, subject to continued campaign eligibility.
CREATE FUNCTION content_select_ad(viewer UUID, operation UUID, slot TEXT)
RETURNS TABLE(result TEXT, ad_id UUID, headline TEXT, destination TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    previous public.content_ad_deliveries%ROWTYPE;
    campaign public.content_ad_campaigns%ROWTYPE;
    instant TIMESTAMPTZ;
BEGIN
    IF viewer IS NULL OR operation IS NULL OR slot IS NULL
        OR slot NOT IN ('mixed_feed', 'photo_feed', 'video_feed') THEN
        RAISE EXCEPTION 'invalid ad request';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || viewer::text,0));
    IF EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id=viewer) THEN
        RETURN QUERY SELECT 'empty',NULL::UUID,NULL::TEXT,NULL::TEXT;
        RETURN;
    END IF;

    SELECT * INTO previous FROM public.content_ad_deliveries
    WHERE viewer_id=viewer AND request_id=operation;
    IF FOUND THEN
        IF previous.placement <> slot THEN
            RETURN QUERY SELECT 'conflict',NULL::UUID,NULL::TEXT,NULL::TEXT;
        ELSIF EXISTS (
            SELECT 1 FROM public.content_ad_campaigns c
            WHERE c.id=previous.campaign_id AND c.enabled
                AND clock_timestamp() >= c.starts_at AND clock_timestamp() < c.ends_at
        ) THEN
            RETURN QUERY SELECT 'ad',previous.campaign_id,previous.headline,previous.destination;
        ELSE
            RETURN QUERY SELECT 'empty',NULL::UUID,NULL::TEXT,NULL::TEXT;
        END IF;
        RETURN;
    END IF;

    instant := clock_timestamp();
    IF EXISTS (
        SELECT 1 FROM public.content_ad_deliveries
        WHERE viewer_id=viewer AND delivered_at > instant - INTERVAL '1 hour'
        LIMIT 1 OFFSET 2
    ) THEN
        RETURN QUERY SELECT 'empty',NULL::UUID,NULL::TEXT,NULL::TEXT;
        RETURN;
    END IF;

    SELECT c.* INTO campaign FROM public.content_ad_campaigns c
    WHERE c.placement=slot AND c.enabled AND c.starts_at<=instant AND c.ends_at>instant
        AND c.deliveries<c.delivery_budget AND NOT EXISTS (
            SELECT 1 FROM public.content_ad_deliveries d
            WHERE d.viewer_id=viewer AND d.campaign_id=c.id AND d.delivered_at>instant-INTERVAL '1 hour'
        )
    ORDER BY c.starts_at,c.id LIMIT 1 FOR UPDATE OF c;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'empty',NULL::UUID,NULL::TEXT,NULL::TEXT;
        RETURN;
    END IF;

    instant := clock_timestamp();
    IF instant >= campaign.ends_at THEN
        RETURN QUERY SELECT 'empty',NULL::UUID,NULL::TEXT,NULL::TEXT;
        RETURN;
    END IF;

    UPDATE public.content_ad_campaigns SET deliveries=deliveries+1 WHERE id=campaign.id;
    INSERT INTO public.content_ad_deliveries(viewer_id,request_id,placement,campaign_id,headline,destination,delivered_at)
    VALUES(viewer,operation,slot,campaign.id,campaign.headline,campaign.destination,instant);
    RETURN QUERY SELECT 'ad',campaign.id,campaign.headline,campaign.destination;
END;
$$;

CREATE FUNCTION content_purge_ad_deliveries(viewer UUID) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id=viewer) THEN
        RAISE EXCEPTION 'missing viewer purge marker';
    END IF;
    DELETE FROM public.content_ad_deliveries WHERE viewer_id=viewer AND request_id IN (
        SELECT request_id FROM public.content_ad_deliveries WHERE viewer_id=viewer ORDER BY request_id LIMIT 500
    );
    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION content_select_ad(UUID,UUID,TEXT),content_purge_ad_deliveries(UUID) FROM PUBLIC;
