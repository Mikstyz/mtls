ALTER TABLE content_ad_campaigns ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0);

CREATE TABLE content_ad_campaign_events (
    campaign_id UUID NOT NULL REFERENCES content_ad_campaigns(id),
    revision BIGINT NOT NULL,
    operator_id UUID NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    configuration JSONB NOT NULL,
    PRIMARY KEY (campaign_id, revision)
);

CREATE FUNCTION content_ad_campaign_list(after_id UUID, page_size INTEGER)
RETURNS SETOF public.content_ad_campaigns
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT c.* FROM public.content_ad_campaigns c
    WHERE after_id IS NULL OR c.id>after_id
    ORDER BY c.id
    LIMIT CASE WHEN page_size BETWEEN 1 AND 41 THEN page_size ELSE 0 END
$$;

CREATE FUNCTION content_ad_campaign_put(
    actor UUID, target UUID, expected BIGINT, slot TEXT, title TEXT, link TEXT, starts TIMESTAMPTZ,
    ends TIMESTAMPTZ, active BOOLEAN, budget BIGINT
) RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    campaign public.content_ad_campaigns%ROWTYPE;
    status INTEGER;
BEGIN
    IF actor IS NULL OR target IS NULL OR expected IS NULL OR expected NOT BETWEEN 0 AND 9223372036854775806
        OR slot IS NULL OR slot NOT IN ('mixed_feed', 'photo_feed', 'video_feed')
        OR link IS NULL OR link NOT IN ('mixed_feed', 'photo_feed', 'video_feed')
        OR title IS NULL OR char_length(title) NOT BETWEEN 1 AND 140 OR btrim(title)=''
        OR starts IS NULL OR ends IS NULL OR NOT isfinite(starts) OR NOT isfinite(ends) OR ends<=starts
        OR active IS NULL OR budget IS NULL OR budget<1
    THEN RETURN 400; END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('content-ad-campaign:'||target::text,0));
    SELECT * INTO campaign FROM public.content_ad_campaigns WHERE id=target FOR UPDATE;
    IF NOT FOUND THEN
        IF expected<>0 THEN RETURN 404; END IF;
        INSERT INTO public.content_ad_campaigns(id,placement,headline,destination,starts_at,ends_at,enabled,delivery_budget)
            VALUES(target,slot,title,link,starts,ends,active,budget) RETURNING * INTO campaign;
        status := 201;
    ELSE
        IF campaign.revision IN (expected,expected+1)
            AND (campaign.placement,campaign.headline,campaign.destination,campaign.starts_at,
                campaign.ends_at,campaign.enabled,campaign.delivery_budget)=(slot,title,link,starts,ends,active,budget)
        THEN RETURN 204; END IF;

        IF expected<>campaign.revision OR budget<campaign.deliveries THEN RETURN 409; END IF;
        UPDATE public.content_ad_campaigns SET placement=slot,headline=title,destination=link,
            starts_at=starts,ends_at=ends,enabled=active,delivery_budget=budget,revision=revision+1
            WHERE id=target RETURNING * INTO campaign;
        status := 204;
    END IF;

    INSERT INTO public.content_ad_campaign_events(campaign_id,revision,operator_id,configuration)
        VALUES(target,campaign.revision,actor,to_jsonb(campaign));
    RETURN status;
END;
$$;

REVOKE ALL ON FUNCTION content_ad_campaign_list(UUID,INTEGER),
    content_ad_campaign_put(UUID,UUID,BIGINT,TEXT,TEXT,TEXT,TIMESTAMPTZ,TIMESTAMPTZ,BOOLEAN,BIGINT) FROM PUBLIC;

-- A retry may reuse an earlier response while its placement is still eligible.
CREATE OR REPLACE FUNCTION content_select_ad(viewer UUID, operation UUID, slot TEXT)
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
            WHERE c.id=previous.campaign_id AND c.enabled AND c.placement=slot
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
