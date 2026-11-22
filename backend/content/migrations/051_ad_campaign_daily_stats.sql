CREATE TABLE content_ad_campaign_daily_stats (
    campaign_id UUID NOT NULL REFERENCES content_ad_campaigns(id),
    day DATE NOT NULL,
    deliveries BIGINT NOT NULL DEFAULT 0 CHECK(deliveries>=0),
    impressions BIGINT NOT NULL DEFAULT 0 CHECK(impressions>=0),
    PRIMARY KEY(campaign_id,day)
);

CREATE FUNCTION content_record_ad_daily_stats() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        INSERT INTO public.content_ad_campaign_daily_stats AS s(campaign_id,day,deliveries)
        VALUES(NEW.campaign_id,(NEW.delivered_at AT TIME ZONE 'UTC')::DATE,1)
        ON CONFLICT(campaign_id,day) DO UPDATE SET deliveries=s.deliveries+1;
    ELSE
        INSERT INTO public.content_ad_campaign_daily_stats AS s(campaign_id,day,impressions)
        VALUES(NEW.campaign_id,(NEW.impressed_at AT TIME ZONE 'UTC')::DATE,1)
        ON CONFLICT(campaign_id,day) DO UPDATE SET impressions=s.impressions+1;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER content_ad_daily_delivery
    AFTER INSERT ON content_ad_deliveries FOR EACH ROW
    EXECUTE FUNCTION content_record_ad_daily_stats();

CREATE TRIGGER content_ad_daily_impression
    AFTER UPDATE OF impressed_at ON content_ad_deliveries
    FOR EACH ROW WHEN (OLD.impressed_at IS NULL AND NEW.impressed_at IS NOT NULL)
    EXECUTE FUNCTION content_record_ad_daily_stats();

CREATE FUNCTION content_ad_campaign_daily_report(campaign UUID, start_day DATE, end_day DATE)
RETURNS TABLE(day TEXT,deliveries BIGINT,impressions BIGINT)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT to_char(start_day+i,'YYYY-MM-DD'),COALESCE(s.deliveries,0),COALESCE(s.impressions,0)
    FROM public.content_ad_campaigns c
    CROSS JOIN generate_series(0,LEAST(30,end_day-start_day-1)) i
    LEFT JOIN public.content_ad_campaign_daily_stats s ON s.campaign_id=c.id AND s.day=start_day+i
    WHERE c.id=campaign AND end_day-start_day BETWEEN 1 AND 31
    ORDER BY i
$$;

REVOKE ALL ON FUNCTION content_record_ad_daily_stats(),content_ad_campaign_daily_report(UUID,DATE,DATE) FROM PUBLIC;
