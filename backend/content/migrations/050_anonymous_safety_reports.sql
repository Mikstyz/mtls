ALTER TABLE content_reports ADD COLUMN anonymous_safety BOOLEAN NOT NULL DEFAULT FALSE;

CREATE UNIQUE INDEX content_anonymous_safety_open_idx ON content_reports(post_id,reason)
    WHERE anonymous_safety AND status IN ('pending','reviewing');

CREATE TABLE content_safety_report_budget (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(id),
    hour_start TIMESTAMPTZ NOT NULL,
    used INTEGER NOT NULL CHECK (used BETWEEN 1 AND 120)
);

CREATE FUNCTION content_submit_anonymous_safety_report(target UUID, category TEXT) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    bucket TIMESTAMPTZ := date_trunc('hour',clock_timestamp(),'UTC');
BEGIN
    IF target IS NULL OR category IS NULL OR category NOT IN ('consent','age_safety') THEN RETURN FALSE; END IF;

    INSERT INTO public.content_safety_report_budget AS budget(id,hour_start,used)
    VALUES(TRUE,bucket,1)
    ON CONFLICT(id) DO UPDATE SET hour_start=bucket,
        used=CASE WHEN budget.hour_start=bucket THEN budget.used+1 ELSE 1 END
    WHERE budget.hour_start<bucket OR (budget.hour_start=bucket AND budget.used<120);
    IF NOT FOUND THEN RETURN FALSE; END IF;

    INSERT INTO public.content_reports(post_id,reason,escalated,anonymous_safety)
    SELECT p.id,category,TRUE,TRUE
    FROM public.content_posts p
    WHERE p.id=target AND p.status='published' AND p.visibility='public'
        AND NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=p.author_id)
    FOR SHARE OF p
    ON CONFLICT (post_id,reason) WHERE anonymous_safety AND status IN ('pending','reviewing')
    DO NOTHING;

    RETURN TRUE;
END;
$$;

REVOKE ALL ON FUNCTION content_submit_anonymous_safety_report(UUID,TEXT) FROM PUBLIC;
