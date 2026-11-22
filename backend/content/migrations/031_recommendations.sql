CREATE TABLE content_recommendation_snapshots (
    bucket TIMESTAMPTZ PRIMARY KEY
);
CREATE TABLE content_recommendations (
    bucket TIMESTAMPTZ NOT NULL REFERENCES content_recommendation_snapshots(bucket) ON DELETE CASCADE,
    rank INTEGER NOT NULL CHECK(rank BETWEEN 1 AND 1000),
    post_id UUID NOT NULL REFERENCES content_posts(id) ON DELETE CASCADE,
    PRIMARY KEY(bucket,rank),
    UNIQUE(bucket,post_id)
);
CREATE INDEX content_recommendations_post_idx ON content_recommendations(post_id);

CREATE FUNCTION content_ensure_recommendations() RETURNS TIMESTAMPTZ
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    current_bucket TIMESTAMPTZ := date_trunc('hour',clock_timestamp(),'UTC');
    oldest_day INTEGER := (clock_timestamp() AT TIME ZONE 'UTC')::DATE - DATE '1970-01-01' - 1;
BEGIN
    INSERT INTO public.content_recommendation_snapshots(bucket) VALUES(current_bucket)
    ON CONFLICT DO NOTHING;
    IF NOT FOUND THEN RETURN current_bucket; END IF;

    WITH candidates AS MATERIALIZED (
        SELECT p.id,p.author_id,p.published_at FROM public.content_posts p
        WHERE p.status='published' AND p.visibility='public' AND p.hidden_by_case IS NULL
            AND p.published_at>=current_bucket-INTERVAL '30 days'
            AND NOT EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id=p.author_id)
        ORDER BY p.published_at DESC,p.id DESC LIMIT 1000
    ), scored AS (
        SELECT p.*, (
            SELECT count(*) FROM public.content_post_view_receipts v
            WHERE v.post_id=p.id AND v.view_day>=oldest_day
        ) AS views
        FROM candidates p
    ), varied AS (
        SELECT *,row_number() OVER (PARTITION BY author_id ORDER BY views DESC,published_at DESC,id DESC) AS author_rank
        FROM scored
    )
    INSERT INTO public.content_recommendations(bucket,rank,post_id)
    SELECT current_bucket,row_number() OVER(ORDER BY author_rank,views DESC,published_at DESC,id DESC),id
    FROM varied;

    DELETE FROM public.content_recommendation_snapshots
        WHERE bucket<current_bucket-INTERVAL '24 hours';
    RETURN current_bucket;
END;
$$;
REVOKE ALL ON FUNCTION content_ensure_recommendations() FROM PUBLIC;
