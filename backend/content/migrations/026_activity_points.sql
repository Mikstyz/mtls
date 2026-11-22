ALTER TABLE content_points_policies
    ADD COLUMN daily_activity_points INTEGER NOT NULL DEFAULT 1 CHECK(daily_activity_points BETWEEN 0 AND 10),
    ADD COLUMN activity_authors_required INTEGER NOT NULL DEFAULT 3 CHECK(activity_authors_required BETWEEN 2 AND 20);

ALTER TABLE content_points_ledger DROP CONSTRAINT content_points_ledger_operation_check;
ALTER TABLE content_points_ledger DROP CONSTRAINT content_points_ledger_check;
ALTER TABLE content_points_ledger
    ADD COLUMN activity_day INTEGER,
    ADD CONSTRAINT content_points_ledger_operation_check CHECK(operation IN ('deduction','reversal','activity')),
    ADD CONSTRAINT content_points_ledger_delta_check CHECK (
        (operation='deduction' AND delta<=0 AND activity_day IS NULL)
        OR (operation='reversal' AND delta>=0 AND activity_day IS NULL)
        OR (operation='activity' AND delta>0 AND activity_day IS NOT NULL)
    );
CREATE UNIQUE INDEX content_points_activity_day_idx
    ON content_points_ledger(owner_id,activity_day) WHERE operation='activity';
CREATE INDEX content_post_view_receipts_activity_idx
    ON content_post_view_receipts(viewer_id,view_day,post_id);

CREATE FUNCTION content_reward_public_views(viewer UUID, observed_day INTEGER) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    account public.content_points_accounts%ROWTYPE;
    policy public.content_points_policies%ROWTYPE;
    award INTEGER;
BEGIN
    IF observed_day <> (clock_timestamp() AT TIME ZONE 'UTC')::DATE - DATE '1970-01-01'
      OR NOT EXISTS(SELECT 1 FROM public.content_points_accounts WHERE owner_id=viewer)
    THEN RETURN; END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('content-points:' || viewer::text,0));
    SELECT * INTO account FROM public.content_points_accounts WHERE owner_id=viewer FOR UPDATE;
    IF NOT FOUND OR account.balance>=account.maximum_points OR EXISTS(
        SELECT 1 FROM public.content_points_ledger
        WHERE owner_id=viewer AND activity_day=observed_day AND operation='activity'
    ) OR EXISTS(SELECT 1 FROM public.content_active_points_ban(viewer))
    THEN RETURN; END IF;

    SELECT * INTO STRICT policy FROM public.content_points_policies WHERE active;
    IF policy.daily_activity_points=0 OR NOT EXISTS(
        SELECT 1 FROM public.content_post_view_receipts v JOIN public.content_posts p ON p.id=v.post_id
        WHERE v.viewer_id=viewer AND v.view_day=observed_day
            AND p.author_id<>viewer AND p.status='published' AND p.visibility='public' AND p.hidden_by_case IS NULL
            AND NOT EXISTS(SELECT 1 FROM public.content_author_purges a WHERE a.author_id=p.author_id)
        GROUP BY p.author_id LIMIT 1 OFFSET (policy.activity_authors_required-1)
    ) THEN RETURN; END IF;

    award := LEAST(policy.daily_activity_points,account.maximum_points-account.balance);
    INSERT INTO public.content_points_ledger(case_id,operation,owner_id,policy_version,delta,activity_day)
    VALUES(gen_random_uuid(),'activity',viewer,policy.version,award,observed_day)
    ON CONFLICT(owner_id,activity_day) WHERE operation='activity' DO NOTHING;
    IF FOUND THEN
        UPDATE public.content_points_accounts SET balance=balance+award WHERE owner_id=viewer;
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION content_reward_public_views(UUID,INTEGER) FROM PUBLIC;

CREATE OR REPLACE FUNCTION content_record_points_thresholds() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    account public.content_points_accounts%ROWTYPE;
    after_balance INTEGER;
    next_tier INTEGER;
    observed_at TIMESTAMPTZ := clock_timestamp();
    deadline TIMESTAMPTZ;
BEGIN
    IF NEW.operation='reversal' THEN
        UPDATE public.content_points_bans SET reversed_at=observed_at
        WHERE case_id=NEW.case_id AND owner_id=NEW.owner_id AND reversed_at IS NULL;
        RETURN NEW;
    END IF;
    IF NEW.operation<>'deduction' OR NEW.delta=0 THEN RETURN NEW; END IF;

    -- The decision function holds the owner lock and records the ledger entry
    -- before updating the balance projection.
    SELECT * INTO STRICT account FROM public.content_points_accounts WHERE owner_id=NEW.owner_id FOR UPDATE;
    after_balance := account.balance+NEW.delta;

    INSERT INTO public.content_points_warnings(owner_id,lost_percent,case_id,created_at)
    SELECT NEW.owner_id,t.percent,NEW.case_id,observed_at
    FROM (VALUES(50),(70),(80),(90)) t(percent)
    WHERE (account.initial_points-account.balance)*100 < account.initial_points*t.percent
      AND (account.initial_points-after_balance)*100 >= account.initial_points*t.percent
    ON CONFLICT(owner_id,lost_percent) DO NOTHING;

    IF after_balance<>0 OR EXISTS(
        SELECT 1 FROM public.content_points_bans
        WHERE owner_id=NEW.owner_id AND reversed_at IS NULL AND (ends_at IS NULL OR ends_at>observed_at)
    ) THEN RETURN NEW; END IF;

    SELECT LEAST(4,COUNT(*)+1)::INTEGER INTO next_tier FROM public.content_points_bans
    WHERE owner_id=NEW.owner_id AND reversed_at IS NULL;

    deadline := CASE next_tier
        WHEN 1 THEN observed_at+INTERVAL '24 hours'
        WHEN 2 THEN observed_at+INTERVAL '168 hours'
        WHEN 3 THEN ((observed_at AT TIME ZONE 'UTC')+INTERVAL '1 month') AT TIME ZONE 'UTC'
        ELSE NULL END;

    INSERT INTO public.content_points_bans(case_id,owner_id,tier,started_at,ends_at)
    VALUES(NEW.case_id,NEW.owner_id,next_tier,observed_at,deadline);
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION content_count_post_view(view_post UUID, view_media UUID, view_user UUID, observed_day INTEGER, allow_test BOOLEAN)
RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    today INTEGER := (clock_timestamp() AT TIME ZONE 'UTC')::DATE - DATE '1970-01-01';
BEGIN
    IF observed_day NOT BETWEEN today - 1 AND today THEN
        RETURN;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || view_user::text, 0));
    PERFORM 1 FROM public.content_posts p
    JOIN public.content_post_media m ON m.post_id = p.id AND m.media_id = view_media
    WHERE p.id = view_post AND p.status = 'published' AND p.hidden_by_case IS NULL AND (p.visibility = 'public' OR (p.visibility='private' AND allow_test AND public.content_test_entitled(p.id,p.revision,view_user)))
        AND p.author_id <> view_user
        AND NOT EXISTS (
            SELECT 1 FROM public.content_author_purges a WHERE a.author_id IN (p.author_id, view_user)
        )
    FOR SHARE OF p;

    IF NOT FOUND THEN RETURN; END IF;

    INSERT INTO public.content_post_view_receipts (post_id, viewer_id, view_day)
        VALUES (view_post, view_user, observed_day)
    ON CONFLICT (post_id, viewer_id) DO UPDATE SET view_day = EXCLUDED.view_day
        WHERE public.content_post_view_receipts.view_day < EXCLUDED.view_day;

    IF FOUND THEN
        INSERT INTO public.content_post_statistics (post_id, views) VALUES (view_post, 1)
        ON CONFLICT (post_id) DO UPDATE SET views = public.content_post_statistics.views + 1;
        PERFORM public.content_reward_public_views(view_user,observed_day);
    END IF;
END;
$$;
