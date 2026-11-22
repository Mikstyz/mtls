CREATE TABLE content_points_warnings (
    owner_id UUID NOT NULL REFERENCES content_points_accounts(owner_id) ON DELETE CASCADE,
    lost_percent INTEGER NOT NULL CHECK(lost_percent IN (50,70,80,90)),
    case_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(owner_id,lost_percent)
);

CREATE TABLE content_points_bans (
    case_id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES content_points_accounts(owner_id) ON DELETE CASCADE,
    tier INTEGER NOT NULL CHECK(tier BETWEEN 1 AND 4),
    started_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ,
    reversed_at TIMESTAMPTZ,
    CHECK ((tier=4)=(ends_at IS NULL)),
    CHECK (ends_at IS NULL OR ends_at>started_at)
);
CREATE INDEX content_points_bans_owner_idx ON content_points_bans(owner_id,started_at DESC,case_id);

CREATE FUNCTION content_record_points_thresholds() RETURNS trigger
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
    IF NEW.delta=0 THEN RETURN NEW; END IF;

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
CREATE TRIGGER content_points_thresholds
    AFTER INSERT ON content_points_ledger
    FOR EACH ROW EXECUTE FUNCTION content_record_points_thresholds();

CREATE FUNCTION content_owner_point_notices(owner UUID)
RETURNS TABLE(lost_percent INTEGER,case_id UUID,created_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT w.lost_percent,w.case_id,w.created_at FROM public.content_points_warnings w
    WHERE w.owner_id=owner AND NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=owner)
    ORDER BY w.lost_percent
$$;

CREATE FUNCTION content_active_points_ban(owner UUID)
RETURNS TABLE(tier INTEGER,ends_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT b.tier,b.ends_at FROM public.content_points_bans b
    WHERE b.owner_id=owner AND b.reversed_at IS NULL AND (b.ends_at IS NULL OR b.ends_at>statement_timestamp())
        AND NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=owner)
    ORDER BY b.started_at DESC,b.case_id LIMIT 1
$$;

REVOKE ALL ON FUNCTION content_record_points_thresholds(),content_owner_point_notices(UUID),
    content_active_points_ban(UUID) FROM PUBLIC;
