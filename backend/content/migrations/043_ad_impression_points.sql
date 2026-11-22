ALTER TABLE content_points_policies
    ADD COLUMN daily_ad_points INTEGER NOT NULL DEFAULT 0 CHECK (daily_ad_points BETWEEN 0 AND 1),
    ADD COLUMN ad_campaigns_required INTEGER NOT NULL DEFAULT 3 CHECK (ad_campaigns_required BETWEEN 2 AND 10);

ALTER TABLE content_points_ledger
    ADD COLUMN ad_request_id UUID,
    ADD CONSTRAINT content_points_ad_source_check CHECK ((operation='ad_impressions')=(ad_request_id IS NOT NULL)),
    DROP CONSTRAINT content_points_ledger_operation_check,
    DROP CONSTRAINT content_points_ledger_delta_check,
    ADD CONSTRAINT content_points_ledger_operation_check
        CHECK (operation IN ('deduction','reversal','activity','ad_impressions')),
    ADD CONSTRAINT content_points_ledger_delta_check CHECK (
        (operation='deduction' AND delta<=0 AND activity_day IS NULL)
        OR (operation='reversal' AND delta>=0 AND activity_day IS NULL)
        OR (operation IN ('activity','ad_impressions') AND delta>0 AND activity_day IS NOT NULL)
    );

CREATE UNIQUE INDEX content_points_ad_day_idx
    ON content_points_ledger(owner_id,activity_day) WHERE operation='ad_impressions';

CREATE INDEX content_ad_impressions_by_viewer_idx
    ON content_ad_deliveries(viewer_id,impressed_at,campaign_id) WHERE impressed_at IS NOT NULL;

CREATE FUNCTION content_reward_ad_impressions() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    policy public.content_points_policies%ROWTYPE;
    account public.content_points_accounts%ROWTYPE;
    day_start TIMESTAMPTZ := date_trunc('day',NEW.impressed_at,'UTC');
    award_day INTEGER := (day_start AT TIME ZONE 'UTC')::DATE - DATE '1970-01-01';
BEGIN
    SELECT * INTO policy FROM public.content_points_policies WHERE active;
    IF NOT FOUND OR policy.daily_ad_points=0 THEN RETURN NEW; END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('content-points:' || NEW.viewer_id::text,0));
    SELECT * INTO account FROM public.content_points_accounts WHERE owner_id=NEW.viewer_id FOR UPDATE;
    IF NOT FOUND OR account.balance>=account.maximum_points
        OR EXISTS (SELECT 1 FROM public.content_active_points_ban(NEW.viewer_id))
        OR EXISTS (
            SELECT 1 FROM public.content_points_ledger
            WHERE owner_id=NEW.viewer_id AND activity_day=award_day AND operation='ad_impressions'
        )
        OR NOT EXISTS (
            SELECT 1 FROM public.content_ad_deliveries
            WHERE viewer_id=NEW.viewer_id AND impressed_at>=day_start AND impressed_at<=NEW.impressed_at
            GROUP BY campaign_id
            LIMIT 1 OFFSET (policy.ad_campaigns_required-1)
        )
    THEN RETURN NEW; END IF;

    INSERT INTO public.content_points_ledger(case_id,operation,owner_id,policy_version,delta,activity_day,ad_request_id)
    VALUES (gen_random_uuid(),'ad_impressions',NEW.viewer_id,policy.version,policy.daily_ad_points,award_day,NEW.request_id)
    ON CONFLICT (owner_id,activity_day) WHERE operation='ad_impressions' DO NOTHING;

    IF FOUND THEN
        UPDATE public.content_points_accounts SET balance=balance+policy.daily_ad_points WHERE owner_id=NEW.viewer_id;
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION content_reward_ad_impressions() FROM PUBLIC;

CREATE TRIGGER content_points_ad_impressions
    AFTER UPDATE OF impressed_at ON content_ad_deliveries
    FOR EACH ROW WHEN (OLD.impressed_at IS NULL AND NEW.impressed_at IS NOT NULL)
    EXECUTE FUNCTION content_reward_ad_impressions();
