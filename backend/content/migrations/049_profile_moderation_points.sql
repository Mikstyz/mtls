ALTER TABLE content_points_policies ADD COLUMN profile_image_severity TEXT NOT NULL DEFAULT 'low'
    CHECK (profile_image_severity IN ('low','medium','high','critical'));

CREATE TABLE content_profile_points_events (
    case_id UUID PRIMARY KEY,
    ledger_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN ('spam','harassment','consent','age_safety','other')),
    state TEXT NOT NULL CHECK (state IN ('deducted','reversed'))
);
CREATE INDEX content_profile_points_owner_idx ON content_profile_points_events(owner_id);

CREATE FUNCTION content_deduct_moderation_points(subject UUID, target UUID, rule_code TEXT, level TEXT) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    policy public.content_points_policies%ROWTYPE;
    account public.content_points_accounts%ROWTYPE;
    charge INTEGER;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-points:' || subject::text,0));

    IF EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=subject) THEN
        RETURN;
    END IF;

    SELECT * INTO STRICT policy FROM public.content_points_policies WHERE active;
    SELECT points INTO STRICT charge FROM public.content_points_deductions
    WHERE policy_version=policy.version AND rule=rule_code AND severity=COALESCE(level,policy.profile_image_severity);

    INSERT INTO public.content_points_accounts(owner_id,baseline_policy,initial_points,maximum_points,balance)
        VALUES(subject,policy.version,policy.initial_points,policy.maximum_points,policy.initial_points)
        ON CONFLICT(owner_id) DO NOTHING;
    SELECT * INTO STRICT account FROM public.content_points_accounts WHERE owner_id=subject FOR UPDATE;
    charge := LEAST(charge,account.balance);

    INSERT INTO public.content_points_ledger(case_id,operation,owner_id,policy_version,delta)
        VALUES(target,'deduction',subject,policy.version,-charge)
        ON CONFLICT(case_id,operation) DO NOTHING;
    IF FOUND THEN
        UPDATE public.content_points_accounts SET balance=balance-charge WHERE owner_id=subject;
    END IF;
    RETURN;
END;
$$;

CREATE FUNCTION content_refund_moderation_points(target UUID) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    debit public.content_points_ledger%ROWTYPE;
    account public.content_points_accounts%ROWTYPE;
    refund INTEGER;
BEGIN
    SELECT * INTO debit FROM public.content_points_ledger WHERE case_id=target AND operation='deduction';
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('content-points:' || debit.owner_id::text,0));
    SELECT * INTO account FROM public.content_points_accounts WHERE owner_id=debit.owner_id FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    refund := LEAST(-debit.delta,account.maximum_points-account.balance);
    INSERT INTO public.content_points_ledger(case_id,operation,owner_id,policy_version,delta)
        VALUES(target,'reversal',debit.owner_id,debit.policy_version,refund)
        ON CONFLICT(case_id,operation) DO NOTHING;
    IF FOUND THEN
        UPDATE public.content_points_accounts SET balance=balance+refund WHERE owner_id=debit.owner_id;
    END IF;
    RETURN;
END;
$$;

CREATE OR REPLACE FUNCTION content_apply_points_decision() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    subject UUID;
BEGIN
    SELECT owner_id INTO subject FROM public.content_case_owners WHERE case_id=NEW.case_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'missing moderation subject'; END IF;

    PERFORM public.content_deduct_moderation_points(subject,NEW.case_id,NEW.rule,NEW.severity);
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION content_reverse_points_decision() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    PERFORM public.content_refund_moderation_points(NEW.case_id);
    RETURN NEW;
END;
$$;

CREATE FUNCTION content_apply_profile_points(target UUID, subject UUID, operation TEXT, rule_code TEXT) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    item public.content_profile_points_events%ROWTYPE;
BEGIN
    IF target IS NULL OR subject IS NULL OR operation IS NULL OR operation NOT IN ('deduct','reverse')
        OR rule_code IS NULL OR rule_code NOT IN ('spam','harassment','consent','age_safety','other')
    THEN RETURN FALSE; END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || subject::text,0));
    IF EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id=subject) THEN RETURN TRUE; END IF;

    INSERT INTO public.content_profile_points_events(case_id,owner_id,reason,state)
    VALUES(target,subject,rule_code,CASE operation WHEN 'deduct' THEN 'deducted' ELSE 'reversed' END)
    ON CONFLICT (case_id) DO NOTHING RETURNING * INTO item;
    IF FOUND THEN
        IF operation='deduct' THEN
            PERFORM public.content_deduct_moderation_points(subject,item.ledger_id,rule_code,NULL);
        END IF;
        RETURN TRUE;
    END IF;

    SELECT * INTO STRICT item FROM public.content_profile_points_events WHERE case_id=target FOR UPDATE;
    IF item.owner_id<>subject OR item.reason<>rule_code THEN RETURN FALSE; END IF;
    IF operation='reverse' AND item.state='deducted' THEN
        PERFORM public.content_refund_moderation_points(item.ledger_id);
        UPDATE public.content_profile_points_events SET state='reversed' WHERE case_id=target;
    END IF;
    RETURN TRUE;
END;
$$;

CREATE FUNCTION content_purge_profile_points_events() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    DELETE FROM public.content_profile_points_events WHERE owner_id=NEW.author_id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER content_purge_profile_points_events
    AFTER INSERT ON content_author_purges
    FOR EACH ROW EXECUTE FUNCTION content_purge_profile_points_events();

REVOKE ALL ON FUNCTION content_deduct_moderation_points(UUID,UUID,TEXT,TEXT),
    content_refund_moderation_points(UUID),content_apply_profile_points(UUID,UUID,TEXT,TEXT),
    content_purge_profile_points_events() FROM PUBLIC;
