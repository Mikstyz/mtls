CREATE TABLE content_points_policies (
    version INTEGER PRIMARY KEY CHECK(version>0),
    initial_points INTEGER NOT NULL CHECK(initial_points BETWEEN 1 AND 1000000),
    maximum_points INTEGER NOT NULL CHECK(maximum_points BETWEEN initial_points AND 1000000),
    active BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE UNIQUE INDEX content_points_one_active_policy ON content_points_policies(active) WHERE active;

CREATE TABLE content_points_deductions (
    policy_version INTEGER NOT NULL REFERENCES content_points_policies(version),
    rule TEXT NOT NULL CHECK(rule IN ('spam','harassment','consent','age_safety','other')),
    severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
    points INTEGER NOT NULL CHECK(points BETWEEN 1 AND 1000000),
    PRIMARY KEY (policy_version,rule,severity)
);

INSERT INTO content_points_policies(version,initial_points,maximum_points,active)
VALUES(1,100,100,TRUE);

INSERT INTO content_points_deductions(policy_version,rule,severity,points)
SELECT 1,r.rule,d.severity,d.points * r.weight
FROM (VALUES ('spam',1),('harassment',2),('consent',3),('age_safety',3),('other',1)) r(rule,weight)
CROSS JOIN (VALUES ('low',5),('medium',10),('high',20),('critical',35)) d(severity,points);

CREATE TABLE content_points_accounts (
    owner_id UUID PRIMARY KEY,
    baseline_policy INTEGER NOT NULL REFERENCES content_points_policies(version),
    initial_points INTEGER NOT NULL CHECK(initial_points>0),
    maximum_points INTEGER NOT NULL CHECK(maximum_points>=initial_points),
    balance INTEGER NOT NULL CHECK(balance BETWEEN 0 AND maximum_points)
);
CREATE TABLE content_points_ledger (
    case_id UUID NOT NULL,
    operation TEXT NOT NULL CHECK(operation IN ('deduction','reversal')),
    owner_id UUID NOT NULL REFERENCES content_points_accounts(owner_id) ON DELETE CASCADE,
    policy_version INTEGER NOT NULL REFERENCES content_points_policies(version),
    delta INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(case_id,operation),
    CHECK((operation='deduction' AND delta<=0) OR (operation='reversal' AND delta>=0))
);
CREATE INDEX content_points_ledger_owner_idx ON content_points_ledger(owner_id,created_at DESC,case_id);

CREATE FUNCTION content_apply_points_decision() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    subject UUID;
    policy public.content_points_policies%ROWTYPE;
    account public.content_points_accounts%ROWTYPE;
    charge INTEGER;
BEGIN
    SELECT owner_id INTO subject FROM public.content_case_owners WHERE case_id=NEW.case_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'missing moderation subject'; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('content-points:' || subject::text,0));

    IF EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=subject) THEN
        RETURN NEW;
    END IF;

    SELECT * INTO STRICT policy FROM public.content_points_policies WHERE active;
    SELECT points INTO STRICT charge FROM public.content_points_deductions
    WHERE policy_version=policy.version AND rule=NEW.rule AND severity=NEW.severity;

    INSERT INTO public.content_points_accounts(owner_id,baseline_policy,initial_points,maximum_points,balance)
        VALUES(subject,policy.version,policy.initial_points,policy.maximum_points,policy.initial_points)
        ON CONFLICT(owner_id) DO NOTHING;
    SELECT * INTO STRICT account FROM public.content_points_accounts WHERE owner_id=subject FOR UPDATE;
    charge := LEAST(charge,account.balance);

    INSERT INTO public.content_points_ledger(case_id,operation,owner_id,policy_version,delta)
        VALUES(NEW.case_id,'deduction',subject,policy.version,-charge)
        ON CONFLICT(case_id,operation) DO NOTHING;
    IF FOUND THEN
        UPDATE public.content_points_accounts SET balance=balance-charge WHERE owner_id=subject;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION content_reverse_points_decision() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    debit public.content_points_ledger%ROWTYPE;
    account public.content_points_accounts%ROWTYPE;
    refund INTEGER;
BEGIN
    SELECT * INTO debit FROM public.content_points_ledger WHERE case_id=NEW.case_id AND operation='deduction';
    IF NOT FOUND THEN RETURN NEW; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('content-points:' || debit.owner_id::text,0));
    SELECT * INTO account FROM public.content_points_accounts WHERE owner_id=debit.owner_id FOR UPDATE;
    IF NOT FOUND THEN RETURN NEW; END IF;

    refund := LEAST(-debit.delta,account.maximum_points-account.balance);
    INSERT INTO public.content_points_ledger(case_id,operation,owner_id,policy_version,delta)
        VALUES(NEW.case_id,'reversal',debit.owner_id,debit.policy_version,refund)
        ON CONFLICT(case_id,operation) DO NOTHING;
    IF FOUND THEN
        UPDATE public.content_points_accounts SET balance=balance+refund WHERE owner_id=debit.owner_id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER content_points_confirm
    AFTER INSERT ON content_moderation_events FOR EACH ROW WHEN (NEW.action='confirm')
    EXECUTE FUNCTION content_apply_points_decision();
CREATE TRIGGER content_points_reverse
    AFTER UPDATE OF outcome ON content_moderation_appeals FOR EACH ROW
    WHEN (NEW.outcome='reversed' AND OLD.outcome IS DISTINCT FROM NEW.outcome)
    EXECUTE FUNCTION content_reverse_points_decision();

CREATE FUNCTION content_owner_points(owner UUID)
RETURNS TABLE(balance INTEGER,initial_points INTEGER,maximum_points INTEGER,comments_limited BOOLEAN)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT COALESCE(a.balance,p.initial_points),COALESCE(a.initial_points,p.initial_points),
        COALESCE(a.maximum_points,p.maximum_points),COALESCE(a.balance*100<=a.initial_points*30,FALSE)
    FROM public.content_points_policies p LEFT JOIN public.content_points_accounts a ON a.owner_id=owner
    WHERE p.active AND NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=owner)
$$;
CREATE FUNCTION content_purge_points(owner UUID) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-points:' || owner::text,0));
    IF NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=owner) THEN
        RAISE EXCEPTION 'missing points owner purge marker';
    END IF;
    DELETE FROM public.content_points_accounts WHERE owner_id=owner;
END;
$$;

REVOKE ALL ON FUNCTION content_apply_points_decision(),content_reverse_points_decision(),
    content_owner_points(UUID),content_purge_points(UUID) FROM PUBLIC;

CREATE OR REPLACE FUNCTION content_write_comment(target UUID, actor UUID, comment_id UUID, message TEXT, allow_test BOOLEAN)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    previous public.content_comments%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || actor::text, 0));
    PERFORM 1 FROM public.content_posts p
    WHERE p.id=target AND p.status='published' AND p.hidden_by_case IS NULL AND ((p.visibility='public' OR p.author_id=actor OR (p.visibility='private' AND allow_test AND public.content_test_entitled(p.id,p.revision,actor))))
        AND NOT EXISTS (SELECT 1 FROM public.content_author_purges a WHERE a.author_id IN (actor,p.author_id))
    FOR SHARE;
    IF NOT FOUND THEN RETURN 404; END IF;

    SELECT * INTO previous FROM public.content_comments WHERE id=comment_id;
    IF FOUND THEN
        IF previous.author_id <> actor OR previous.post_id <> target THEN RETURN 404; END IF;
        IF message IS NULL THEN
            UPDATE public.content_comments SET body=NULL WHERE id=comment_id AND body IS NOT NULL;
            RETURN 204;
        END IF;
        IF previous.body IS DISTINCT FROM message THEN RETURN 409; END IF;
        RETURN 204;
    END IF;
    IF message IS NULL THEN RETURN 404; END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('content-points:' || actor::text,0));
    IF EXISTS (SELECT 1 FROM public.content_owner_points(actor) WHERE comments_limited) THEN RETURN 403; END IF;

    IF EXISTS (SELECT 1 FROM public.content_comments WHERE author_id=actor
        AND created_at > clock_timestamp() - INTERVAL '1 minute' OFFSET 4 LIMIT 1)
    THEN RETURN 429; END IF;

    INSERT INTO public.content_comments(id,post_id,author_id,body)
    VALUES(comment_id,target,actor,message) ON CONFLICT (id) DO NOTHING;
    IF NOT FOUND THEN RETURN 404; END IF;
    RETURN 201;
END;
$$;
