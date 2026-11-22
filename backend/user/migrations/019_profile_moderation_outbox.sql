CREATE TABLE user_profile_moderation_outbox (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES user_profile_image_reports(case_id) ON DELETE CASCADE,
    owner_id UUID NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('deduct','reverse')),
    reason TEXT NOT NULL CHECK (reason IN ('spam','harassment','consent','age_safety','other')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(case_id,operation)
);

CREATE FUNCTION user_emit_profile_moderation_event() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    INSERT INTO public.user_profile_moderation_outbox(case_id,owner_id,operation,reason)
    SELECT r.case_id,r.owner_id,TG_ARGV[0],r.reason
    FROM public.user_profile_image_reports r
    WHERE r.case_id=NEW.case_id
    ON CONFLICT(case_id,operation) DO NOTHING;
    RETURN NEW;
END;
$$;

CREATE TRIGGER user_emit_profile_moderation_deduction
    AFTER INSERT ON user_profile_image_decisions
    FOR EACH ROW WHEN (NEW.action='remove')
    EXECUTE FUNCTION user_emit_profile_moderation_event('deduct');

CREATE TRIGGER user_emit_profile_moderation_reversal
    AFTER UPDATE OF outcome ON user_profile_image_appeals
    FOR EACH ROW WHEN (OLD.outcome IS NULL AND NEW.outcome='reversed')
    EXECUTE FUNCTION user_emit_profile_moderation_event('reverse');

REVOKE ALL ON FUNCTION user_emit_profile_moderation_event() FROM PUBLIC;
