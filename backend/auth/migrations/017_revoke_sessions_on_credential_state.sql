CREATE FUNCTION revoke_sessions_on_credential_state_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.enabled IS NOT DISTINCT FROM NEW.enabled THEN
        RETURN NEW;
    END IF;

    IF NEW.password_revision <= OLD.password_revision THEN
        NEW.password_revision := OLD.password_revision + 1;
    END IF;

    UPDATE sessions
    SET revoked_at = clock_timestamp()
    WHERE user_id = OLD.user_id AND revoked_at IS NULL;

    RETURN NEW;
END;
$$;

CREATE TRIGGER credentials_state_revoke_sessions
BEFORE UPDATE OF enabled ON credentials
FOR EACH ROW EXECUTE FUNCTION revoke_sessions_on_credential_state_change();
