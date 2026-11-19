CREATE FUNCTION revoke_sessions_on_role_change() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    affected_user UUID;
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        UPDATE credentials
        SET password_revision = password_revision + 1
        WHERE user_id IN (SELECT user_id FROM account_roles);

        UPDATE sessions
        SET revoked_at = clock_timestamp()
        WHERE revoked_at IS NULL AND user_id IN (SELECT user_id FROM account_roles);

        RETURN NULL;
    END IF;

    IF TG_OP = 'UPDATE' AND OLD.user_id = NEW.user_id AND OLD.role = NEW.role THEN
        RETURN NULL;
    END IF;

    IF TG_OP = 'DELETE' THEN
        affected_user := OLD.user_id;
    ELSE
        affected_user := NEW.user_id;
    END IF;

    IF TG_OP = 'UPDATE' AND OLD.user_id <> NEW.user_id THEN
        UPDATE credentials
        SET password_revision = password_revision + 1
        WHERE user_id = OLD.user_id;

        UPDATE sessions
        SET revoked_at = clock_timestamp()
        WHERE user_id = OLD.user_id AND revoked_at IS NULL;
    END IF;

    UPDATE credentials
    SET password_revision = password_revision + 1
    WHERE user_id = affected_user;

    UPDATE sessions
    SET revoked_at = clock_timestamp()
    WHERE user_id = affected_user AND revoked_at IS NULL;

    RETURN NULL;
END;
$$;

CREATE TRIGGER account_roles_revoke_sessions
AFTER INSERT OR UPDATE OR DELETE ON account_roles
FOR EACH ROW EXECUTE FUNCTION revoke_sessions_on_role_change();

CREATE TRIGGER account_roles_revoke_sessions_on_truncate
BEFORE TRUNCATE ON account_roles
FOR EACH STATEMENT EXECUTE FUNCTION revoke_sessions_on_role_change();
