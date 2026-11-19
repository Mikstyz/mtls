CREATE TABLE security_event_versions (
    user_id UUID PRIMARY KEY,
    version BIGINT NOT NULL CHECK (version > 0)
);

CREATE TABLE security_event_outbox (
    event_id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    event_type TEXT NOT NULL CHECK (event_type IN (
        'password_changed', 'credentials_enabled', 'credentials_disabled', 'credentials_deleted',
        'session_revoked', 'role_changed', 'deletion_started', 'account_archived',
        'restore_started', 'purge_started', 'account_restored', 'account_purged', 'deletion_record_removed'
    )),
    lifecycle_state TEXT CHECK (lifecycle_state IN (
        'deleting', 'deleted', 'restoring_owner', 'restoring_moderator', 'purging'
    )),
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    published_at TIMESTAMPTZ,
    lease_id UUID,
    lease_until TIMESTAMPTZ,
    available_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    UNIQUE (user_id, version),
    CHECK ((lease_id IS NULL) = (lease_until IS NULL)),
    CHECK ((lifecycle_state IS NULL) = (deleted_at IS NULL))
);

CREATE INDEX security_event_outbox_pending_idx
    ON security_event_outbox (available_at, created_at, event_id)
    WHERE published_at IS NULL;

CREATE FUNCTION append_security_event(
    event_user UUID, event_kind TEXT, event_state TEXT DEFAULT NULL,
    account_deleted_at TIMESTAMPTZ DEFAULT NULL
) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
    next_version BIGINT;
BEGIN
    INSERT INTO security_event_versions (user_id, version)
    VALUES (event_user, 1)
    ON CONFLICT (user_id) DO UPDATE SET version = security_event_versions.version + 1
    RETURNING version INTO next_version;

    INSERT INTO security_event_outbox (event_id, user_id, version, event_type, lifecycle_state, deleted_at)
    VALUES (gen_random_uuid(), event_user, next_version, event_kind, event_state, account_deleted_at);
END;
$$;

CREATE FUNCTION record_credential_security_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM append_security_event(OLD.user_id, 'credentials_deleted');
        RETURN OLD;
    END IF;

    IF (OLD.password_hash IS DISTINCT FROM NEW.password_hash OR OLD.password_salt IS DISTINCT FROM NEW.password_salt)
       AND NOT (OLD.password_version = 1 AND NEW.password_version = 2
                AND OLD.password_revision = NEW.password_revision) THEN
        PERFORM append_security_event(NEW.user_id, 'password_changed');
    END IF;

    IF OLD.enabled IS DISTINCT FROM NEW.enabled THEN
        IF NEW.enabled THEN
            PERFORM append_security_event(NEW.user_id, 'credentials_enabled');
        ELSE
            PERFORM append_security_event(NEW.user_id, 'credentials_disabled');
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER credentials_security_event_update
AFTER UPDATE ON credentials
FOR EACH ROW EXECUTE FUNCTION record_credential_security_event();

CREATE TRIGGER credentials_security_event_delete
AFTER DELETE ON credentials
FOR EACH ROW EXECUTE FUNCTION record_credential_security_event();

CREATE FUNCTION record_session_revocation_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM append_security_event(OLD.user_id, 'session_revoked');
        RETURN OLD;
    END IF;

    PERFORM append_security_event(NEW.user_id, 'session_revoked');
    RETURN NEW;
END;
$$;

CREATE TRIGGER sessions_security_event_revocation
AFTER UPDATE OF revoked_at ON sessions
FOR EACH ROW WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
EXECUTE FUNCTION record_session_revocation_event();

CREATE TRIGGER sessions_security_event_delete
AFTER DELETE ON sessions
FOR EACH ROW WHEN (OLD.revoked_at IS NULL AND OLD.expires_at > clock_timestamp()
                   AND OLD.last_seen_at > clock_timestamp() - INTERVAL '168 hours')
EXECUTE FUNCTION record_session_revocation_event();

CREATE FUNCTION record_role_security_event() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    affected_user UUID;
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        FOR affected_user IN SELECT DISTINCT user_id FROM account_roles ORDER BY user_id LOOP
            PERFORM append_security_event(affected_user, 'role_changed');
        END LOOP;
        RETURN NULL;
    END IF;

    IF TG_OP = 'UPDATE' AND OLD.user_id = NEW.user_id AND OLD.role = NEW.role THEN
        RETURN NULL;
    END IF;

    IF TG_OP = 'DELETE' THEN
        PERFORM append_security_event(OLD.user_id, 'role_changed');
    ELSE
        IF TG_OP = 'UPDATE' AND OLD.user_id <> NEW.user_id THEN
            PERFORM append_security_event(OLD.user_id, 'role_changed');
        END IF;
        PERFORM append_security_event(NEW.user_id, 'role_changed');
    END IF;

    RETURN NULL;
END;
$$;

CREATE TRIGGER account_roles_security_event
AFTER INSERT OR UPDATE OR DELETE ON account_roles
FOR EACH ROW EXECUTE FUNCTION record_role_security_event();

CREATE TRIGGER account_roles_security_event_truncate
BEFORE TRUNCATE ON account_roles
FOR EACH STATEMENT EXECUTE FUNCTION record_role_security_event();

CREATE FUNCTION record_account_lifecycle_event() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    event_kind TEXT;
    item account_deletions%ROWTYPE;
BEGIN
    IF TG_OP = 'DELETE' THEN
        item := OLD;
        event_kind := CASE
            WHEN OLD.state IN ('restoring_owner', 'restoring_moderator') AND EXISTS (
                SELECT 1 FROM credentials WHERE user_id = OLD.user_id AND enabled
            ) THEN 'account_restored'
            WHEN OLD.state = 'purging' THEN 'account_purged'
            ELSE 'deletion_record_removed'
        END;
    ELSE
        item := NEW;

        IF TG_OP = 'UPDATE' AND OLD.state = NEW.state THEN
            RETURN NEW;
        END IF;

        event_kind := CASE
            WHEN NEW.state = 'deleting' THEN 'deletion_started'
            WHEN NEW.state = 'deleted' THEN 'account_archived'
            WHEN NEW.state IN ('restoring_owner', 'restoring_moderator') THEN 'restore_started'
            WHEN NEW.state = 'purging' THEN 'purge_started'
        END;
    END IF;

    PERFORM append_security_event(item.user_id, event_kind, item.state, item.deleted_at);

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER account_deletions_security_event
AFTER INSERT OR UPDATE OR DELETE ON account_deletions
FOR EACH ROW EXECUTE FUNCTION record_account_lifecycle_event();
