ALTER TABLE password_resets ADD COLUMN purpose TEXT NOT NULL DEFAULT 'password_reset';
ALTER TABLE password_resets ADD COLUMN email TEXT;

UPDATE password_resets p SET email = c.email FROM credentials c WHERE c.user_id = p.user_id;

ALTER TABLE password_resets ALTER COLUMN email SET NOT NULL;
ALTER TABLE password_resets ADD CONSTRAINT password_resets_purpose_check
    CHECK (purpose IN ('password_reset', 'verify_email'));
