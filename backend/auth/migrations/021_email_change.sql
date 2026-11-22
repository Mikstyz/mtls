ALTER TABLE password_resets ADD COLUMN pending_email TEXT;
ALTER TABLE password_resets DROP CONSTRAINT password_resets_purpose_check;
ALTER TABLE password_resets ADD CONSTRAINT password_resets_purpose_check CHECK (
    (purpose IN ('password_reset', 'verify_email') AND pending_email IS NULL)
    OR (purpose='change_email' AND pending_email IS NOT NULL AND pending_email<>email)
);
