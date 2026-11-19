ALTER TABLE registrations ADD COLUMN provision_lease_id UUID;
ALTER TABLE registrations ADD COLUMN provision_lease_until TIMESTAMPTZ;
ALTER TABLE registrations ADD COLUMN provision_after TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE registrations ADD COLUMN provision_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE registrations ADD CONSTRAINT registration_lease_pair
    CHECK ((provision_lease_id IS NULL) = (provision_lease_until IS NULL));
