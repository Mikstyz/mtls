ALTER TABLE account_roles
    DROP CONSTRAINT account_roles_role_check,
    ADD CONSTRAINT account_roles_role_check CHECK (role IN ('moderator', 'ad_operator'));
