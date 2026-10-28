-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Groups and the roles of a tenant (see kernoid-identity, group and roles). Read models of the group and tenant
-- aggregates, written inline; a role is granted to an account or to a group, whose members then hold it.

CREATE TABLE groups (
    id          uuid        PRIMARY KEY,
    tenant_id   uuid        NOT NULL REFERENCES tenants (id),
    name        text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX groups_by_tenant ON groups (tenant_id);

CREATE TABLE group_members (
    group_id    uuid        NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    account_id  uuid        NOT NULL REFERENCES accounts (id),
    PRIMARY KEY (group_id, account_id)
);
CREATE INDEX group_members_by_account ON group_members (account_id);

CREATE TABLE role_assignments (
    tenant_id       uuid    NOT NULL REFERENCES tenants (id),
    principal_kind  text    NOT NULL CHECK (principal_kind IN ('account', 'group')),
    principal_id    uuid    NOT NULL,
    role            text    NOT NULL,
    PRIMARY KEY (tenant_id, principal_kind, principal_id, role)
);
CREATE INDEX role_assignments_by_principal ON role_assignments (principal_id);

CREATE OR REPLACE FUNCTION kernoid_grant_runtime(runtime name) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    -- Events are read and added, never changed or removed.
    EXECUTE format('GRANT SELECT, INSERT ON events TO %I', runtime);
    -- Cursors are created and moved; a projection is rebuilt by the owner, not by kernoid itself.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON projection_cursors TO %I', runtime);
    -- Tenant keys are created and read; removing them (destroying a tenant's content) is left to the owner.
    EXECUTE format('GRANT SELECT, INSERT ON tenant_keys TO %I', runtime);
    -- Read models follow the events, including removals; they can be rebuilt from the events.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON instances, tenants, accounts, applications TO %I', runtime);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON instance_domains, tenant_domains, tenant_modules, addresses, groups, group_members, role_assignments TO %I',
                   runtime);
    -- Credentials are set, replaced and removed.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON account_passwords, application_secrets, signing_keys, account_totp, account_passkeys, account_recovery_codes TO %I',
                   runtime);
    -- Sessions, requests, challenges, codes and tokens end and expire; expired ones are cleaned up.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON sessions, login_failures, auth_requests, authorization_codes, access_tokens, refresh_tokens, webauthn_challenges TO %I',
                   runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
