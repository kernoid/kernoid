-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Instance administrators, roles a tenant defines itself, and projects with their roles (RFC 0001, 7.4 and 7.5).
-- Read models of the instance, tenant, project and authorization aggregates.

-- Instance roles held by accounts or groups of any tenant of the instance.
CREATE TABLE instance_role_assignments (
    instance_id     uuid        NOT NULL REFERENCES instances (id),
    principal_kind  text        NOT NULL CHECK (principal_kind IN ('account', 'group')),
    principal_id    uuid        NOT NULL,
    role            text        NOT NULL,
    PRIMARY KEY (instance_id, principal_kind, principal_id, role)
);
CREATE INDEX instance_role_assignments_by_principal ON instance_role_assignments (principal_id);

-- Roles a tenant defines: a name and the permissions it grants; the built-in roles are not stored.
CREATE TABLE tenant_roles (
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    name            text        NOT NULL,
    permissions     text[]      NOT NULL,
    PRIMARY KEY (tenant_id, name)
);

-- Projects hold applications and the roles those applications know (as in ZITADEL).
CREATE TABLE projects (
    id              uuid        PRIMARY KEY,
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    name            text        NOT NULL,
    -- Put the account's project roles into ID tokens and userinfo.
    role_assertion  boolean     NOT NULL DEFAULT false,
    -- Let only accounts with a role in the project log in to its applications.
    role_check      boolean     NOT NULL DEFAULT false
);
CREATE INDEX projects_by_tenant ON projects (tenant_id);

CREATE TABLE project_roles (
    project_id      uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    key             text        NOT NULL,
    display_name    text        NOT NULL,
    role_group      text,
    PRIMARY KEY (project_id, key)
);

-- Who holds which project role ("authorizations"): accounts or groups of the project's tenant.
CREATE TABLE project_authorizations (
    project_id      uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    principal_kind  text        NOT NULL CHECK (principal_kind IN ('account', 'group')),
    principal_id    uuid        NOT NULL,
    role            text        NOT NULL,
    PRIMARY KEY (project_id, principal_kind, principal_id, role),
    FOREIGN KEY (project_id, role) REFERENCES project_roles (project_id, key)
);
CREATE INDEX project_authorizations_by_principal ON project_authorizations (principal_id);

-- Applications belong to a project; older ones may have none.
ALTER TABLE applications ADD COLUMN project_id uuid REFERENCES projects (id);
CREATE INDEX applications_by_project ON applications (project_id);

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
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON instance_domains, tenant_domains, tenant_modules, addresses, groups, group_members, role_assignments,
                   instance_role_assignments, tenant_roles, projects, project_roles, project_authorizations TO %I',
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
