-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Projects granted to other tenants of the instance, with a part of their roles (RFC 0001, 7.5) – as ZITADEL's
-- project grants. Authorizations now say which tenant gave them: the project's own, or one it is granted to.

CREATE TABLE project_grants (
    project_id      uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    -- The project roles the tenant may give its own accounts and groups.
    roles           text[]      NOT NULL,
    PRIMARY KEY (project_id, tenant_id)
);
CREATE INDEX project_grants_by_tenant ON project_grants (tenant_id);

-- Authorizations so far were all given by the project's own tenant.
ALTER TABLE project_authorizations ADD COLUMN tenant_id uuid REFERENCES tenants (id);
UPDATE project_authorizations a SET tenant_id = p.tenant_id FROM projects p WHERE p.id = a.project_id;
ALTER TABLE project_authorizations ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX project_authorizations_by_tenant ON project_authorizations (project_id, tenant_id);

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
                   instance_role_assignments, tenant_roles, projects, project_roles, project_authorizations,
                   project_grants TO %I',
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
