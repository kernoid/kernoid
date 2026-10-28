-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Provisioning with SCIM 2.0 (RFC 7643, 7644; RFC 0001, 7.8): tokens a tenant gives its directory (Entra ID, Okta …),
-- and the identifiers that directory knows its users and groups by.

CREATE TABLE scim_tokens (
    id              uuid        PRIMARY KEY,
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    name            text        NOT NULL,
    -- SHA-256 of the token; the token is shown once.
    token_hash      bytea       NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz
);
CREATE INDEX scim_tokens_by_tenant ON scim_tokens (tenant_id);

-- The directory's own identifier (`externalId`), set by provisioning.
ALTER TABLE accounts ADD COLUMN external_id text;
ALTER TABLE groups ADD COLUMN external_id text;
CREATE INDEX accounts_by_external_id ON accounts (tenant_id, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX groups_by_external_id ON groups (tenant_id, external_id) WHERE external_id IS NOT NULL;

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
                   project_grants,
                   identity_providers, account_links,
                   scim_tokens TO %I',
                   runtime);
    -- Credentials are set, replaced and removed.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON account_passwords, application_secrets, signing_keys, account_totp, account_passkeys, account_recovery_codes,
                   identity_provider_secrets TO %I',
                   runtime);
    -- Sessions, requests, challenges, codes and tokens end and expire; expired ones are cleaned up.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON sessions, login_failures, auth_requests, authorization_codes, access_tokens, refresh_tokens, webauthn_challenges,
                   idp_logins TO %I',
                   runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
