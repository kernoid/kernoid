-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Federation completed (RFC 0001, 7.7, 7.8): identity providers for a whole instance, profile sync, kernoid's own
-- SAML key (signed requests, encrypted assertions), single logout, and what SCIM needs for ETags.

-- A provider belongs to a tenant, or to the instance (tenant_id NULL) and serves all its tenants' domains.
ALTER TABLE identity_providers ADD COLUMN instance_id uuid REFERENCES instances (id);
UPDATE identity_providers p SET instance_id = t.instance_id FROM tenants t WHERE t.id = p.tenant_id;
ALTER TABLE identity_providers ALTER COLUMN instance_id SET NOT NULL;
ALTER TABLE identity_providers ALTER COLUMN tenant_id DROP NOT NULL;
CREATE INDEX identity_providers_by_instance ON identity_providers (instance_id);
ALTER TABLE identity_providers ADD COLUMN sync_profile boolean NOT NULL DEFAULT false;
ALTER TABLE identity_providers ADD COLUMN saml_sign_requests boolean NOT NULL DEFAULT false;
ALTER TABLE identity_providers ADD COLUMN saml_slo_url text;

-- kernoid's SAML key of an instance: signs requests, decrypts assertions; sealed with the main key. The certificate
-- (self-signed) carries the public key into the metadata.
CREATE TABLE saml_sp_keys (
    instance_id     uuid        PRIMARY KEY REFERENCES instances (id),
    private_sealed  bytea       NOT NULL,
    certificate     bytea       NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- Who logged in at a SAML provider, for single logout.
ALTER TABLE idp_logins ADD COLUMN saml_name_id text;
ALTER TABLE idp_logins ADD COLUMN saml_name_id_format text;
ALTER TABLE idp_logins ADD COLUMN saml_session_index text;
CREATE TABLE idp_sessions (
    session_id          uuid    PRIMARY KEY REFERENCES sessions (id) ON DELETE CASCADE,
    idp_id              uuid    NOT NULL REFERENCES identity_providers (id) ON DELETE CASCADE,
    name_id             text    NOT NULL,
    name_id_format      text,
    session_index       text
);
CREATE INDEX idp_sessions_by_name ON idp_sessions (idp_id, name_id);

-- Logout requests kernoid sent, until the provider answers.
CREATE TABLE saml_logouts (
    request_id      text        PRIMARY KEY,
    instance_id     uuid        NOT NULL REFERENCES instances (id),
    idp_id          uuid        NOT NULL REFERENCES identity_providers (id) ON DELETE CASCADE,
    expires_at      timestamptz NOT NULL
);

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
                   scim_tokens,
                   consents, instance_roles TO %I',
                   runtime);
    -- Credentials are set, replaced and removed.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON account_passwords, application_secrets, signing_keys, account_totp, account_passkeys, account_recovery_codes,
                   identity_provider_secrets, saml_sp_keys TO %I',
                   runtime);
    -- Sessions, requests, challenges, codes and tokens end and expire; expired ones are cleaned up.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON sessions, login_failures, auth_requests, authorization_codes, access_tokens, refresh_tokens, webauthn_challenges,
                   idp_logins,
                   session_applications, logout_notifications, known_devices,
                   idp_sessions, saml_logouts TO %I',
                   runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
