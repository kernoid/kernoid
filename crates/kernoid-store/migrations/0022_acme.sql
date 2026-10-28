-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Certificates from an ACME CA (RFC 8555) for the instances' domains, kept in PostgreSQL so that every process of an
-- installation serves them and answers the CA's HTTP-01 challenges (RFC 0001, 9).

-- The installation's account at a CA; its key sealed with the main key.
CREATE TABLE acme_accounts (
    directory           text        PRIMARY KEY,
    credentials_sealed  bytea       NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now()
);

-- A certificate per domain: the chain (PEM) and its private key, sealed with the main key.
CREATE TABLE tls_certificates (
    domain          text        PRIMARY KEY,
    chain_pem       text        NOT NULL,
    key_sealed      bytea       NOT NULL,
    not_after       timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- HTTP-01 challenges being answered: token and key authorization, as the CA expects them under
-- /.well-known/acme-challenge/<token>.
CREATE TABLE acme_challenges (
    token               text        PRIMARY KEY,
    key_authorization   text        NOT NULL,
    expires_at          timestamptz NOT NULL
);

-- Orders that failed, so that the next attempt waits (the CA's rate limits).
CREATE TABLE acme_orders (
    domain          text        PRIMARY KEY,
    attempts        integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error      text
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
                   identity_provider_secrets, saml_sp_keys, acme_accounts, tls_certificates TO %I',
                   runtime);
    -- Sessions, requests, challenges, codes and tokens end and expire; expired ones are cleaned up.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON sessions, login_failures, auth_requests, authorization_codes, access_tokens, refresh_tokens, webauthn_challenges,
                   idp_logins,
                   session_applications, logout_notifications, known_devices,
                   idp_sessions, saml_logouts, acme_challenges, acme_orders TO %I',
                   runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
