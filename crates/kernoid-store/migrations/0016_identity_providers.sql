-- SPDX-License-Identifier: AGPL-3.0-or-later
-- External identity providers of tenants: logging in with another OpenID provider (RFC 0001, 7.7).

CREATE TABLE identity_providers (
    id              uuid        PRIMARY KEY,
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    name            text        NOT NULL,
    -- `oidc` for now.
    kind            text        NOT NULL CHECK (kind IN ('oidc')),
    issuer          text        NOT NULL,
    client_id       text        NOT NULL,
    scopes          text[]      NOT NULL,
    -- Mail domains of the tenant whose logins go to this provider.
    domains         text[]      NOT NULL DEFAULT '{}',
    -- Create an account at the first login (just in time), and link an existing account with the same address.
    auto_create     boolean     NOT NULL DEFAULT false,
    auto_link       boolean     NOT NULL DEFAULT false,
    active          boolean     NOT NULL DEFAULT true
);
CREATE INDEX identity_providers_by_tenant ON identity_providers (tenant_id);

-- The client secret kernoid authenticates with at the provider, sealed with the main key: it must be read again.
CREATE TABLE identity_provider_secrets (
    idp_id          uuid        PRIMARY KEY REFERENCES identity_providers (id) ON DELETE CASCADE,
    sealed          bytea       NOT NULL
);

-- Which external identity (the provider's `sub`) is which account.
CREATE TABLE account_links (
    idp_id          uuid        NOT NULL REFERENCES identity_providers (id),
    subject         text        NOT NULL,
    account_id      uuid        NOT NULL REFERENCES accounts (id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (idp_id, subject)
);
CREATE INDEX account_links_by_account ON account_links (account_id);

-- Logins under way at a provider: started, then answered at the callback, then handed to the browser once.
CREATE TABLE idp_logins (
    id              uuid        PRIMARY KEY,
    instance_id     uuid        NOT NULL REFERENCES instances (id),
    idp_id          uuid        NOT NULL REFERENCES identity_providers (id) ON DELETE CASCADE,
    -- SHA-256 of the `state` sent to the provider.
    state_hash      bytea       NOT NULL UNIQUE CHECK (length(state_hash) = 32),
    verifier        text        NOT NULL,
    nonce           text        NOT NULL,
    auth_request_id text,
    expires_at      timestamptz NOT NULL,
    -- Set at the callback: who logged in, with what, and the SHA-256 of the code the browser exchanges once.
    account_id      uuid        REFERENCES accounts (id),
    checks          text[],
    handoff_hash    bytea       CHECK (length(handoff_hash) = 32),
    used_at         timestamptz
);
CREATE INDEX idp_logins_by_expiry ON idp_logins (expires_at);

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
                   identity_providers, account_links TO %I',
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
