-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Accounts, logins and services (RFC 0003).

-- An external account has no native address.
ALTER TABLE accounts ALTER COLUMN primary_address DROP NOT NULL;
ALTER TABLE accounts ADD COLUMN username text, ADD COLUMN email text,
    ADD COLUMN email_verified boolean NOT NULL DEFAULT false;

-- Logins that are unique in an instance: usernames and verified contact addresses (read models of
-- account.username_set and account.email_set).
CREATE TABLE account_usernames (
    instance_id     uuid        NOT NULL REFERENCES instances (id),
    username        text        NOT NULL,
    account_id      uuid        NOT NULL UNIQUE REFERENCES accounts (id),
    PRIMARY KEY (instance_id, username)
);
CREATE TABLE account_emails (
    instance_id     uuid        NOT NULL REFERENCES instances (id),
    email           text        NOT NULL,
    account_id      uuid        NOT NULL UNIQUE REFERENCES accounts (id),
    PRIMARY KEY (instance_id, email)
);

-- What an account uses: `requested` waits for an administrator.
CREATE TABLE account_services (
    account_id      uuid        NOT NULL REFERENCES accounts (id),
    service         text        NOT NULL CHECK (service IN ('mail', 'files')),
    state           text        NOT NULL CHECK (state IN ('requested', 'on')),
    PRIMARY KEY (account_id, service)
);
-- Every account so far has mail (account.added revision 1 is read as granting it).
INSERT INTO account_services (account_id, service, state) SELECT id, 'mail', 'on' FROM accounts;

-- A tenant's rules: logins, registration, services.
ALTER TABLE tenants ADD COLUMN usernames boolean NOT NULL DEFAULT false,
    ADD COLUMN email_login boolean NOT NULL DEFAULT true,
    ADD COLUMN registration_allowed boolean NOT NULL DEFAULT false,
    ADD COLUMN registration_domains text[] NOT NULL DEFAULT '{}';
CREATE TABLE tenant_service_policies (
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    service         text        NOT NULL CHECK (service IN ('mail', 'files')),
    assign          text        NOT NULL CHECK (assign IN ('none', 'native', 'all')),
    approval        boolean     NOT NULL,
    PRIMARY KEY (tenant_id, service)
);

-- Where people without a native address register.
ALTER TABLE instances ADD COLUMN registration_tenant uuid REFERENCES tenants (id);

-- Providers people may register and log in with without a domain of their own (a "Sign in with …" button).
ALTER TABLE identity_providers ADD COLUMN register boolean NOT NULL DEFAULT false;

-- A provider login that links an account (from its account page), or that found an account with the same verified
-- address and proposes linking it (RFC 0003, 3).
ALTER TABLE idp_logins ADD COLUMN link_account uuid REFERENCES accounts (id),
    ADD COLUMN proposal_account uuid REFERENCES accounts (id),
    ADD COLUMN subject text, ADD COLUMN email text, ADD COLUMN display_name text;

-- A registration waiting for its code (RFC 0003, 5): not yet an account, no events.
CREATE TABLE registrations (
    id              uuid        PRIMARY KEY,
    instance_id     uuid        NOT NULL REFERENCES instances (id),
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    email           text        NOT NULL,
    native_address  text,
    username        text,
    display_name    text        NOT NULL,
    password_hash   text        NOT NULL,
    code_hash       bytea       NOT NULL,
    attempts        integer     NOT NULL DEFAULT 0,
    expires_at      timestamptz NOT NULL
);
CREATE INDEX registrations_by_expiry ON registrations (expires_at);

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
                   project_grants, mail_access, account_usernames, account_emails,
                   account_services, tenant_service_policies,
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
    -- The mail store of an account is created and changed, never removed by kernoid itself.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON mail_accounts TO %I', runtime);
    -- Mail is data (RFC 0002): mailboxes, emails and threads are created, changed and destroyed; the journal and the
    -- garbage of object storage are written and cleaned up.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON mailboxes, emails, email_mailboxes, threads, email_thread_refs,
                   sieve_scripts TO %I',
                   runtime);
    EXECUTE format('GRANT SELECT, INSERT, DELETE ON mail_changes TO %I', runtime);
    -- DKIM keys are made by the worker and read for signing; removing them is left to the owner.
    EXECUTE format('GRANT SELECT, INSERT ON dkim_keys TO %I', runtime);
    -- The queue: messages and their recipients come and go.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON outbound_messages, outbound_recipients TO %I', runtime);
    -- App passwords are credentials: set, used and removed. Policies and vacation replies are caches that expire.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON account_app_passwords, mta_sts_policies, sieve_vacation_sent TO %I',
                   runtime);
    -- What the protocols keep: uploads and submissions come and go; expunged UIDs are pruned with the journal.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON jmap_uploads, email_submissions TO %I', runtime);
    EXECUTE format('GRANT SELECT, INSERT, DELETE ON mailbox_expunged TO %I', runtime);
    -- Registrations wait for their code, then become accounts (events); the rest expire.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON registrations TO %I', runtime);
    -- A mark made again keeps the earlier due time (ON CONFLICT … DO UPDATE).
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON blob_garbage TO %I', runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
