-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Sending mail, the rest (RFC 0002, 10): app passwords for submission, the MTA-STS policies of receiving domains, and
-- whom a vacation reply went to.

-- App passwords (RFC 0002, 10.1): random, so a SHA-256 hash is enough, as for tokens. The events say only that one
-- was added or removed.
CREATE TABLE account_app_passwords (
    id              uuid        PRIMARY KEY,
    account_id      uuid        NOT NULL REFERENCES accounts (id),
    name            text        NOT NULL,
    hash            bytea       NOT NULL UNIQUE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz
);
CREATE INDEX account_app_passwords_by_account ON account_app_passwords (account_id);

-- MTA-STS policies of the domains kernoid sends to (RFC 8461), kept for their max_age.
CREATE TABLE mta_sts_policies (
    domain          text        PRIMARY KEY,
    -- The id from the _mta-sts TXT record: a new one means a new policy.
    policy_id       text        NOT NULL,
    mode            text        NOT NULL CHECK (mode IN ('enforce', 'testing', 'none')),
    mx              text[]      NOT NULL,
    fetched_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL
);

-- Whom an account's vacation reply went to, and until when it is not sent again (RFC 5230, 4.6).
CREATE TABLE sieve_vacation_sent (
    account_id      uuid        NOT NULL REFERENCES mail_accounts (account_id),
    key             text        NOT NULL,
    expires_at      timestamptz NOT NULL,
    PRIMARY KEY (account_id, key)
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
    -- A mark made again keeps the earlier due time (ON CONFLICT … DO UPDATE).
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON blob_garbage TO %I', runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
