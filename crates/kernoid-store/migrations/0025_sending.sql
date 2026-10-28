-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Sending mail (RFC 0002, 10): DKIM keys per domain and the queue of outgoing mail.

-- One DKIM key per verified domain of a tenant (RFC 0002, 10.3): the private key sealed with the main key, the public
-- key as published (SubjectPublicKeyInfo, DER).
CREATE TABLE dkim_keys (
    domain          text        PRIMARY KEY,
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    selector        text        NOT NULL,
    private_sealed  bytea       NOT NULL,
    public_key      bytea       NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- Outgoing messages (RFC 0002, 10.2); the message itself is in object storage, sealed with the tenant's key.
CREATE TABLE outbound_messages (
    id              uuid        PRIMARY KEY,
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    -- The account that sent it, if any (bounces and replies of Sieve have one too).
    account_id      uuid        REFERENCES accounts (id),
    -- Empty for bounces: they get no bounce of their own.
    envelope_from   text        NOT NULL,
    size            bigint      NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- After this, recipients still waiting fail and are bounced.
    expires_at      timestamptz NOT NULL
);

CREATE TABLE outbound_recipients (
    message_id      uuid        NOT NULL REFERENCES outbound_messages (id) ON DELETE CASCADE,
    address         text        NOT NULL,
    domain          text        NOT NULL,
    status          text        NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'delivered', 'failed')),
    attempts        integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    -- A worker delivering it holds it until then.
    leased_until    timestamptz,
    last_error      text,
    PRIMARY KEY (message_id, address)
);
CREATE INDEX outbound_recipients_due ON outbound_recipients (next_attempt_at, domain) WHERE status = 'queued';

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
    -- A mark made again keeps the earlier due time (ON CONFLICT … DO UPDATE).
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON blob_garbage TO %I', runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
