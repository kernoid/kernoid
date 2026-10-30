-- SPDX-License-Identifier: AGPL-3.0-or-later
-- End-to-end encryption (RFC 0006). The keys of accounts: public keys, which anyone may learn (the directory, WKD,
-- Autocrypt), and the protected copies of their secret keys, which only the account's own clients can open – the
-- server never holds a secret key unprotected. Events say a key or copy was added; the bytes are here.
CREATE TABLE openpgp_keys (
    fingerprint text        PRIMARY KEY CHECK (fingerprint ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
    account_id  uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    tenant_id   uuid        NOT NULL REFERENCES tenants (id),
    kind        text        NOT NULL CHECK (kind IN ('pqc', 'compatible')),
    public_key  bytea       NOT NULL CHECK (length(public_key) <= 65536),
    created_at  timestamptz NOT NULL DEFAULT now(),
    -- Retired keys decrypt what was encrypted to them; nothing is encrypted to them again.
    retired_at  timestamptz
);
CREATE INDEX openpgp_keys_by_account ON openpgp_keys (account_id) WHERE retired_at IS NULL;
-- One key in use per account.
CREATE UNIQUE INDEX openpgp_keys_one_current ON openpgp_keys (account_id) WHERE retired_at IS NULL;

-- Protected copies of a secret key (RFC 0006, 4.2), by label: `recovery`, `tenant`, `passkey:<credential id>`,
-- `device:<id>`. `salt` is what a passkey's PRF extension is evaluated with.
CREATE TABLE openpgp_key_copies (
    fingerprint text        NOT NULL REFERENCES openpgp_keys (fingerprint) ON DELETE CASCADE,
    label       text        NOT NULL CHECK (label ~ '^(recovery|tenant|passkey:[A-Za-z0-9_-]{1,200}|device:[A-Za-z0-9_-]{1,64})$'),
    protected   bytea       NOT NULL CHECK (length(protected) <= 65536),
    salt        bytea       CHECK (length(salt) BETWEEN 16 AND 64),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (fingerprint, label)
);

-- An account's mail encrypted on arrival (RFC 0006, 5.1).
ALTER TABLE accounts ADD COLUMN mail_e2e boolean NOT NULL DEFAULT false;

-- The tenant's policy (RFC 0006, 8): each setting allowed, required or forbidden, and recovery through the tenant.
ALTER TABLE tenants ADD COLUMN e2e_mail text NOT NULL DEFAULT 'allowed' CHECK (e2e_mail IN ('allowed', 'required', 'forbidden'));
ALTER TABLE tenants ADD COLUMN e2e_vaults text NOT NULL DEFAULT 'allowed' CHECK (e2e_vaults IN ('allowed', 'required', 'forbidden'));
ALTER TABLE tenants ADD COLUMN e2e_collections text NOT NULL DEFAULT 'allowed'
    CHECK (e2e_collections IN ('allowed', 'required', 'forbidden'));
ALTER TABLE tenants ADD COLUMN e2e_recovery boolean NOT NULL DEFAULT false;

-- The tenant's recovery key (RFC 0006, 8.2): public only; its secret stays with the administrators.
CREATE TABLE tenant_recovery_keys (
    tenant_id   uuid        PRIMARY KEY REFERENCES tenants (id),
    fingerprint text        NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
    public_key  bytea       NOT NULL CHECK (length(public_key) <= 65536),
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Mail is data (RFC 0002): an email encrypted to its account's key carries its summary encrypted the same way
-- (RFC 0006, 5.2), as an OpenPGP message; its `subject` and `preview` are then empty.
ALTER TABLE emails ADD COLUMN encrypted boolean NOT NULL DEFAULT false;
ALTER TABLE emails ADD COLUMN encrypted_summary bytea CHECK (length(encrypted_summary) <= 65536);

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
                   project_grants, mail_access, collection_access, file_access, account_usernames, account_emails,
                   account_services, tenant_service_policies,
                   identity_providers, account_links,
                   scim_tokens, file_links,
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
                   idp_sessions, saml_logouts, acme_challenges, acme_orders,
                   file_link_access, file_link_failures TO %I',
                   runtime);
    -- What came in through links, until its notice is sent.
    EXECUTE format('GRANT SELECT, INSERT, DELETE ON file_link_arrivals TO %I', runtime);
    -- The mail store of an account is created and changed, never removed by kernoid itself.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON mail_accounts TO %I', runtime);
    -- Mail is data (RFC 0002): mailboxes, emails and threads are created, changed and destroyed; the journal and the
    -- garbage of object storage are written and cleaned up.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON mailboxes, emails, email_mailboxes, threads, email_thread_refs,
                   sieve_scripts TO %I',
                   runtime);
    EXECUTE format('GRANT SELECT, INSERT, DELETE ON mail_changes TO %I', runtime);
    -- The secret of SRS addresses (RFC 0002, 10.6): made once, then only read.
    EXECUTE format('GRANT SELECT, INSERT ON srs_secret TO %I', runtime);
    -- DKIM keys are made by the worker and read for signing; they go from next to active to retired; removing them
    -- is left to the owner.
    EXECUTE format('GRANT SELECT, INSERT ON dkim_keys TO %I', runtime);
    EXECUTE format('GRANT UPDATE (state, state_since) ON dkim_keys TO %I', runtime);
    -- The queue: messages and their recipients come and go.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON outbound_messages, outbound_recipients TO %I', runtime);
    -- App passwords are credentials: set, used and removed. Policies and vacation replies are caches that expire.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON account_app_passwords, mta_sts_policies, sieve_vacation_sent TO %I',
                   runtime);
    -- What the protocols keep: uploads and submissions come and go; expunged UIDs are pruned with the journal.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON jmap_uploads, email_submissions TO %I', runtime);
    -- A UID that leaves a mailbox again moves its modseq on (INSERT … ON CONFLICT … DO UPDATE needs UPDATE).
    EXECUTE format('GRANT SELECT, INSERT, DELETE ON mailbox_expunged TO %I', runtime);
    EXECUTE format('GRANT UPDATE (modseq) ON mailbox_expunged TO %I', runtime);
    -- Calendars and contacts are data like mail (RFC 0004): created, changed and destroyed; the journal is written and
    -- pruned.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON groupware_accounts, calendars, calendar_events,
                   calendar_notifications, addressbooks, contacts TO %I', runtime);
    EXECUTE format('GRANT SELECT, INSERT, DELETE ON groupware_changes TO %I', runtime);
    -- Files are data like mail (RFC 0005): the store is created and changed, never removed by kernoid itself; nodes,
    -- contents and locks are created, changed and destroyed; the journal is written and pruned.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON file_accounts TO %I', runtime);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON file_nodes, file_contents, file_locks TO %I', runtime);
    EXECUTE format('GRANT SELECT, INSERT, DELETE ON file_changes TO %I', runtime);
    -- Registrations wait for their code, then become accounts (events); the rest expire.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON registrations TO %I', runtime);
    -- An account's vacation response is made and changed by its owner.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON vacation_responses TO %I', runtime);
    -- Meeting rooms of the module jitsi are made and read.
    EXECUTE format('GRANT SELECT, INSERT ON jitsi_rooms TO %I', runtime);
    -- An account's picture is set, replaced and removed by its owner.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON account_avatars TO %I', runtime);
    -- Public keys of accounts and tenants and the protected copies of secret keys (RFC 0006): added, retired, replaced
    -- and removed as their events say.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON openpgp_keys, openpgp_key_copies, tenant_recovery_keys TO %I', runtime);
    -- A mark made again keeps the earlier due time (ON CONFLICT … DO UPDATE).
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON blob_garbage TO %I', runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;

