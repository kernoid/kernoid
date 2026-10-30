-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Vaults (RFC 0006, 6): directories whose content only their members can read. A vault's root holds the vault's
-- public key, which every writer encrypts to; each node inside names its vault, so that moves and copies across a
-- vault's boundary can be refused and WebDAV and the content search leave vaults out. Inside a vault the name is an
-- id the client chose, the real name an OpenPGP message of its own.
ALTER TABLE file_nodes ADD COLUMN vault_key bytea CHECK (length(vault_key) <= 65536);
ALTER TABLE file_nodes ADD COLUMN vault_id uuid REFERENCES file_nodes (id);
ALTER TABLE file_nodes ADD COLUMN encrypted_name bytea CHECK (length(encrypted_name) <= 16384);
ALTER TABLE file_nodes ADD CONSTRAINT file_nodes_vault_root
    CHECK (vault_key IS NULL OR (node_type = 'directory' AND vault_id = id));
ALTER TABLE file_nodes ADD CONSTRAINT file_nodes_vault_names CHECK (vault_id IS NULL OR encrypted_name IS NOT NULL);
CREATE INDEX file_nodes_by_vault ON file_nodes (vault_id) WHERE vault_id IS NOT NULL;

-- The vault's secret key, encrypted to the key of each account that may read it – made and wrapped by members'
-- apps, never readable by kernoid.
CREATE TABLE file_vault_keys (
    vault_id    uuid        NOT NULL REFERENCES file_nodes (id) ON DELETE CASCADE,
    account_id  uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    sealed      bytea       NOT NULL CHECK (length(sealed) BETWEEN 1 AND 65536),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (vault_id, account_id)
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
    -- Vaults' keys, wrapped for their members: added, replaced and removed by the members' apps.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON file_vault_keys TO %I', runtime);
    -- A mark made again keeps the earlier due time (ON CONFLICT … DO UPDATE).
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON blob_garbage TO %I', runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;

