-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Files (RFC 0005): the file store of each account – directories and files, their contents and versions, the
-- journal of changes – with the content in object storage, sealed per tenant and stored in parts. Its own store
-- beside the mail store: files do not need a mailbox. Drives are accounts of the tenant that only hold files.

-- Quotas are administration (account.files_quota_set, tenant.default_files_quota_set); none means no limit.
ALTER TABLE accounts ADD COLUMN files_quota bigint CHECK (files_quota >= 0);
ALTER TABLE tenants ADD COLUMN default_files_quota bigint CHECK (default_files_quota >= 0);

-- A drive (RFC 0005, 12): a file store of the tenant, without a login and without an address.
ALTER TABLE accounts DROP CONSTRAINT accounts_kind_check;
ALTER TABLE accounts ADD CONSTRAINT accounts_kind_check CHECK (kind IN ('person', 'shared', 'drive'));

-- Uploads belong to the account, whatever service it has (RFC 0005, 8), not to its mail store, and are stored in
-- parts (upload/<account>/<id>/<n>); rows from before have one object (parts is null).
ALTER TABLE jmap_uploads DROP CONSTRAINT jmap_uploads_account_id_fkey;
ALTER TABLE jmap_uploads ADD CONSTRAINT jmap_uploads_account_id_fkey FOREIGN KEY (account_id) REFERENCES accounts (id);
ALTER TABLE jmap_uploads ADD COLUMN parts integer CHECK (parts >= 0);
ALTER TABLE jmap_uploads ADD COLUMN sha256 bytea;

-- One row per account that has used files: its modification sequence and the bytes its files take. Every change to
-- the account's files takes this row first.
CREATE TABLE file_accounts (
    account_id      uuid        PRIMARY KEY REFERENCES accounts (id),
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    modseq          bigint      NOT NULL DEFAULT 0 CHECK (modseq >= 0),
    -- Journal rows up to this modseq are gone: older states cannot be brought up to date.
    changes_floor   bigint      NOT NULL DEFAULT 0,
    -- The contents of all files and their versions.
    used_bytes      bigint      NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE file_nodes (
    id              uuid        PRIMARY KEY,
    account_id      uuid        NOT NULL REFERENCES file_accounts (account_id),
    parent_id       uuid        REFERENCES file_nodes (id),
    node_type       text        NOT NULL CHECK (node_type IN ('directory', 'file')),
    name            text        NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 255),
    role            text        CHECK (role IN ('trash')),
    -- Files: the current content, its size (as in file_contents, for queries) and type.
    content_id      uuid        UNIQUE,
    size            bigint      CHECK (size >= 0),
    media_type      text,
    executable      boolean,
    created         timestamptz NOT NULL,
    modified        timestamptz NOT NULL,
    accessed        timestamptz NOT NULL,
    changed         timestamptz NOT NULL DEFAULT now(),
    is_subscribed   boolean     NOT NULL DEFAULT true,
    CHECK ((node_type = 'file') = (content_id IS NOT NULL AND size IS NOT NULL AND media_type IS NOT NULL
                                   AND executable IS NOT NULL)),
    CHECK (role IS NULL OR node_type = 'directory')
);
CREATE UNIQUE INDEX file_nodes_one_role ON file_nodes (account_id, role) WHERE role IS NOT NULL;
-- Names are unique among siblings; NULLS NOT DISTINCT makes it hold at the top as well.
CREATE UNIQUE INDEX file_nodes_unique_name ON file_nodes (account_id, parent_id, name) NULLS NOT DISTINCT;
CREATE INDEX file_nodes_by_parent ON file_nodes (parent_id);

-- The contents of a file: the current one and earlier versions (RFC 0005, 5 and 6). The parts lie below prefix in
-- object storage – files/<account>/<id>, or the upload's own prefix when a file took an upload; several contents may
-- share one prefix (copies), which goes to the garbage with the last of them.
CREATE TABLE file_contents (
    id              uuid        PRIMARY KEY,
    account_id      uuid        NOT NULL REFERENCES file_accounts (account_id),
    node_id         uuid        NOT NULL REFERENCES file_nodes (id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    prefix          text        NOT NULL,
    parts           integer     NOT NULL CHECK (parts >= 0),
    size            bigint      NOT NULL CHECK (size >= 0),
    sha256          bytea       NOT NULL,
    media_type      text        NOT NULL,
    -- The file's modification time while this was its content.
    modified        timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX file_contents_by_node ON file_contents (node_id, created_at);
CREATE INDEX file_contents_by_prefix ON file_contents (prefix);
ALTER TABLE file_nodes ADD CONSTRAINT file_nodes_content FOREIGN KEY (content_id) REFERENCES file_contents (id)
    DEFERRABLE INITIALLY DEFERRED;

-- The journal of changes, for JMAP FileNode/changes; old rows are removed by the worker.
CREATE TABLE file_changes (
    account_id      uuid        NOT NULL REFERENCES file_accounts (account_id),
    modseq          bigint      NOT NULL,
    node_id         uuid        NOT NULL,
    change          text        NOT NULL CHECK (change IN ('created', 'updated', 'destroyed')),
    changed_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, modseq, node_id)
);
CREATE INDEX file_changes_by_age ON file_changes (changed_at);

-- Who may use whose files (RFC 0005, 11): a read model of account.file_access_set and account.file_access_removed.
-- A grant is on one directory and what lies below it, or on the whole store (node_id null). Rights are letters:
-- r read, a add children, n rename, d delete, w modify content, s share.
CREATE TABLE file_access (
    owner_id        uuid        NOT NULL REFERENCES accounts (id),
    node_id         uuid,
    grantee_account uuid        REFERENCES accounts (id),
    grantee_group   uuid        REFERENCES groups (id) ON DELETE CASCADE,
    rights          text        NOT NULL CHECK (rights ~ '^[randws]+$'),
    granted_at      timestamptz NOT NULL,
    CHECK ((grantee_account IS NULL) <> (grantee_group IS NULL))
);
CREATE UNIQUE INDEX file_access_one_grant ON file_access
    (owner_id, node_id, coalesce(grantee_account, grantee_group)) NULLS NOT DISTINCT;
CREATE INDEX file_access_by_account ON file_access (grantee_account);
CREATE INDEX file_access_by_group ON file_access (grantee_group);

-- WebDAV locks (RFC 4918, 6–7) on nodes; they expire.
CREATE TABLE file_locks (
    token           text        PRIMARY KEY,
    account_id      uuid        NOT NULL REFERENCES file_accounts (account_id),
    node_id         uuid        NOT NULL REFERENCES file_nodes (id) ON DELETE CASCADE,
    holder_id       uuid        NOT NULL REFERENCES accounts (id),
    exclusive       boolean     NOT NULL,
    deep            boolean     NOT NULL,
    owner_info      text,
    expires_at      timestamptz NOT NULL
);
CREATE INDEX file_locks_by_node ON file_locks (node_id);
CREATE INDEX file_locks_by_expiry ON file_locks (expires_at);

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
    -- A mark made again keeps the earlier due time (ON CONFLICT … DO UPDATE).
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON blob_garbage TO %I', runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
