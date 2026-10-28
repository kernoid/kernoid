-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Mail (RFC 0002): the mail store of each account – mailboxes, emails, threads, the journal of changes – and the
-- objects in object storage waiting to be removed. The raw messages are in object storage, sealed per tenant.

-- An account's quota is administration (account.mail_quota_set); none means no limit.
ALTER TABLE accounts ADD COLUMN mail_quota bigint CHECK (mail_quota >= 0);

-- One row per account that has used mail: its modification sequence and the bytes its emails take. Every change to
-- the account's mail takes this row first.
CREATE TABLE mail_accounts (
    account_id      uuid        PRIMARY KEY REFERENCES accounts (id),
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    modseq          bigint      NOT NULL DEFAULT 0 CHECK (modseq >= 0),
    -- Journal rows up to this modseq are gone: older states cannot be brought up to date.
    changes_floor   bigint      NOT NULL DEFAULT 0,
    used_bytes      bigint      NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE mailboxes (
    id              uuid        PRIMARY KEY,
    account_id      uuid        NOT NULL REFERENCES mail_accounts (account_id),
    parent_id       uuid        REFERENCES mailboxes (id),
    name            text        NOT NULL,
    role            text        CHECK (role IN ('inbox', 'drafts', 'sent', 'archive', 'junk', 'trash')),
    sort_order      integer     NOT NULL DEFAULT 0 CHECK (sort_order >= 0),
    is_subscribed   boolean     NOT NULL DEFAULT true,
    uid_validity    bigint      NOT NULL CHECK (uid_validity BETWEEN 1 AND 4294967295),
    uid_next        bigint      NOT NULL DEFAULT 1 CHECK (uid_next BETWEEN 1 AND 4294967296),
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX mailboxes_one_role ON mailboxes (account_id, role) WHERE role IS NOT NULL;
-- Names are unique among siblings; NULLS NOT DISTINCT makes it hold at the top as well.
CREATE UNIQUE INDEX mailboxes_unique_name ON mailboxes (account_id, parent_id, name) NULLS NOT DISTINCT;
CREATE INDEX mailboxes_by_parent ON mailboxes (parent_id);

CREATE TABLE threads (
    id              uuid        PRIMARY KEY,
    account_id      uuid        NOT NULL REFERENCES mail_accounts (account_id)
);
CREATE INDEX threads_by_account ON threads (account_id);

CREATE TABLE emails (
    id              uuid        PRIMARY KEY,
    account_id      uuid        NOT NULL REFERENCES mail_accounts (account_id),
    thread_id       uuid        NOT NULL REFERENCES threads (id),
    size            bigint      NOT NULL CHECK (size >= 0),
    received_at     timestamptz NOT NULL,
    sent_at         timestamptz,
    message_id      text,
    in_reply_to     text[]      NOT NULL DEFAULT '{}',
    "references"    text[]      NOT NULL DEFAULT '{}',
    subject         text,
    from_addresses  jsonb       NOT NULL DEFAULT '[]',
    to_addresses    jsonb       NOT NULL DEFAULT '[]',
    cc_addresses    jsonb       NOT NULL DEFAULT '[]',
    bcc_addresses   jsonb       NOT NULL DEFAULT '[]',
    reply_to        jsonb       NOT NULL DEFAULT '[]',
    sender          jsonb       NOT NULL DEFAULT '[]',
    preview         text        NOT NULL DEFAULT '',
    has_attachment  boolean     NOT NULL DEFAULT false,
    keywords        text[]      NOT NULL DEFAULT '{}'
);
CREATE INDEX emails_by_account ON emails (account_id, received_at DESC);
CREATE INDEX emails_by_thread ON emails (thread_id, received_at);

-- The mailboxes an email is in, with its IMAP UID there and the modseq of its last change there.
CREATE TABLE email_mailboxes (
    email_id        uuid        NOT NULL REFERENCES emails (id) ON DELETE CASCADE,
    mailbox_id      uuid        NOT NULL REFERENCES mailboxes (id),
    uid             bigint      NOT NULL CHECK (uid BETWEEN 1 AND 4294967295),
    modseq          bigint      NOT NULL,
    PRIMARY KEY (email_id, mailbox_id)
);
CREATE UNIQUE INDEX email_mailboxes_by_uid ON email_mailboxes (mailbox_id, uid);

-- Threading (RFC 0002, 5): the message ids of each email, with a hash of its base subject.
CREATE TABLE email_thread_refs (
    account_id      uuid        NOT NULL REFERENCES mail_accounts (account_id),
    subject_hash    bytea       NOT NULL,
    message_ref     text        NOT NULL,
    email_id        uuid        NOT NULL REFERENCES emails (id) ON DELETE CASCADE,
    PRIMARY KEY (account_id, subject_hash, message_ref, email_id)
);
CREATE INDEX email_thread_refs_by_email ON email_thread_refs (email_id);

-- The journal of changes, for JMAP */changes; old rows are removed by the worker.
CREATE TABLE mail_changes (
    account_id      uuid        NOT NULL REFERENCES mail_accounts (account_id),
    modseq          bigint      NOT NULL,
    object_type     text        NOT NULL CHECK (object_type IN ('mailbox', 'email', 'thread')),
    object_id       uuid        NOT NULL,
    change          text        NOT NULL CHECK (change IN ('created', 'updated', 'destroyed')),
    changed_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, object_type, modseq, object_id)
);
CREATE INDEX mail_changes_by_age ON mail_changes (changed_at);

-- Objects to remove from object storage once due (RFC 0002, 7): written before an object is stored and removed when
-- the row that needs it is committed, or written when that row goes.
CREATE TABLE blob_garbage (
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    key             text        NOT NULL,
    due_at          timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, key)
);
CREATE INDEX blob_garbage_by_due ON blob_garbage (due_at);

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
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON mailboxes, emails, email_mailboxes, threads, email_thread_refs TO %I',
                   runtime);
    EXECUTE format('GRANT SELECT, INSERT, DELETE ON mail_changes TO %I', runtime);
    -- A mark made again keeps the earlier due time (ON CONFLICT … DO UPDATE).
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON blob_garbage TO %I', runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
