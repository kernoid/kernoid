-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Access protocols (RFC 0002, 11): JMAP uploads and submissions, and the UIDs that left a mailbox (IMAP QRESYNC).

-- A blob uploaded through JMAP, in object storage under upload/<account>/<id>; kept a day.
CREATE TABLE jmap_uploads (
    id              uuid        PRIMARY KEY,
    account_id      uuid        NOT NULL REFERENCES mail_accounts (account_id),
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    content_type    text        NOT NULL,
    size            bigint      NOT NULL,
    expires_at      timestamptz NOT NULL
);
CREATE INDEX jmap_uploads_by_expiry ON jmap_uploads (expires_at);

-- JMAP EmailSubmission objects: what was sent, through which identity, and its message in the queue.
CREATE TABLE email_submissions (
    id              uuid        PRIMARY KEY,
    account_id      uuid        NOT NULL REFERENCES mail_accounts (account_id),
    email_id        uuid        NOT NULL,
    identity_id     text        NOT NULL,
    envelope_from   text        NOT NULL,
    recipients      text[]      NOT NULL,
    send_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX email_submissions_by_account ON email_submissions (account_id, send_at);

-- UIDs that left a mailbox, for VANISHED (RFC 7162); pruned like the journal.
CREATE TABLE mailbox_expunged (
    mailbox_id      uuid        NOT NULL REFERENCES mailboxes (id) ON DELETE CASCADE,
    uid             bigint      NOT NULL,
    modseq          bigint      NOT NULL,
    expunged_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (mailbox_id, uid)
);
CREATE INDEX mailbox_expunged_by_modseq ON mailbox_expunged (mailbox_id, modseq);

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
    -- What the protocols keep: uploads and submissions come and go; expunged UIDs are pruned with the journal.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON jmap_uploads, email_submissions TO %I', runtime);
    EXECUTE format('GRANT SELECT, INSERT, DELETE ON mailbox_expunged TO %I', runtime);
    -- A mark made again keeps the earlier due time (ON CONFLICT … DO UPDATE).
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON blob_garbage TO %I', runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
