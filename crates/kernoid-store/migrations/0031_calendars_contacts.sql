-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Calendars and contacts (RFC 0004). They live in the account's mail store (mail_accounts): its row orders changes,
-- its modseq numbers them and its quota counts them.

-- An account whose default calendar and address book exist.
CREATE TABLE groupware_accounts (
    account_id      uuid        PRIMARY KEY REFERENCES mail_accounts (account_id),
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE calendars (
    id              uuid        PRIMARY KEY,
    account_id      uuid        NOT NULL REFERENCES mail_accounts (account_id),
    -- Its name in the account's calendar home (CalDAV), as the client chose it; the id by default.
    resource_name   text        NOT NULL CHECK (length(resource_name) BETWEEN 1 AND 255),
    name            text        NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    description     text,
    color           text,
    sort_order      bigint      NOT NULL DEFAULT 0,
    timezone        text,
    -- VEVENT, VTODO or both.
    components      text[]      NOT NULL DEFAULT '{VEVENT,VTODO}',
    is_default      boolean     NOT NULL DEFAULT false,
    is_subscribed   boolean     NOT NULL DEFAULT true,
    is_visible      boolean     NOT NULL DEFAULT true,
    -- Properties clients set that kernoid does not know (WebDAV dead properties), as JSON.
    dead_properties jsonb       NOT NULL DEFAULT '[]',
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, resource_name)
);
CREATE UNIQUE INDEX calendars_one_default ON calendars (account_id) WHERE is_default;

-- An event (or task) with its exceptions: the iCalendar object sealed with the tenant's key, and what finding needs.
CREATE TABLE calendar_events (
    id              uuid        PRIMARY KEY,
    account_id      uuid        NOT NULL REFERENCES mail_accounts (account_id),
    calendar_id     uuid        NOT NULL REFERENCES calendars (id),
    resource_name   text        NOT NULL CHECK (length(resource_name) BETWEEN 1 AND 255),
    uid             text        NOT NULL,
    component       text        NOT NULL CHECK (component IN ('VEVENT', 'VTODO', 'VJOURNAL')),
    -- From the start of the first instance to the end of the last; unbounded above for endless recurrences.
    span            tstzrange,
    organized       boolean     NOT NULL DEFAULT false,
    data            bytea       NOT NULL,
    size            bigint      NOT NULL CHECK (size >= 0),
    schedule_tag    bigint      NOT NULL DEFAULT 0,
    modseq          bigint      NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (calendar_id, resource_name),
    UNIQUE (calendar_id, uid)
);
CREATE INDEX calendar_events_by_account ON calendar_events (account_id);
CREATE INDEX calendar_events_by_uid ON calendar_events (account_id, uid);
CREATE INDEX calendar_events_by_span ON calendar_events USING gist (span);

-- What scheduling changed in an account's events (JMAP CalendarEventNotification).
CREATE TABLE calendar_notifications (
    id              uuid        PRIMARY KEY,
    account_id      uuid        NOT NULL REFERENCES mail_accounts (account_id),
    event_id        uuid,
    kind            text        NOT NULL CHECK (kind IN ('created', 'updated', 'destroyed')),
    changed_by      jsonb       NOT NULL,
    comment         text,
    data            bytea       NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX calendar_notifications_by_account ON calendar_notifications (account_id, created_at);

CREATE TABLE addressbooks (
    id              uuid        PRIMARY KEY,
    account_id      uuid        NOT NULL REFERENCES mail_accounts (account_id),
    resource_name   text        NOT NULL CHECK (length(resource_name) BETWEEN 1 AND 255),
    name            text        NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    description     text,
    sort_order      bigint      NOT NULL DEFAULT 0,
    is_default      boolean     NOT NULL DEFAULT false,
    is_subscribed   boolean     NOT NULL DEFAULT true,
    dead_properties jsonb       NOT NULL DEFAULT '[]',
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, resource_name)
);
CREATE UNIQUE INDEX addressbooks_one_default ON addressbooks (account_id) WHERE is_default;

CREATE TABLE contacts (
    id              uuid        PRIMARY KEY,
    account_id      uuid        NOT NULL REFERENCES mail_accounts (account_id),
    addressbook_id  uuid        NOT NULL REFERENCES addressbooks (id),
    resource_name   text        NOT NULL CHECK (length(resource_name) BETWEEN 1 AND 255),
    uid             text        NOT NULL,
    kind            text        NOT NULL DEFAULT 'individual',
    -- Lower case, for finding a contact by address.
    emails          text[]      NOT NULL DEFAULT '{}',
    data            bytea       NOT NULL,
    size            bigint      NOT NULL CHECK (size >= 0),
    modseq          bigint      NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (addressbook_id, resource_name),
    UNIQUE (addressbook_id, uid)
);
CREATE INDEX contacts_by_account ON contacts (account_id);
CREATE INDEX contacts_by_email ON contacts USING gin (emails);

-- The journal of calendars and contacts (RFC 0004, 2), with the collection and resource name so that a sync of one
-- collection also finds what left it.
CREATE TABLE groupware_changes (
    account_id      uuid        NOT NULL REFERENCES mail_accounts (account_id),
    modseq          bigint      NOT NULL,
    object_type     text        NOT NULL CHECK (object_type IN ('calendar', 'event', 'notification', 'addressbook', 'contact')),
    object_id       uuid        NOT NULL,
    collection_id   uuid,
    resource_name   text,
    change          text        NOT NULL CHECK (change IN ('created', 'updated', 'destroyed')),
    changed_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, object_type, modseq, object_id)
);
CREATE INDEX groupware_changes_by_collection ON groupware_changes (collection_id, modseq);
CREATE INDEX groupware_changes_by_age ON groupware_changes (changed_at);

-- Who may use whose calendars and address books: a read model of account.collection_access_set and
-- account.collection_access_removed (RFC 0004, 9).
CREATE TABLE collection_access (
    owner_id        uuid        NOT NULL REFERENCES accounts (id),
    collection_type text        NOT NULL CHECK (collection_type IN ('calendar', 'addressbook')),
    collection_id   uuid        NOT NULL,
    grantee_account uuid        REFERENCES accounts (id),
    grantee_group   uuid        REFERENCES groups (id) ON DELETE CASCADE,
    level           text        NOT NULL CHECK (level IN ('freebusy', 'read', 'rsvp', 'write', 'admin')),
    granted_at      timestamptz NOT NULL,
    CHECK ((grantee_account IS NULL) <> (grantee_group IS NULL))
);
CREATE UNIQUE INDEX collection_access_one_grant ON collection_access
    (collection_id, coalesce(grantee_account, grantee_group));
CREATE INDEX collection_access_by_account ON collection_access (grantee_account);
CREATE INDEX collection_access_by_group ON collection_access (grantee_group);
CREATE INDEX collection_access_by_owner ON collection_access (owner_id);

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
                   project_grants, mail_access, collection_access, account_usernames, account_emails,
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
    -- Registrations wait for their code, then become accounts (events); the rest expire.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON registrations TO %I', runtime);
    -- A mark made again keeps the earlier due time (ON CONFLICT … DO UPDATE).
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON blob_garbage TO %I', runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
