-- SPDX-License-Identifier: AGPL-3.0-or-later
-- A server as one more node of spaces of streams (RFC 0010, 8; RFC 0012; crate kernoid-node): what a device keeps in
-- SQLite (kernoid-spaces' store), a server keeps here. `node` names the node, so that one database holds several – a
-- program's organisations, say. What only the node may read – the state of a space with the node's seed, the keys of
-- streams and the events read from them – is sealed under the node's key, bound to its node, space, stream and kind;
-- the roster and the records are as public as at the relay.
CREATE TABLE node_spaces (
    node        text    NOT NULL CHECK (length(node) BETWEEN 1 AND 128),
    space       text    NOT NULL CHECK (length(space) BETWEEN 1 AND 64),
    state       bytea   NOT NULL,
    PRIMARY KEY (node, space)
);

CREATE TABLE node_roster (
    node        text    NOT NULL,
    space       text    NOT NULL,
    seq         bigint  NOT NULL CHECK (seq >= 0),
    canonical   bytea   NOT NULL,
    PRIMARY KEY (node, space, seq)
);

CREATE TABLE node_streams (
    node        text    NOT NULL,
    space       text    NOT NULL,
    stream      text    NOT NULL,
    position    bigint  NOT NULL DEFAULT 0,
    due         boolean NOT NULL DEFAULT false,
    inbox       boolean NOT NULL DEFAULT false,
    PRIMARY KEY (node, space, stream)
);

CREATE TABLE node_stream_keys (
    node        text    NOT NULL,
    space       text    NOT NULL,
    stream      text    NOT NULL,
    generation  bigint  NOT NULL CHECK (generation BETWEEN 0 AND 4294967295),
    key         bytea   NOT NULL,
    PRIMARY KEY (node, space, stream, generation)
);

CREATE TABLE node_stream_parents (
    node        text    NOT NULL,
    space       text    NOT NULL,
    stream      text    NOT NULL,
    kind        text    NOT NULL CHECK (kind IN ('stream', 'person')),
    parent      text    NOT NULL,
    PRIMARY KEY (node, space, stream, kind, parent)
);
CREATE INDEX node_stream_children ON node_stream_parents (node, space, kind, parent);

CREATE TABLE node_stream_records (
    node        text    NOT NULL,
    space       text    NOT NULL,
    stream      text    NOT NULL,
    position    bigint  NOT NULL,
    canonical   bytea   NOT NULL,
    PRIMARY KEY (node, space, stream, position)
);

CREATE TABLE node_stream_events (
    node        text    NOT NULL,
    space       text    NOT NULL,
    stream      text    NOT NULL,
    hash        text    NOT NULL,
    canonical   bytea   NOT NULL,
    PRIMARY KEY (node, space, stream, hash)
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
    -- Encrypted collections: their wrapped keys and their entries come and go as their members' apps write them.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON collection_keys, sealed_items TO %I', runtime);
    -- A mark made again keeps the earlier due time (ON CONFLICT … DO UPDATE).
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON blob_garbage TO %I', runtime);
    -- Objects kept in PostgreSQL instead of object storage (`[blob] kind = "database"`): stored, replaced, removed.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON blob_objects TO %I', runtime);
    -- The relay (RFC 0010, 4): spaces are founded and removed; member records and envelopes are added, never changed;
    -- requests to join come and go. Removing a space removes what it holds.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON relay_spaces, relay_requests TO %I', runtime);
    EXECUTE format('GRANT SELECT, INSERT, DELETE ON relay_records, relay_envelopes TO %I', runtime);
    -- Streams (RFC 0012): the roster, streams, their tokens, records and originals are added and removed with their
    -- stream or space, never changed.
    EXECUTE format('GRANT SELECT, INSERT, DELETE ON relay_roster, relay_streams, relay_stream_tokens, relay_stream_records,
                   relay_stream_originals TO %I', runtime);
    -- Spaces of destroyed vaults wait for the worker.
    EXECUTE format('GRANT SELECT, INSERT, DELETE ON relay_space_removals TO %I', runtime);
    -- A server as a node of spaces (kernoid-node): its state, streams and positions change; the rest is added and
    -- removed with its stream or space.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON node_spaces, node_streams TO %I', runtime);
    EXECUTE format('GRANT SELECT, INSERT, DELETE ON node_roster, node_stream_keys, node_stream_parents, node_stream_records,
                   node_stream_events TO %I', runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;

