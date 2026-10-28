-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Sessions (see kernoid-identity, session). A session exists only after a successful check, so requests without
-- credentials never write events. Its token is a credential: only its SHA-256 is kept, here and never in an event.
-- Failed attempts are counted here, not as events, so that nobody can fill the event log from outside.

CREATE TABLE sessions (
    id              uuid        PRIMARY KEY,
    instance_id     uuid        NOT NULL REFERENCES instances (id),
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    account_id      uuid        NOT NULL REFERENCES accounts (id),
    token_hash      bytea       NOT NULL CHECK (length(token_hash) = 32),
    -- Which checks the session passed, e.g. {password}.
    checks          text[]      NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    terminated_at   timestamptz,
    client_address  inet,
    user_agent      text
);
CREATE INDEX sessions_by_account ON sessions (account_id);
CREATE INDEX sessions_by_expiry ON sessions (expires_at);

-- Failed login attempts per login name and per client address, in a sliding window.
CREATE TABLE login_failures (
    instance_id     uuid        NOT NULL,
    -- `name:<login name as typed, normalised>` or `address:<client address>`.
    key             text        NOT NULL,
    failures        integer     NOT NULL,
    window_start    timestamptz NOT NULL,
    PRIMARY KEY (instance_id, key)
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
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON instances, tenants, accounts TO %I', runtime);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON instance_domains, tenant_domains, tenant_modules, addresses TO %I',
                   runtime);
    -- Password hashes are set, rehashed on login when the parameters change, and removed.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON account_passwords TO %I', runtime);
    -- Sessions end and expire; expired ones and old failure counts are cleaned up.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON sessions, login_failures TO %I', runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
