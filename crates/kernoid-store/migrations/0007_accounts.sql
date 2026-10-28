-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Accounts (see kernoid-identity, account). An address – primary or alias – belongs to exactly one account in the
-- whole installation: it is a login name and a mail destination at once. Password hashes are credentials, not
-- events: they live in their own table, so that they can be replaced and removed; the events only say that a
-- password was set.

CREATE TABLE accounts (
    id              uuid        PRIMARY KEY,
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    display_name    text        NOT NULL,
    primary_address text        NOT NULL,
    active          boolean     NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX accounts_by_tenant ON accounts (tenant_id);

CREATE TABLE addresses (
    address     text        PRIMARY KEY,
    tenant_id   uuid        NOT NULL REFERENCES tenants (id),
    account_id  uuid        NOT NULL REFERENCES accounts (id),
    is_primary  boolean     NOT NULL DEFAULT false,
    -- The domain part, for checking whether a domain is still in use.
    domain      text        NOT NULL
);
CREATE INDEX addresses_by_account ON addresses (account_id);
CREATE INDEX addresses_by_domain ON addresses (domain);
CREATE UNIQUE INDEX addresses_one_primary ON addresses (account_id) WHERE is_primary;

CREATE TABLE account_passwords (
    account_id  uuid        PRIMARY KEY REFERENCES accounts (id),
    -- PHC string: algorithm, parameters, salt, hash.
    hash        text        NOT NULL,
    changed_at  timestamptz NOT NULL DEFAULT now()
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
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
