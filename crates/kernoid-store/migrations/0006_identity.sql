-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Read models of instances and tenants (see kernoid-identity). They are written inline, in the transaction that
-- appends the events, so that a lookup right after a change sees it – and so that PostgreSQL enforces uniqueness:
-- a login domain names one instance, a verified mail domain one tenant in the whole installation (incoming mail must
-- find exactly one recipient). They can be rebuilt from the events at any time.

CREATE TABLE instances (
    id          uuid        PRIMARY KEY,
    name        text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Hosts under which an instance is reached (login, API, web app).
CREATE TABLE instance_domains (
    domain      text        PRIMARY KEY,
    instance_id uuid        NOT NULL REFERENCES instances (id),
    is_primary  boolean     NOT NULL DEFAULT false
);
CREATE UNIQUE INDEX instance_domains_one_primary ON instance_domains (instance_id) WHERE is_primary;

CREATE TABLE tenants (
    id          uuid        PRIMARY KEY,
    instance_id uuid        NOT NULL REFERENCES instances (id),
    name        text        NOT NULL,
    active      boolean     NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tenants_by_instance ON tenants (instance_id);

-- Mail domains of tenants. Any tenant may claim a domain; only one can have it verified.
CREATE TABLE tenant_domains (
    tenant_id   uuid        NOT NULL REFERENCES tenants (id),
    domain      text        NOT NULL,
    -- Published by the tenant in DNS to prove the domain is theirs.
    token       text        NOT NULL,
    verified    boolean     NOT NULL DEFAULT false,
    PRIMARY KEY (tenant_id, domain)
);
CREATE UNIQUE INDEX tenant_domains_verified_once ON tenant_domains (domain) WHERE verified;

CREATE TABLE tenant_modules (
    tenant_id   uuid        NOT NULL REFERENCES tenants (id),
    module      text        NOT NULL,
    PRIMARY KEY (tenant_id, module)
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
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON instances, tenants TO %I', runtime);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON instance_domains, tenant_domains, tenant_modules TO %I',
                   runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
