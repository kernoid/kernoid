-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Tenant keys for content in object storage (see kernoid-store, crypto), wrapped by the main key. Kept apart from the
-- events on purpose: removing a tenant's keys makes its content unreadable, which an append-only log could not do.

CREATE TABLE tenant_keys (
    tenant_id   uuid        NOT NULL,
    number      integer     NOT NULL CHECK (number > 0),
    -- Nonce, then the key encrypted and authenticated with the main key, bound to tenant_id and number.
    wrapped     bytea       NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, number)
);

CREATE OR REPLACE FUNCTION kernoid_grant_runtime(runtime name) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    -- Events are read and added, never changed or removed.
    EXECUTE format('GRANT SELECT, INSERT ON events TO %I', runtime);
    -- Cursors are created and moved; a projection is rebuilt by the owner, not by kernoid itself.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON projection_cursors TO %I', runtime);
    -- Tenant keys are created and read; removing them (destroying a tenant's content) is left to the owner.
    EXECUTE format('GRANT SELECT, INSERT ON tenant_keys TO %I', runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
