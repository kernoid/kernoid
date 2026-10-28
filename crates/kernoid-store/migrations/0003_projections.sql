-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Where each projection stands in the stream of all events (see kernoid-events, projection). The cursor moves in the
-- same transaction as the projection's own tables, so every event takes effect exactly once.

CREATE TABLE projection_cursors (
    name            text        PRIMARY KEY,
    transaction_id  bigint      NOT NULL DEFAULT 0,
    position        bigint      NOT NULL DEFAULT 0,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION kernoid_grant_runtime(runtime name) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    -- Events are read and added, never changed or removed.
    EXECUTE format('GRANT SELECT, INSERT ON events TO %I', runtime);
    -- Cursors are created and moved; a projection is rebuilt by the owner, not by kernoid itself.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON projection_cursors TO %I', runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
