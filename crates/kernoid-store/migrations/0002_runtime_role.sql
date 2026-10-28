-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kernoid runs with a role that does not own the schema. `kernoid migrate` (as the owner) calls this function for the
-- runtime role after every migration, so the role has exactly what it needs and nothing more. A migration that adds
-- a table replaces this function with the complete list of grants.

CREATE FUNCTION kernoid_grant_runtime(runtime name) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    -- Events are read and added, never changed or removed.
    EXECUTE format('GRANT SELECT, INSERT ON events TO %I', runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
