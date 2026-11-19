-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kernoid's tables may live in a schema of their own (`database.schema`, RFC 0009, 4): a program that builds kernoid in
-- keeps its own tables apart in the same database. The runtime role needs to use that schema; `kernoid migrate` grants
-- it, as it grants the tables (kernoid_grant_runtime). For the public schema it changes nothing.
CREATE OR REPLACE FUNCTION kernoid_grant_schema(runtime name) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', current_schema(), runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_schema(name) FROM PUBLIC;
