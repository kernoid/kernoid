#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Runs once, when PostgreSQL creates its data directory. Creates the owner of kernoid's schema (runs `kernoid migrate`)
# and the runtime role (serves; `kernoid migrate` grants it its rights). The superuser is for administration only.
# Passwords are passed as psql variables and quoted by psql (:'name').
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
    -v owner_password="$KERNOID_OWNER_PASSWORD" -v app_password="$KERNOID_APP_PASSWORD" <<'SQL'
CREATE ROLE kernoid_owner LOGIN PASSWORD :'owner_password';
CREATE ROLE kernoid_app LOGIN PASSWORD :'app_password';
CREATE DATABASE kernoid OWNER kernoid_owner;
REVOKE ALL ON DATABASE kernoid FROM PUBLIC;
GRANT CONNECT ON DATABASE kernoid TO kernoid_app;
SQL
