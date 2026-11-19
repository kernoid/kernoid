-- SPDX-License-Identifier: AGPL-3.0-or-later
-- The sessions of a program that logs in with kernoid-auth (RFC 0009, 2), in the program's database. A session is found
-- by the hash of its id – the id itself is only in the browser's cookie.
CREATE TABLE kernoid_auth_sessions (
    id_hash          bytea       PRIMARY KEY CHECK (length(id_hash) = 32),
    principal        jsonb       NOT NULL,
    id_token         text        NOT NULL,
    -- From the principal, to end the sessions a back-channel logout names.
    subject          text        NOT NULL,
    provider_session text,
    expires_at       timestamptz NOT NULL
);
CREATE INDEX kernoid_auth_sessions_by_subject ON kernoid_auth_sessions (subject);
CREATE INDEX kernoid_auth_sessions_by_provider_session ON kernoid_auth_sessions (provider_session);
