-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Refresh tokens with rotation, prompt and max_age of auth requests, and the redirect URIs an application may be sent
-- back to after logout (see kernoid-oidc).

ALTER TABLE applications ADD COLUMN post_logout_redirect_uris text[] NOT NULL DEFAULT '{}';

-- What the login UI must respect (OpenID Connect Core, 3.1.2.1).
ALTER TABLE auth_requests ADD COLUMN prompt text[] NOT NULL DEFAULT '{}';
ALTER TABLE auth_requests ADD COLUMN max_age integer CHECK (max_age >= 0);

-- A refresh token is used once: refreshing hands out the next one. All tokens from one login form a family (its auth
-- request); a token presented after it was used means it was copied, and the whole family is revoked.
CREATE TABLE refresh_tokens (
    token_hash      bytea       PRIMARY KEY CHECK (length(token_hash) = 32),
    family          text        NOT NULL REFERENCES auth_requests (id) ON DELETE CASCADE,
    instance_id     uuid        NOT NULL REFERENCES instances (id),
    application_id  uuid        NOT NULL REFERENCES applications (id),
    account_id      uuid        NOT NULL REFERENCES accounts (id),
    session_id      uuid        NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    scopes          text[]      NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- Never later than the session's end.
    expires_at      timestamptz NOT NULL,
    used_at         timestamptz
);
CREATE INDEX refresh_tokens_by_family ON refresh_tokens (family);
CREATE INDEX refresh_tokens_by_expiry ON refresh_tokens (expires_at);

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
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON instance_domains, tenant_domains, tenant_modules, addresses TO %I',
                   runtime);
    -- Credentials are set, replaced and removed.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON account_passwords, application_secrets, signing_keys TO %I',
                   runtime);
    -- Sessions, requests, codes and tokens end and expire; expired ones are cleaned up.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON sessions, login_failures, auth_requests, authorization_codes, access_tokens, refresh_tokens TO %I',
                   runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
