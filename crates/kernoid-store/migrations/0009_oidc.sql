-- SPDX-License-Identifier: AGPL-3.0-or-later
-- OpenID Connect (see kernoid-oidc). Applications are aggregates with an inline read model; everything secret –
-- client secrets, signing keys, authorization codes, access tokens – lives only here, as hashes or encrypted, never
-- in events. Auth requests and codes are short-lived; the worker removes them when they expire.

CREATE TABLE applications (
    id              uuid        PRIMARY KEY,
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    name            text        NOT NULL,
    -- `confidential` (has a secret) or `public` (browser and mobile apps; PKCE only).
    kind            text        NOT NULL CHECK (kind IN ('confidential', 'public')),
    -- Exact matches only, no patterns.
    redirect_uris   text[]      NOT NULL,
    active          boolean     NOT NULL DEFAULT true
);
CREATE INDEX applications_by_tenant ON applications (tenant_id);

CREATE TABLE application_secrets (
    application_id  uuid        PRIMARY KEY REFERENCES applications (id),
    -- SHA-256 of a 256-bit random secret.
    secret_hash     bytea       NOT NULL CHECK (length(secret_hash) = 32),
    changed_at      timestamptz NOT NULL DEFAULT now()
);

-- Keys an instance signs ID tokens with. initial: published, not yet signing; active: signs (one per instance);
-- inactive: published until the tokens it signed have expired; removed keys are deleted.
CREATE TABLE signing_keys (
    kid             text        PRIMARY KEY,
    instance_id     uuid        NOT NULL REFERENCES instances (id),
    algorithm       text        NOT NULL,
    state           text        NOT NULL CHECK (state IN ('initial', 'active', 'inactive')),
    -- The public key as a JWK.
    public_jwk      jsonb       NOT NULL,
    -- The private key (PKCS#8), sealed with the main key and bound to instance and kid.
    private_sealed  bytea       NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    state_since     timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX signing_keys_one_active ON signing_keys (instance_id) WHERE state = 'active';

-- An authorization request waiting for a login UI to finish it with a session.
CREATE TABLE auth_requests (
    id              text        PRIMARY KEY,
    instance_id     uuid        NOT NULL REFERENCES instances (id),
    application_id  uuid        NOT NULL REFERENCES applications (id),
    redirect_uri    text        NOT NULL,
    scopes          text[]      NOT NULL,
    state           text,
    nonce           text,
    code_challenge  text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    -- Set when a session finished it; it is then used up.
    session_id      uuid
);

CREATE TABLE authorization_codes (
    code_hash       bytea       PRIMARY KEY CHECK (length(code_hash) = 32),
    auth_request_id text        NOT NULL REFERENCES auth_requests (id) ON DELETE CASCADE,
    session_id      uuid        NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    account_id      uuid        NOT NULL REFERENCES accounts (id),
    expires_at      timestamptz NOT NULL,
    used_at         timestamptz
);

CREATE TABLE access_tokens (
    token_hash      bytea       PRIMARY KEY CHECK (length(token_hash) = 32),
    instance_id     uuid        NOT NULL REFERENCES instances (id),
    application_id  uuid        NOT NULL REFERENCES applications (id),
    account_id      uuid        NOT NULL REFERENCES accounts (id),
    session_id      uuid        REFERENCES sessions (id) ON DELETE CASCADE,
    -- The request the token came from: if its code is presented a second time, its tokens are revoked.
    auth_request_id text        REFERENCES auth_requests (id) ON DELETE CASCADE,
    scopes          text[]      NOT NULL,
    expires_at      timestamptz NOT NULL
);
CREATE INDEX access_tokens_by_expiry ON access_tokens (expires_at);

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
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON sessions, login_failures, auth_requests, authorization_codes, access_tokens TO %I',
                   runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
