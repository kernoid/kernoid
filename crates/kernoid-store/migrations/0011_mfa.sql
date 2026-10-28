-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Further checks of a session: TOTP (RFC 6238) and passkeys (WebAuthn). Credentials, not events: the TOTP secret is
-- sealed with the main key; a passkey's public key and counter are kept as webauthn-rs stores them. Challenges of
-- WebAuthn ceremonies stay server-side here, for five minutes.

CREATE TABLE account_totp (
    account_id      uuid        PRIMARY KEY REFERENCES accounts (id),
    secret_sealed   bytea       NOT NULL,
    -- Set when the first code was confirmed; until then the secret is only proposed.
    confirmed_at    timestamptz,
    -- The last time step accepted: every code works once.
    last_step       bigint
);

CREATE TABLE account_passkeys (
    id              uuid        PRIMARY KEY,
    account_id      uuid        NOT NULL REFERENCES accounts (id),
    name            text        NOT NULL,
    credential_id   bytea       NOT NULL UNIQUE,
    -- webauthn-rs' Passkey: public key, counter, backup state.
    credential      jsonb       NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz
);
CREATE INDEX account_passkeys_by_account ON account_passkeys (account_id);

CREATE TABLE webauthn_challenges (
    id              text        PRIMARY KEY,
    instance_id     uuid        NOT NULL REFERENCES instances (id),
    -- registration, authentication (a further check of a session) or login (no session yet).
    purpose         text        NOT NULL CHECK (purpose IN ('registration', 'authentication', 'login')),
    account_id      uuid        REFERENCES accounts (id) ON DELETE CASCADE,
    session_id      uuid        REFERENCES sessions (id) ON DELETE CASCADE,
    state           jsonb       NOT NULL,
    expires_at      timestamptz NOT NULL
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
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON instances, tenants, accounts, applications TO %I', runtime);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON instance_domains, tenant_domains, tenant_modules, addresses TO %I',
                   runtime);
    -- Credentials are set, replaced and removed.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON account_passwords, application_secrets, signing_keys, account_totp, account_passkeys TO %I',
                   runtime);
    -- Sessions, requests, challenges, codes and tokens end and expire; expired ones are cleaned up.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON sessions, login_failures, auth_requests, authorization_codes, access_tokens, refresh_tokens, webauthn_challenges TO %I',
                   runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
