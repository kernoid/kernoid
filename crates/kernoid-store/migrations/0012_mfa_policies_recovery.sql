-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Requiring a second factor per tenant and per application, and recovery codes for when the devices are gone (see
-- kernoid-identity, mfa; kernoid-oidc, flow). Recovery codes are kept only as SHA-256, bound to their account.

ALTER TABLE tenants ADD COLUMN mfa_required boolean NOT NULL DEFAULT false;
ALTER TABLE applications ADD COLUMN mfa_required boolean NOT NULL DEFAULT false;

CREATE TABLE account_recovery_codes (
    code_hash       bytea       PRIMARY KEY CHECK (length(code_hash) = 32),
    account_id      uuid        NOT NULL REFERENCES accounts (id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    used_at         timestamptz
);
CREATE INDEX account_recovery_codes_by_account ON account_recovery_codes (account_id);

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
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON account_passwords, application_secrets, signing_keys, account_totp, account_passkeys, account_recovery_codes TO %I',
                   runtime);
    -- Sessions, requests, challenges, codes and tokens end and expire; expired ones are cleaned up.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON sessions, login_failures, auth_requests, authorization_codes, access_tokens, refresh_tokens, webauthn_challenges TO %I',
                   runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
