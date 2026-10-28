-- SPDX-License-Identifier: AGPL-3.0-or-later
-- The identity core completed (RFC 0001, 7.1, 7.3, 7.4): known devices, so that failed logins of others cannot lock
-- an account out; a grace period for a tenant's second-factor requirement; a passkey RP ID that stays when the
-- primary domain changes; instance roles of an instance's own.

-- A device that logged in to an account before carries a token (stored as SHA-256) that lets it log in although the
-- login name is throttled (OWASP: device cookies). It belongs to the login name as typed.
CREATE TABLE known_devices (
    token_hash      bytea       PRIMARY KEY CHECK (length(token_hash) = 32),
    instance_id     uuid        NOT NULL REFERENCES instances (id),
    account_id      uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    name_key        text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL
);
CREATE INDEX known_devices_by_account ON known_devices (account_id);
CREATE INDEX known_devices_by_expiry ON known_devices (expires_at);

-- An account without a second factor may log in without one this many days after the requirement (or the account)
-- began.
ALTER TABLE tenants ADD COLUMN mfa_grace_days integer NOT NULL DEFAULT 0 CHECK (mfa_grace_days BETWEEN 0 AND 365);
ALTER TABLE tenants ADD COLUMN mfa_required_since timestamptz;
UPDATE tenants SET mfa_required_since = now() WHERE mfa_required;

-- Passkeys are bound to the RP ID; it no longer follows the primary domain. It starts as the instance's first domain
-- (as a rebuild from the events has it).
ALTER TABLE instances ADD COLUMN passkey_rp_id text;
UPDATE instances i SET passkey_rp_id = e.payload ->> 'domain'
FROM events e
WHERE e.aggregate_type = 'instance' AND e.aggregate_id = i.id::text AND e.event_type = 'instance.added';

-- Instance roles of an instance's own: instance permissions at the instance, tenant permissions in every tenant.
CREATE TABLE instance_roles (
    instance_id     uuid        NOT NULL REFERENCES instances (id),
    name            text        NOT NULL,
    permissions     text[]      NOT NULL,
    PRIMARY KEY (instance_id, name)
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
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON instance_domains, tenant_domains, tenant_modules, addresses, groups, group_members, role_assignments,
                   instance_role_assignments, tenant_roles, projects, project_roles, project_authorizations,
                   project_grants,
                   identity_providers, account_links,
                   scim_tokens,
                   consents, instance_roles TO %I',
                   runtime);
    -- Credentials are set, replaced and removed.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON account_passwords, application_secrets, signing_keys, account_totp, account_passkeys, account_recovery_codes,
                   identity_provider_secrets TO %I',
                   runtime);
    -- Sessions, requests, challenges, codes and tokens end and expire; expired ones are cleaned up.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON sessions, login_failures, auth_requests, authorization_codes, access_tokens, refresh_tokens, webauthn_challenges,
                   idp_logins,
                   session_applications, logout_notifications, known_devices TO %I',
                   runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
