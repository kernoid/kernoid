-- SPDX-License-Identifier: AGPL-3.0-or-later
-- OpenID Connect completed (RFC 0001, 7.2): options per application (JWT access tokens, offline access, consent,
-- logout notifications), consents, refresh tokens that outlive the session, notifications of ended sessions, and a
-- login UI of the instance's own.

ALTER TABLE applications ADD COLUMN access_token_format text NOT NULL DEFAULT 'opaque'
    CHECK (access_token_format IN ('opaque', 'jwt'));
ALTER TABLE applications ADD COLUMN offline_access boolean NOT NULL DEFAULT false;
ALTER TABLE applications ADD COLUMN consent_required boolean NOT NULL DEFAULT false;
ALTER TABLE applications ADD COLUMN backchannel_logout_uri text;
ALTER TABLE applications ADD COLUMN frontchannel_logout_uri text;

-- What an account agreed an application may have.
CREATE TABLE consents (
    account_id      uuid        NOT NULL REFERENCES accounts (id),
    application_id  uuid        NOT NULL REFERENCES applications (id),
    scopes          text[]      NOT NULL,
    granted_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, application_id)
);

-- Offline refresh tokens (`offline_access`) outlive the session they came from.
ALTER TABLE refresh_tokens ADD COLUMN offline boolean NOT NULL DEFAULT false;
ALTER TABLE refresh_tokens ALTER COLUMN session_id DROP NOT NULL;
ALTER TABLE refresh_tokens DROP CONSTRAINT refresh_tokens_session_id_fkey;
ALTER TABLE refresh_tokens ADD CONSTRAINT refresh_tokens_session_id_fkey
    FOREIGN KEY (session_id) REFERENCES sessions (id) ON DELETE SET NULL;
-- What the login was, for ID tokens issued after the session is gone.
ALTER TABLE refresh_tokens ADD COLUMN auth_time timestamptz NOT NULL DEFAULT now();
ALTER TABLE refresh_tokens ADD COLUMN checks text[] NOT NULL DEFAULT '{}';

-- Which applications a session logged in to: they are told when it ends (front- and back-channel logout).
CREATE TABLE session_applications (
    session_id      uuid        NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    application_id  uuid        NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    PRIMARY KEY (session_id, application_id)
);

-- Back-channel logout: an ended session is told to every application that got tokens in it.
CREATE TABLE logout_notifications (
    session_id      uuid        NOT NULL,
    application_id  uuid        NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    account_id      uuid        NOT NULL REFERENCES accounts (id),
    instance_id     uuid        NOT NULL REFERENCES instances (id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    attempts        integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    delivered_at    timestamptz,
    last_error      text,
    PRIMARY KEY (session_id, application_id)
);
CREATE INDEX logout_notifications_due ON logout_notifications (next_attempt_at) WHERE delivered_at IS NULL;

-- A login UI of the instance's own, elsewhere than kernoid's /login.
ALTER TABLE instances ADD COLUMN login_ui_url text;

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
                   consents TO %I',
                   runtime);
    -- Credentials are set, replaced and removed.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON account_passwords, application_secrets, signing_keys, account_totp, account_passkeys, account_recovery_codes,
                   identity_provider_secrets TO %I',
                   runtime);
    -- Sessions, requests, challenges, codes and tokens end and expire; expired ones are cleaned up.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON sessions, login_failures, auth_requests, authorization_codes, access_tokens, refresh_tokens, webauthn_challenges,
                   idp_logins,
                   session_applications, logout_notifications TO %I',
                   runtime);
END
$$;

REVOKE ALL ON FUNCTION kernoid_grant_runtime(name) FROM PUBLIC;
