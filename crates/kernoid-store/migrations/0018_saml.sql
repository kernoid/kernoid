-- SPDX-License-Identifier: AGPL-3.0-or-later
-- SAML 2.0 identity providers (RFC 0001, 7.7): where to send the AuthnRequest, which certificates sign, which
-- attributes carry address and name; and the ID of the AuthnRequest a login waits an answer for.

ALTER TABLE identity_providers DROP CONSTRAINT identity_providers_kind_check;
ALTER TABLE identity_providers ADD CONSTRAINT identity_providers_kind_check CHECK (kind IN ('oidc', 'saml'));
ALTER TABLE identity_providers ADD COLUMN saml_sso_url text;
-- Base64 DER of the provider's signing certificates.
ALTER TABLE identity_providers ADD COLUMN saml_certificates text[] NOT NULL DEFAULT '{}';
ALTER TABLE identity_providers ADD COLUMN saml_email_attribute text;
ALTER TABLE identity_providers ADD COLUMN saml_name_attribute text;

ALTER TABLE idp_logins ADD COLUMN saml_request_id text;
