-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kernoid's SAML key changes (RFC 0001, 7.7): an instance has several keys. A key is `next` (in the metadata – for
-- providers to take in, and to decrypt with – but not signing), `active` (signs; one per instance) or `retired`
-- (no longer in the metadata; still decrypts what a provider encrypted for it). The keys made so far are active.
ALTER TABLE saml_sp_keys DROP CONSTRAINT saml_sp_keys_pkey;
ALTER TABLE saml_sp_keys ADD COLUMN id uuid;
UPDATE saml_sp_keys SET id = uuidv7();
ALTER TABLE saml_sp_keys ALTER COLUMN id SET NOT NULL;
ALTER TABLE saml_sp_keys ADD PRIMARY KEY (id);
ALTER TABLE saml_sp_keys ADD COLUMN state text NOT NULL DEFAULT 'active' CHECK (state IN ('next', 'active', 'retired'));
ALTER TABLE saml_sp_keys ALTER COLUMN state DROP DEFAULT;
ALTER TABLE saml_sp_keys ADD COLUMN state_since timestamptz NOT NULL DEFAULT now();
CREATE INDEX saml_sp_keys_by_instance ON saml_sp_keys (instance_id);
CREATE UNIQUE INDEX saml_sp_keys_one_active ON saml_sp_keys (instance_id) WHERE state = 'active';
CREATE UNIQUE INDEX saml_sp_keys_one_next ON saml_sp_keys (instance_id) WHERE state = 'next';

-- Where the browser goes once the provider answers kernoid's LogoutRequest – an application's
-- post_logout_redirect_uri when the logout came through OpenID Connect; else the login UI.
ALTER TABLE saml_logouts ADD COLUMN return_to text;
