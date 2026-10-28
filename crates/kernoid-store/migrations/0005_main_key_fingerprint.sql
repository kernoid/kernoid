-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Which main key wrapped a tenant key: 8 bytes derived from the main key (see kernoid-store, crypto::fingerprint),
-- not the key itself. Lets `kernoid keys rewrap` find what is still wrapped with a previous main key. Empty for keys
-- written before this column existed – they are recognised by trying the configured main keys.

ALTER TABLE tenant_keys
    ADD COLUMN main_key bytea CHECK (main_key IS NULL OR length(main_key) = 8);
