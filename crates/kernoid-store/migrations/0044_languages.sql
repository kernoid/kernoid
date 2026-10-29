-- SPDX-License-Identifier: AGPL-3.0-or-later
-- The language of the emails kernoid writes itself – invitations, notices – for an account and as a tenant's default
-- (`account.language_set`, `tenant.language_set`); none for the tenant's, or English. Read models: the runtime role
-- may already update both tables.
ALTER TABLE accounts ADD COLUMN language text;
ALTER TABLE tenants ADD COLUMN language text;
