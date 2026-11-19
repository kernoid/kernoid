-- SPDX-License-Identifier: AGPL-3.0-or-later
-- What a tenant's end-to-end encrypted spaces on the relay may take together (RFC 0010, 4), from the event
-- `tenant.relay_quota_set`; null for no limit.
ALTER TABLE tenants ADD COLUMN relay_quota bigint CHECK (relay_quota >= 0);
