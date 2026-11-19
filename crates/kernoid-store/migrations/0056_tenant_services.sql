-- SPDX-License-Identifier: AGPL-3.0-or-later
-- The services of the installation a tenant does not get (RFC 0008, 4), from the event `tenant.service_switched`.
ALTER TABLE tenants ADD COLUMN services_off text[] NOT NULL DEFAULT '{}';
