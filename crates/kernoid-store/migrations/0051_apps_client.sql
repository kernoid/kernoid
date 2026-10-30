-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kernoid's own apps sign in with OpenID Connect (RFC 0001, 7.2): one public client per instance, built in – of no
-- tenant, usable by every account of the instance, without an administrator registering it. Applications name their
-- instance now; only the built-in client has no tenant. It is not an aggregate: nothing about it is set by anyone,
-- it exists with its instance.
ALTER TABLE applications ADD COLUMN instance_id uuid REFERENCES instances (id);
UPDATE applications a SET instance_id = t.instance_id FROM tenants t WHERE t.id = a.tenant_id;
ALTER TABLE applications ALTER COLUMN instance_id SET NOT NULL;
ALTER TABLE applications ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE applications ADD COLUMN builtin boolean NOT NULL DEFAULT false;
ALTER TABLE applications ADD CONSTRAINT applications_builtin_has_no_tenant CHECK (builtin = (tenant_id IS NULL));
CREATE UNIQUE INDEX applications_builtin_per_instance ON applications (instance_id) WHERE builtin;

INSERT INTO applications (id, tenant_id, instance_id, name, kind, redirect_uris, offline_access, builtin)
SELECT uuidv7(), NULL, id, 'kernoid', 'public',
       ARRAY['dev.kernoid.kernoid:/oauth', 'http://127.0.0.1/oauth', 'http://[::1]/oauth'], true, true
FROM instances;
