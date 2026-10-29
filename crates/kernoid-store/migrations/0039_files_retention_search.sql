-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Files (RFC 0005, 4 and 8): how long what is in a trash stays, per tenant (`tenant.files_retention_set`); and the
-- text of textual contents for searching inside files (`body`), indexed by the worker as mail is (RFC 0002, 13.1).
ALTER TABLE tenants ADD COLUMN files_trash_retention_days integer CHECK (files_trash_retention_days BETWEEN 1 AND 3650);
-- NULL: not looked at yet; an empty vector: nothing to search (not text, too large, unreadable).
ALTER TABLE file_contents ADD COLUMN body_search tsvector;
CREATE INDEX file_contents_body_search ON file_contents USING gin (body_search);
CREATE INDEX file_contents_unindexed ON file_contents (id) WHERE body_search IS NULL;
