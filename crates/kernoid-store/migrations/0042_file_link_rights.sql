-- SPDX-License-Identifier: AGPL-3.0-or-later
-- What a link lets people do (RFC 0005, 11.3): read what it names, add files to the directory it names, or both. A
-- link that only adds is a drop box: people put files in without seeing what is there. Links made before could read.
ALTER TABLE file_links
    ADD COLUMN may_read boolean NOT NULL DEFAULT true,
    ADD COLUMN may_add  boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT file_links_do_something CHECK (may_read OR may_add);
