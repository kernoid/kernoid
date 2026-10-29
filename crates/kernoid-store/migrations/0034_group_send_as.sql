-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Sending as a group (RFC 0002, 9.2): whether the members of a group may send from its addresses
-- (group.send_as_set). The runtime role may change groups already.
ALTER TABLE groups ADD COLUMN members_send_as boolean NOT NULL DEFAULT false;
