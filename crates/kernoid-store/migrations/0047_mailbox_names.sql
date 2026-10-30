-- SPDX-License-Identifier: AGPL-3.0-or-later
-- The names an account gives the mail stores it reaches – its own and shared mailboxes – shown instead of their
-- addresses: `{ "<account id>": "<name>" }`. Each account names them for itself.
ALTER TABLE mail_accounts ADD COLUMN mailbox_names jsonb NOT NULL DEFAULT '{}';
