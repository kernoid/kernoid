-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Sending later (RFC 8621, 7: an EmailSubmission held with HOLDFOR): a submission is `pending` until its `send_at`,
-- may be `canceled` until then, and is `final` once sent. The message waits in object storage
-- (`submissions/<id>`), sealed like all content. The account chooses how long the web app holds what it sends –
-- to take it back –, 0 sending at once.
ALTER TABLE email_submissions
    ADD COLUMN undo_status text NOT NULL DEFAULT 'final' CHECK (undo_status IN ('pending', 'final', 'canceled'));
CREATE INDEX email_submissions_pending ON email_submissions (send_at) WHERE undo_status = 'pending';
ALTER TABLE mail_accounts ADD COLUMN undo_send_seconds integer NOT NULL DEFAULT 0 CHECK (undo_send_seconds BETWEEN 0 AND 30);
