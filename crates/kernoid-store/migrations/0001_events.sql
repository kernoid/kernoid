-- SPDX-License-Identifier: AGPL-3.0-or-later
-- The event store: identity and administration are stored as events (see kernoid-events). Rows are only ever added.

CREATE TABLE events (
    -- Order of insertion; readers order by (transaction_id, position), see kernoid-events.
    position        bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- Transaction that wrote the event; lets readers skip events of transactions that may not have committed yet.
    transaction_id  xid8        NOT NULL DEFAULT pg_current_xact_id(),
    -- The instance the event belongs to: every query filters by it.
    instance_id     uuid        NOT NULL,
    -- Who owns the aggregate: a tenant, or the instance itself for instance-wide aggregates. Never changes.
    owner           uuid        NOT NULL,
    aggregate_type  text        NOT NULL,
    aggregate_id    text        NOT NULL,
    -- Position of the event within its aggregate, starting at 1, without gaps.
    sequence        bigint      NOT NULL CHECK (sequence > 0),
    event_type      text        NOT NULL,
    -- Version of the payload schema of this event type.
    revision        smallint    NOT NULL CHECK (revision > 0),
    payload         jsonb       NOT NULL,
    -- Who caused the event: an account, a service account or the system.
    creator         text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (instance_id, aggregate_type, aggregate_id, sequence)
);

CREATE INDEX events_by_transaction ON events (transaction_id, position);
CREATE INDEX events_by_owner ON events (instance_id, owner, position);

CREATE FUNCTION events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'events are append-only';
END
$$;

CREATE TRIGGER events_no_update_or_delete BEFORE UPDATE OR DELETE ON events
    FOR EACH ROW EXECUTE FUNCTION events_append_only();
CREATE TRIGGER events_no_truncate BEFORE TRUNCATE ON events
    FOR EACH STATEMENT EXECUTE FUNCTION events_append_only();
