// SPDX-License-Identifier: MIT
//! What a device keeps of spaces of streams (RFC 0012): the roster, the streams it can open with their keys, how far it
//! has read each, which are due for a new generation, where each was linked from, the records received and the events
//! in them. In the same database as the rest of the store (schema version 2).
//!
//! OPEN: the keys of streams are kept here beside the data, as the seeds of 0.4 are; the key store of the operating
//! system is not used yet.

use std::collections::BTreeMap;

use kernoid_base::{SpaceId, from_root, to_root};
use kernoid_crypt::{
    Domain,
    stream::{PersonId, Roster, RosterRecord, StreamId, StreamKey},
};
use kernoid_log::Log;
use rusqlite::{OptionalExtension, params};

use crate::{Store, StoreError};

pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS roster (
    space TEXT NOT NULL,
    seq INTEGER NOT NULL,
    canonical BLOB NOT NULL,
    PRIMARY KEY (space, seq)
) STRICT;
CREATE TABLE IF NOT EXISTS streams (
    space TEXT NOT NULL,
    stream TEXT NOT NULL,
    position INTEGER NOT NULL DEFAULT 0, -- the relay's position read up to
    due INTEGER NOT NULL DEFAULT 0,      -- 1: a new generation before the next write
    inbox INTEGER NOT NULL DEFAULT 0,    -- a person's stream
    PRIMARY KEY (space, stream)
) STRICT;
CREATE TABLE IF NOT EXISTS stream_keys (
    space TEXT NOT NULL,
    stream TEXT NOT NULL,
    generation INTEGER NOT NULL,
    key BLOB NOT NULL,
    PRIMARY KEY (space, stream, generation)
) STRICT;
CREATE TABLE IF NOT EXISTS stream_parents (
    space TEXT NOT NULL,
    stream TEXT NOT NULL,
    kind TEXT NOT NULL,                  -- 'stream' or 'person'
    parent TEXT NOT NULL,
    PRIMARY KEY (space, stream, kind, parent)
) STRICT;
CREATE TABLE IF NOT EXISTS stream_records (
    space TEXT NOT NULL,
    stream TEXT NOT NULL,
    position INTEGER NOT NULL,
    canonical BLOB NOT NULL,
    PRIMARY KEY (space, stream, position)
) STRICT;
CREATE TABLE IF NOT EXISTS stream_events (
    space TEXT NOT NULL,
    stream TEXT NOT NULL,
    hash TEXT NOT NULL,
    canonical BLOB NOT NULL,
    PRIMARY KEY (space, stream, hash)
) STRICT;
";

/// Where a stream's key came from: a link in a stream above, or one sealed to a person.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Parent {
    Stream(StreamId),
    Person(PersonId),
}

/// What the device knows of a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamState {
    pub stream: StreamId,
    pub position: i64,
    pub due: bool,
    pub inbox: bool,
}

fn identity<T: std::str::FromStr>(text: String) -> Result<T, StoreError> {
    text.parse().map_err(|_| StoreError::Identity(text))
}

impl Store {
    /// The roster's records of a space, in order.
    pub fn roster_records(&self, space: &SpaceId) -> Result<Vec<RosterRecord>, StoreError> {
        let mut statement = self.connection.prepare("SELECT canonical FROM roster WHERE space = ?1 ORDER BY seq")?;
        let rows = statement.query_map([space.as_str()], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|row| {
            from_root(&row?).map_err(|error| StoreError::Record { space: space.clone(), error: error.to_string() })
        })
        .collect()
    }

    /// The roster of a space, every record checked again.
    pub fn roster(&self, domain: Domain, space: &SpaceId) -> Result<Roster, StoreError> {
        Roster::from_records(domain, space.clone(), &self.roster_records(space)?)
            .map_err(|error| StoreError::Record { space: space.clone(), error: error.to_string() })
    }

    /// Applies a record to the roster and stores it – only if it is the next valid one.
    pub fn add_roster_record(&mut self, domain: Domain, record: &RosterRecord) -> Result<(), StoreError> {
        let mut roster = self.roster(domain, &record.space)?;
        roster
            .apply(record.clone())
            .map_err(|error| StoreError::Record { space: record.space.clone(), error: error.to_string() })?;
        let canonical = to_root(record).expect("a record has a canonical encoding");
        self.connection.execute(
            "INSERT INTO roster (space, seq, canonical) VALUES (?1, ?2, ?3)",
            params![record.space.as_str(), record.seq as i64, canonical],
        )?;
        Ok(())
    }

    /// The spaces of streams on this device.
    pub fn stream_spaces(&self) -> Result<Vec<SpaceId>, StoreError> {
        let mut statement = self.connection.prepare("SELECT DISTINCT space FROM roster ORDER BY space")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|id| identity(id?)).collect()
    }

    /// Notes a stream the device can open; returns whether it was new.
    pub fn add_stream(&self, space: &SpaceId, stream: &StreamId, inbox: bool) -> Result<bool, StoreError> {
        let added = self.connection.execute(
            "INSERT INTO streams (space, stream, inbox) VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING",
            params![space.as_str(), stream.as_str(), inbox],
        )?;
        Ok(added > 0)
    }

    pub fn streams(&self, space: &SpaceId) -> Result<Vec<StreamState>, StoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT stream, position, due, inbox FROM streams WHERE space = ?1 ORDER BY stream")?;
        let rows = statement.query_map([space.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, bool>(2)?, row.get::<_, bool>(3)?))
        })?;
        rows.map(|row| {
            let (stream, position, due, inbox) = row?;
            Ok(StreamState { stream: identity(stream)?, position, due, inbox })
        })
        .collect()
    }

    pub fn stream(&self, space: &SpaceId, stream: &StreamId) -> Result<Option<StreamState>, StoreError> {
        Ok(self.streams(space)?.into_iter().find(|state| state.stream == *stream))
    }

    pub fn set_position(&self, space: &SpaceId, stream: &StreamId, position: i64) -> Result<(), StoreError> {
        self.connection.execute(
            "UPDATE streams SET position = max(position, ?3) WHERE space = ?1 AND stream = ?2",
            params![space.as_str(), stream.as_str(), position],
        )?;
        Ok(())
    }

    pub fn set_due(&self, space: &SpaceId, stream: &StreamId, due: bool) -> Result<(), StoreError> {
        self.connection.execute(
            "UPDATE streams SET due = ?3 WHERE space = ?1 AND stream = ?2",
            params![space.as_str(), stream.as_str(), due],
        )?;
        Ok(())
    }

    /// Forgets a space of streams with all the device kept of it – its roster, streams, keys and settings – when the
    /// device was removed from it, or leaves it.
    pub fn remove_stream_space(&mut self, space: &SpaceId) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        for table in
            ["roster", "streams", "stream_keys", "stream_parents", "stream_records", "stream_events", "settings"]
        {
            transaction.execute(&format!("DELETE FROM {table} WHERE space = ?1"), params![space.as_str()])?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Forgets a stream – purged, or no longer reachable – with what the device kept of it.
    pub fn remove_stream(&mut self, space: &SpaceId, stream: &StreamId) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        for table in ["streams", "stream_keys", "stream_parents", "stream_records", "stream_events"] {
            transaction.execute(
                &format!("DELETE FROM {table} WHERE space = ?1 AND stream = ?2"),
                params![space.as_str(), stream.as_str()],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn put_stream_key(
        &self,
        space: &SpaceId,
        stream: &StreamId,
        generation: u32,
        key: &StreamKey,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO stream_keys (space, stream, generation, key) VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
            params![space.as_str(), stream.as_str(), generation, key.0.as_slice()],
        )?;
        Ok(())
    }

    /// The keys of a stream the device holds, by generation.
    pub fn stream_keys(&self, space: &SpaceId, stream: &StreamId) -> Result<BTreeMap<u32, StreamKey>, StoreError> {
        let mut statement =
            self.connection.prepare("SELECT generation, key FROM stream_keys WHERE space = ?1 AND stream = ?2")?;
        let rows = statement.query_map(params![space.as_str(), stream.as_str()], |row| {
            Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        rows.map(|row| {
            let (generation, key) = row?;
            let key: [u8; 32] = key.try_into().map_err(|_| StoreError::Identity("a stream key".into()))?;
            Ok((generation, StreamKey(key)))
        })
        .collect()
    }

    pub fn add_parent(&self, space: &SpaceId, stream: &StreamId, parent: &Parent) -> Result<(), StoreError> {
        let (kind, parent) = match parent {
            Parent::Stream(id) => ("stream", id.to_string()),
            Parent::Person(id) => ("person", id.to_string()),
        };
        self.connection.execute(
            "INSERT INTO stream_parents (space, stream, kind, parent) VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
            params![space.as_str(), stream.as_str(), kind, parent],
        )?;
        Ok(())
    }

    /// The streams and persons a stream's key was linked from – its audience, as far as this device has seen.
    pub fn parents(&self, space: &SpaceId, stream: &StreamId) -> Result<Vec<Parent>, StoreError> {
        let mut statement =
            self.connection.prepare("SELECT kind, parent FROM stream_parents WHERE space = ?1 AND stream = ?2")?;
        let rows = statement.query_map(params![space.as_str(), stream.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (kind, parent) = row?;
            Ok(if kind == "stream" { Parent::Stream(identity(parent)?) } else { Parent::Person(identity(parent)?) })
        })
        .collect()
    }

    /// The streams linked from `parent`.
    pub fn children(&self, space: &SpaceId, parent: &Parent) -> Result<Vec<StreamId>, StoreError> {
        let (kind, parent) = match parent {
            Parent::Stream(id) => ("stream", id.to_string()),
            Parent::Person(id) => ("person", id.to_string()),
        };
        let mut statement = self.connection.prepare(
            "SELECT stream FROM stream_parents WHERE space = ?1 AND kind = ?2 AND parent = ?3 ORDER BY stream",
        )?;
        let rows = statement.query_map(params![space.as_str(), kind, parent], |row| row.get::<_, String>(0))?;
        rows.map(|row| identity(row?)).collect()
    }

    pub fn put_stream_record(
        &self,
        space: &SpaceId,
        stream: &StreamId,
        position: i64,
        canonical: &[u8],
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO stream_records (space, stream, position, canonical) VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
            params![space.as_str(), stream.as_str(), position, canonical],
        )?;
        Ok(())
    }

    /// The records of a stream the device received, in the relay's order.
    pub fn stream_records(&self, space: &SpaceId, stream: &StreamId) -> Result<Vec<(i64, Vec<u8>)>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT position, canonical FROM stream_records WHERE space = ?1 AND stream = ?2 ORDER BY position",
        )?;
        let rows =
            statement.query_map(params![space.as_str(), stream.as_str()], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.map(|row| row.map_err(StoreError::from)).collect()
    }

    /// The events of a stream: its log.
    pub fn stream_log(&self, space: &SpaceId, stream: &StreamId) -> Result<Log, StoreError> {
        let mut statement =
            self.connection.prepare("SELECT canonical FROM stream_events WHERE space = ?1 AND stream = ?2")?;
        let rows = statement.query_map(params![space.as_str(), stream.as_str()], |row| row.get::<_, Vec<u8>>(0))?;
        let mut log = Log::new();
        for row in rows {
            log.receive(&row?).map_err(|error| StoreError::Event { space: space.clone(), error })?;
        }
        Ok(log)
    }

    /// Stores an event of a stream (its canonical encoding); whether it was new.
    pub fn add_stream_event(
        &self,
        space: &SpaceId,
        stream: &StreamId,
        hash: &str,
        canonical: &[u8],
    ) -> Result<bool, StoreError> {
        let added = self.connection.execute(
            "INSERT INTO stream_events (space, stream, hash, canonical) VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
            params![space.as_str(), stream.as_str(), hash, canonical],
        )?;
        Ok(added > 0)
    }

    /// Whether the device knows this stream.
    pub fn has_stream(&self, space: &SpaceId, stream: &StreamId) -> Result<bool, StoreError> {
        Ok(self
            .connection
            .query_row(
                "SELECT 1 FROM streams WHERE space = ?1 AND stream = ?2",
                params![space.as_str(), stream.as_str()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }
}
