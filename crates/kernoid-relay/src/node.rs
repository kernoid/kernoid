// SPDX-License-Identifier: AGPL-3.0-or-later
//! A server as one more node of spaces of streams (RFC 0010, 8; RFC 0012): what a device keeps of its spaces in SQLite
//! (`kernoid_spaces::store::Store`), [`Node`] keeps in PostgreSQL, so that a server – a program built on kernoid, its
//! identity built in – follows a space like a device does, holds every key it was given, writes when due and answers
//! for the people it acts for. The engine is kernoid-spaces' own: `Streams::open(domain, device, Node::new(…))`.
//! The feature `node` of kernoid-relay: the relay is where spaces meet, a node is one of their members.
//!
//! The engine is synchronous, as on devices: run it on a thread of its own (`tokio::task::spawn_blocking`) – [`Node`]
//! waits for PostgreSQL there through the runtime's handle, and must never be called on one of the runtime's workers.
//!
//! What only the node may read – the state of a space, which holds the node's seed, the keys of streams and the events
//! read from them – is sealed under the node's key ([`kernoid_store::crypto::seal_secret`]), bound to its node, space,
//! stream and kind, so that a value cannot be moved elsewhere. The key is the program's: a secret of its own, like
//! kernoid's main key – losing it loses what the node read, which the relay still holds for it.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;

use kernoid_base::{SpaceId, from_root, to_root};
use kernoid_crypt::{
    Domain,
    stream::{RosterRecord, StreamId, StreamKey},
};
use kernoid_log::Log;
use kernoid_spaces::store::StoreError;
use kernoid_spaces::store::streams::{Parent, StreamBackend, StreamState, identity};
use kernoid_store::crypto::{Key, open_secret, seal_secret};
use sqlx::PgPool;
use tokio::runtime::Handle;

/// A node's spaces of streams in PostgreSQL (`node_*`, migration 0059).
#[derive(Clone)]
pub struct Node {
    pool: PgPool,
    node: String,
    key: Arc<Key>,
    runtime: Handle,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node").field("node", &self.node).finish_non_exhaustive()
    }
}

fn database(error: sqlx::Error) -> StoreError {
    StoreError::Backend(format!("database: {error}"))
}

fn parent_parts(parent: &Parent) -> (&'static str, String) {
    match parent {
        Parent::Stream(id) => ("stream", id.to_string()),
        Parent::Person(id) => ("person", id.to_string()),
    }
}

impl Node {
    /// The node named `node` (1 to 128 characters) in `pool`'s database, its secrets sealed under `key`; `runtime`
    /// runs the queries the engine waits for.
    pub fn new(pool: PgPool, node: &str, key: Key, runtime: Handle) -> Result<Self, StoreError> {
        if node.is_empty() || node.chars().count() > 128 {
            return Err(StoreError::Backend("a node's name has 1 to 128 characters".into()));
        }
        Ok(Node { pool, node: node.to_owned(), key: Arc::new(key), runtime })
    }

    /// The node's name.
    pub fn name(&self) -> &str {
        &self.node
    }

    fn wait<T>(&self, query: impl Future<Output = Result<T, sqlx::Error>>) -> Result<T, StoreError> {
        self.runtime.block_on(query).map_err(database)
    }

    fn context(&self, kind: &str, parts: &[&str]) -> Vec<u8> {
        let mut context = format!("kernoid-node\u{0}{kind}\u{0}{}", self.node);
        for part in parts {
            context.push('\u{0}');
            context.push_str(part);
        }
        context.into_bytes()
    }

    fn seal(&self, kind: &str, parts: &[&str], value: &[u8]) -> Result<Vec<u8>, StoreError> {
        seal_secret(&self.key, &self.context(kind, parts), value)
            .map_err(|error| StoreError::Backend(format!("sealing: {error}")))
    }

    fn open(&self, kind: &str, parts: &[&str], sealed: &[u8]) -> Result<Vec<u8>, StoreError> {
        open_secret(&self.key, &self.context(kind, parts), sealed).map(|value| value.to_vec()).map_err(|_| {
            StoreError::Backend(format!("a sealed {kind} of node {} does not open with its key", self.node))
        })
    }
}

impl StreamBackend for Node {
    fn space_state(&self, space: &SpaceId) -> Result<Option<String>, StoreError> {
        let sealed = self.wait(
            sqlx::query_scalar!(
                "SELECT state FROM node_spaces WHERE node = $1 AND space = $2",
                self.node,
                space.as_str()
            )
            .fetch_optional(&self.pool),
        )?;
        let Some(sealed) = sealed else { return Ok(None) };
        let state = self.open("state", &[space.as_str()], &sealed)?;
        String::from_utf8(state).map(Some).map_err(|_| StoreError::Identity("a state".into()))
    }

    fn set_space_state(&self, space: &SpaceId, state: &str) -> Result<(), StoreError> {
        let sealed = self.seal("state", &[space.as_str()], state.as_bytes())?;
        self.wait(
            sqlx::query!(
                "INSERT INTO node_spaces (node, space, state) VALUES ($1, $2, $3)
                 ON CONFLICT (node, space) DO UPDATE SET state = EXCLUDED.state",
                self.node,
                space.as_str(),
                sealed
            )
            .execute(&self.pool),
        )?;
        Ok(())
    }

    fn roster_records(&self, space: &SpaceId) -> Result<Vec<RosterRecord>, StoreError> {
        let rows = self.wait(
            sqlx::query_scalar!(
                "SELECT canonical FROM node_roster WHERE node = $1 AND space = $2 ORDER BY seq",
                self.node,
                space.as_str()
            )
            .fetch_all(&self.pool),
        )?;
        rows.iter()
            .map(|row| {
                from_root(row).map_err(|error| StoreError::Record { space: space.clone(), error: error.to_string() })
            })
            .collect()
    }

    fn add_roster_record(&mut self, domain: Domain, record: &RosterRecord) -> Result<(), StoreError> {
        let mut roster = self.roster(domain, &record.space)?;
        roster
            .apply(record.clone())
            .map_err(|error| StoreError::Record { space: record.space.clone(), error: error.to_string() })?;
        let canonical = to_root(record).expect("a record has a canonical encoding");
        // Two writers of the same record: the second fails on the key, as the roster would refuse it.
        self.wait(
            sqlx::query!(
                "INSERT INTO node_roster (node, space, seq, canonical) VALUES ($1, $2, $3, $4)",
                self.node,
                record.space.as_str(),
                record.seq as i64,
                canonical
            )
            .execute(&self.pool),
        )?;
        Ok(())
    }

    fn stream_spaces(&self) -> Result<Vec<SpaceId>, StoreError> {
        let rows = self.wait(
            sqlx::query_scalar!("SELECT DISTINCT space FROM node_roster WHERE node = $1 ORDER BY space", self.node)
                .fetch_all(&self.pool),
        )?;
        rows.into_iter().map(identity).collect()
    }

    fn add_stream(&self, space: &SpaceId, stream: &StreamId, inbox: bool) -> Result<bool, StoreError> {
        let added = self.wait(
            sqlx::query!(
                "INSERT INTO node_streams (node, space, stream, inbox) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                self.node,
                space.as_str(),
                stream.as_str(),
                inbox
            )
            .execute(&self.pool),
        )?;
        Ok(added.rows_affected() > 0)
    }

    fn streams(&self, space: &SpaceId) -> Result<Vec<StreamState>, StoreError> {
        let rows = self.wait(
            sqlx::query!(
                "SELECT stream, position, due, inbox FROM node_streams WHERE node = $1 AND space = $2 ORDER BY stream",
                self.node,
                space.as_str()
            )
            .fetch_all(&self.pool),
        )?;
        rows.into_iter()
            .map(|row| {
                Ok(StreamState {
                    stream: identity(row.stream)?,
                    position: row.position,
                    due: row.due,
                    inbox: row.inbox,
                })
            })
            .collect()
    }

    fn set_position(&self, space: &SpaceId, stream: &StreamId, position: i64) -> Result<(), StoreError> {
        self.wait(
            sqlx::query!(
                "UPDATE node_streams SET position = GREATEST(position, $4) WHERE node = $1 AND space = $2 AND stream = $3",
                self.node,
                space.as_str(),
                stream.as_str(),
                position
            )
            .execute(&self.pool),
        )?;
        Ok(())
    }

    fn set_due(&self, space: &SpaceId, stream: &StreamId, due: bool) -> Result<(), StoreError> {
        self.wait(
            sqlx::query!(
                "UPDATE node_streams SET due = $4 WHERE node = $1 AND space = $2 AND stream = $3",
                self.node,
                space.as_str(),
                stream.as_str(),
                due
            )
            .execute(&self.pool),
        )?;
        Ok(())
    }

    fn remove_stream_space(&mut self, space: &SpaceId) -> Result<(), StoreError> {
        let (pool, node, space) = (self.pool.clone(), self.node.clone(), space.to_string());
        self.wait(async move {
            let mut transaction = pool.begin().await?;
            sqlx::query!("DELETE FROM node_roster WHERE node = $1 AND space = $2", node, space)
                .execute(&mut *transaction)
                .await?;
            sqlx::query!("DELETE FROM node_streams WHERE node = $1 AND space = $2", node, space)
                .execute(&mut *transaction)
                .await?;
            sqlx::query!("DELETE FROM node_stream_keys WHERE node = $1 AND space = $2", node, space)
                .execute(&mut *transaction)
                .await?;
            sqlx::query!("DELETE FROM node_stream_parents WHERE node = $1 AND space = $2", node, space)
                .execute(&mut *transaction)
                .await?;
            sqlx::query!("DELETE FROM node_stream_records WHERE node = $1 AND space = $2", node, space)
                .execute(&mut *transaction)
                .await?;
            sqlx::query!("DELETE FROM node_stream_events WHERE node = $1 AND space = $2", node, space)
                .execute(&mut *transaction)
                .await?;
            sqlx::query!("DELETE FROM node_spaces WHERE node = $1 AND space = $2", node, space)
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await
        })
    }

    fn remove_stream(&mut self, space: &SpaceId, stream: &StreamId) -> Result<(), StoreError> {
        let (pool, node, space, stream) = (self.pool.clone(), self.node.clone(), space.to_string(), stream.to_string());
        self.wait(async move {
            let mut transaction = pool.begin().await?;
            sqlx::query!(
                "DELETE FROM node_streams WHERE node = $1 AND space = $2 AND stream = $3",
                node,
                space,
                stream
            )
            .execute(&mut *transaction)
            .await?;
            sqlx::query!(
                "DELETE FROM node_stream_keys WHERE node = $1 AND space = $2 AND stream = $3",
                node,
                space,
                stream
            )
            .execute(&mut *transaction)
            .await?;
            sqlx::query!(
                "DELETE FROM node_stream_parents WHERE node = $1 AND space = $2 AND stream = $3",
                node,
                space,
                stream
            )
            .execute(&mut *transaction)
            .await?;
            sqlx::query!(
                "DELETE FROM node_stream_records WHERE node = $1 AND space = $2 AND stream = $3",
                node,
                space,
                stream
            )
            .execute(&mut *transaction)
            .await?;
            sqlx::query!(
                "DELETE FROM node_stream_events WHERE node = $1 AND space = $2 AND stream = $3",
                node,
                space,
                stream
            )
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await
        })
    }

    fn put_stream_key(
        &self,
        space: &SpaceId,
        stream: &StreamId,
        generation: u32,
        key: &StreamKey,
    ) -> Result<(), StoreError> {
        let sealed = self.seal("key", &[space.as_str(), stream.as_str(), &generation.to_string()], &key.0)?;
        self.wait(
            sqlx::query!(
                "INSERT INTO node_stream_keys (node, space, stream, generation, key) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT DO NOTHING",
                self.node,
                space.as_str(),
                stream.as_str(),
                i64::from(generation),
                sealed
            )
            .execute(&self.pool),
        )?;
        Ok(())
    }

    fn stream_keys(&self, space: &SpaceId, stream: &StreamId) -> Result<BTreeMap<u32, StreamKey>, StoreError> {
        let rows = self.wait(
            sqlx::query!(
                "SELECT generation, key FROM node_stream_keys WHERE node = $1 AND space = $2 AND stream = $3",
                self.node,
                space.as_str(),
                stream.as_str()
            )
            .fetch_all(&self.pool),
        )?;
        rows.into_iter()
            .map(|row| {
                let generation =
                    u32::try_from(row.generation).map_err(|_| StoreError::Identity("a generation".into()))?;
                let key = self.open("key", &[space.as_str(), stream.as_str(), &generation.to_string()], &row.key)?;
                let key: [u8; 32] = key.try_into().map_err(|_| StoreError::Identity("a stream key".into()))?;
                Ok((generation, StreamKey(key)))
            })
            .collect()
    }

    fn add_parent(&self, space: &SpaceId, stream: &StreamId, parent: &Parent) -> Result<(), StoreError> {
        let (kind, parent) = parent_parts(parent);
        self.wait(
            sqlx::query!(
                "INSERT INTO node_stream_parents (node, space, stream, kind, parent) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT DO NOTHING",
                self.node,
                space.as_str(),
                stream.as_str(),
                kind,
                parent
            )
            .execute(&self.pool),
        )?;
        Ok(())
    }

    fn parents(&self, space: &SpaceId, stream: &StreamId) -> Result<Vec<Parent>, StoreError> {
        let rows = self.wait(
            sqlx::query!(
                "SELECT kind, parent FROM node_stream_parents WHERE node = $1 AND space = $2 AND stream = $3
                 ORDER BY kind, parent",
                self.node,
                space.as_str(),
                stream.as_str()
            )
            .fetch_all(&self.pool),
        )?;
        rows.into_iter()
            .map(|row| {
                Ok(if row.kind == "stream" {
                    Parent::Stream(identity(row.parent)?)
                } else {
                    Parent::Person(identity(row.parent)?)
                })
            })
            .collect()
    }

    fn children(&self, space: &SpaceId, parent: &Parent) -> Result<Vec<StreamId>, StoreError> {
        let (kind, parent) = parent_parts(parent);
        let rows = self.wait(
            sqlx::query_scalar!(
                "SELECT stream FROM node_stream_parents WHERE node = $1 AND space = $2 AND kind = $3 AND parent = $4
                 ORDER BY stream",
                self.node,
                space.as_str(),
                kind,
                parent
            )
            .fetch_all(&self.pool),
        )?;
        rows.into_iter().map(identity).collect()
    }

    fn put_stream_record(
        &self,
        space: &SpaceId,
        stream: &StreamId,
        position: i64,
        canonical: &[u8],
    ) -> Result<(), StoreError> {
        self.wait(
            sqlx::query!(
                "INSERT INTO node_stream_records (node, space, stream, position, canonical) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT DO NOTHING",
                self.node,
                space.as_str(),
                stream.as_str(),
                position,
                canonical
            )
            .execute(&self.pool),
        )?;
        Ok(())
    }

    fn stream_records(&self, space: &SpaceId, stream: &StreamId) -> Result<Vec<(i64, Vec<u8>)>, StoreError> {
        let rows = self.wait(
            sqlx::query!(
                "SELECT position, canonical FROM node_stream_records WHERE node = $1 AND space = $2 AND stream = $3
                 ORDER BY position",
                self.node,
                space.as_str(),
                stream.as_str()
            )
            .fetch_all(&self.pool),
        )?;
        Ok(rows.into_iter().map(|row| (row.position, row.canonical)).collect())
    }

    fn stream_log(&self, space: &SpaceId, stream: &StreamId) -> Result<Log, StoreError> {
        let rows = self.wait(
            sqlx::query!(
                "SELECT hash, canonical FROM node_stream_events WHERE node = $1 AND space = $2 AND stream = $3",
                self.node,
                space.as_str(),
                stream.as_str()
            )
            .fetch_all(&self.pool),
        )?;
        let mut log = Log::new();
        for row in rows {
            let canonical = self.open("event", &[space.as_str(), stream.as_str(), &row.hash], &row.canonical)?;
            log.receive(&canonical).map_err(|error| StoreError::Event { space: space.clone(), error })?;
        }
        Ok(log)
    }

    fn add_stream_event(
        &self,
        space: &SpaceId,
        stream: &StreamId,
        hash: &str,
        canonical: &[u8],
    ) -> Result<bool, StoreError> {
        let sealed = self.seal("event", &[space.as_str(), stream.as_str(), hash], canonical)?;
        let added = self.wait(
            sqlx::query!(
                "INSERT INTO node_stream_events (node, space, stream, hash, canonical) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT DO NOTHING",
                self.node,
                space.as_str(),
                stream.as_str(),
                hash,
                sealed
            )
            .execute(&self.pool),
        )?;
        Ok(added.rows_affected() > 0)
    }

    fn has_stream(&self, space: &SpaceId, stream: &StreamId) -> Result<bool, StoreError> {
        let found = self.wait(
            sqlx::query_scalar!(
                "SELECT 1 AS \"one!\" FROM node_streams WHERE node = $1 AND space = $2 AND stream = $3",
                self.node,
                space.as_str(),
                stream.as_str()
            )
            .fetch_optional(&self.pool),
        )?;
        Ok(found.is_some())
    }
}
