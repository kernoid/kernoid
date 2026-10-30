// SPDX-License-Identifier: MIT
//! The local state of a folder kept in step, in SQLite: the store's tree as last read with the journal state it
//! belongs to, and per path what both sides were when they last agreed (`plan::Base`). One database per folder; it
//! lives outside the folder, where the app keeps its data.

use std::{collections::BTreeMap, path::Path};

use rusqlite::{Connection, OptionalExtension, params};

use crate::{
    Error, Result,
    plan::{Base, Local, RelPath, Remote},
};

/// A node of the store as read from the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub id: String,
    pub parent: Option<String>,
    pub name: String,
    pub directory: bool,
    pub blob: Option<String>,
    pub size: u64,
    pub role: Option<String>,
}

#[derive(Debug)]
pub struct State {
    db: Connection,
}

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Error::State(error.to_string())
    }
}

impl State {
    pub fn open(path: &Path) -> Result<State> {
        let db = Connection::open(path)?;
        db.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS remote (
                 id TEXT PRIMARY KEY, parent TEXT, name TEXT NOT NULL, directory INTEGER NOT NULL, blob TEXT,
                 size INTEGER NOT NULL, role TEXT);
             CREATE TABLE IF NOT EXISTS base (
                 path TEXT PRIMARY KEY, id TEXT NOT NULL, directory INTEGER NOT NULL, blob TEXT, size INTEGER NOT NULL,
                 local_directory INTEGER NOT NULL, local_size INTEGER NOT NULL, local_modified TEXT NOT NULL);",
        )?;
        Ok(State { db })
    }

    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self.db.query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| row.get(0)).optional()?)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)", [key, value])?;
        Ok(())
    }

    pub fn remote(&self) -> Result<BTreeMap<String, Node>> {
        let mut query = self.db.prepare("SELECT id, parent, name, directory, blob, size, role FROM remote")?;
        let rows = query.query_map([], |row| {
            Ok(Node {
                id: row.get(0)?,
                parent: row.get(1)?,
                name: row.get(2)?,
                directory: row.get(3)?,
                blob: row.get(4)?,
                size: row.get::<_, i64>(5)? as u64,
                role: row.get(6)?,
            })
        })?;
        let mut out = BTreeMap::new();
        for node in rows {
            let node = node?;
            out.insert(node.id.clone(), node);
        }
        Ok(out)
    }

    /// Replaces the stored tree and its state at once.
    pub fn set_remote(&mut self, nodes: &BTreeMap<String, Node>, state: &str) -> Result<()> {
        let tx = self.db.transaction()?;
        tx.execute("DELETE FROM remote", [])?;
        {
            let mut insert = tx.prepare(
                "INSERT INTO remote (id, parent, name, directory, blob, size, role) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for node in nodes.values() {
                insert.execute(params![
                    node.id,
                    node.parent,
                    node.name,
                    node.directory,
                    node.blob,
                    node.size as i64,
                    node.role
                ])?;
            }
        }
        tx.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('state', ?1)", [state])?;
        tx.commit()?;
        Ok(())
    }

    pub fn base(&self) -> Result<BTreeMap<RelPath, Base>> {
        let mut query = self
            .db
            .prepare("SELECT path, id, directory, blob, size, local_directory, local_size, local_modified FROM base")?;
        let rows = query.query_map([], |row| {
            let modified: String = row.get(7)?;
            Ok((
                row.get::<_, String>(0)?,
                Base {
                    remote: Remote {
                        id: row.get(1)?,
                        directory: row.get(2)?,
                        blob: row.get(3)?,
                        size: row.get::<_, i64>(4)? as u64,
                    },
                    local: Local {
                        directory: row.get(5)?,
                        size: row.get::<_, i64>(6)? as u64,
                        modified: modified.parse().unwrap_or_default(),
                    },
                },
            ))
        })?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (path, base) = row?;
            out.insert(path, base);
        }
        Ok(out)
    }

    /// Replaces what both sides agreed on.
    pub fn set_base(&mut self, base: &BTreeMap<RelPath, Base>) -> Result<()> {
        let tx = self.db.transaction()?;
        tx.execute("DELETE FROM base", [])?;
        {
            let mut insert = tx.prepare(
                "INSERT INTO base (path, id, directory, blob, size, local_directory, local_size, local_modified)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for (path, base) in base {
                insert.execute(params![
                    path,
                    base.remote.id,
                    base.remote.directory,
                    base.remote.blob,
                    base.remote.size as i64,
                    base.local.directory,
                    base.local.size as i64,
                    base.local.modified.to_string()
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_stored_comes_back() {
        let dir = std::env::temp_dir().join(format!("kernoid-sync-state-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.db");
        let mut state = State::open(&path).unwrap();
        let node = Node {
            id: "n1".into(),
            parent: None,
            name: "a.txt".into(),
            directory: false,
            blob: Some("b1".into()),
            size: 3,
            role: None,
        };
        state.set_remote(&BTreeMap::from([("n1".to_owned(), node.clone())]), "7").unwrap();
        let base = Base {
            remote: Remote { id: "n1".into(), directory: false, blob: Some("b1".into()), size: 3 },
            local: Local { directory: false, size: 3, modified: 1_761_000_000_123_456_789 },
        };
        state.set_base(&BTreeMap::from([("a.txt".to_owned(), base.clone())])).unwrap();
        drop(state);
        let state = State::open(&path).unwrap();
        assert_eq!(state.meta("state").unwrap().as_deref(), Some("7"));
        assert_eq!(state.remote().unwrap()["n1"], node);
        assert_eq!(state.base().unwrap()["a.txt"], base);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
