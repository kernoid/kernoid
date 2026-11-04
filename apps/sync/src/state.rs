// SPDX-License-Identifier: MIT
//! The local state of a folder kept in step, in SQLite: the store's tree as last read with the journal state it
//! belongs to, per path what both sides were when they last agreed (`plan::Base`), and transfers that broke off. One
//! database per folder; it lives outside the folder, where the app keeps its data. Names in vaults are kept here
//! decrypted, as the folder holds them anyway.

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
    /// The vault the node lies in (its own id on a vault's root), and its name there encrypted.
    pub vault: Option<String>,
    pub sealed_name: Option<String>,
    /// In a vault whose key was not at hand: `name` is only the node's id there.
    pub locked: bool,
}

/// An upload in pieces under way: the file it was for (size and modification time), the pieces sent, and when it
/// began – the server keeps uploads for a day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pieces {
    pub size: u64,
    pub modified: i128,
    pub blobs: Vec<String>,
    pub started: i64,
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
        // 1 (0.2.4): vaults, file ids, transfers.
        let version: i64 = db.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version < 1 {
            db.execute_batch(
                "BEGIN;
                 ALTER TABLE remote ADD COLUMN vault TEXT;
                 ALTER TABLE remote ADD COLUMN sealed_name TEXT;
                 ALTER TABLE remote ADD COLUMN locked INTEGER NOT NULL DEFAULT 0;
                 ALTER TABLE base ADD COLUMN vault TEXT;
                 ALTER TABLE base ADD COLUMN local_file TEXT NOT NULL DEFAULT '0';
                 CREATE TABLE downloads (path TEXT PRIMARY KEY, blob TEXT NOT NULL);
                 CREATE TABLE uploads (
                     path TEXT PRIMARY KEY, size INTEGER NOT NULL, modified TEXT NOT NULL, blobs TEXT NOT NULL,
                     started INTEGER NOT NULL);
                 PRAGMA user_version = 1;
                 COMMIT;",
            )?;
        }
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
        let mut query = self
            .db
            .prepare("SELECT id, parent, name, directory, blob, size, role, vault, sealed_name, locked FROM remote")?;
        let rows = query.query_map([], |row| {
            Ok(Node {
                id: row.get(0)?,
                parent: row.get(1)?,
                name: row.get(2)?,
                directory: row.get(3)?,
                blob: row.get(4)?,
                size: row.get::<_, i64>(5)? as u64,
                role: row.get(6)?,
                vault: row.get(7)?,
                sealed_name: row.get(8)?,
                locked: row.get(9)?,
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
                "INSERT INTO remote (id, parent, name, directory, blob, size, role, vault, sealed_name, locked)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            for node in nodes.values() {
                insert.execute(params![
                    node.id,
                    node.parent,
                    node.name,
                    node.directory,
                    node.blob,
                    node.size as i64,
                    node.role,
                    node.vault,
                    node.sealed_name,
                    node.locked
                ])?;
            }
        }
        tx.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('state', ?1)", [state])?;
        tx.commit()?;
        Ok(())
    }

    pub fn base(&self) -> Result<BTreeMap<RelPath, Base>> {
        let mut query = self.db.prepare(
            "SELECT path, id, directory, blob, size, local_directory, local_size, local_modified, vault, local_file
                 FROM base",
        )?;
        let rows = query.query_map([], |row| {
            let modified: String = row.get(7)?;
            let file: String = row.get(9)?;
            Ok((
                row.get::<_, String>(0)?,
                Base {
                    remote: Remote {
                        id: row.get(1)?,
                        directory: row.get(2)?,
                        blob: row.get(3)?,
                        size: row.get::<_, i64>(4)? as u64,
                        vault: row.get(8)?,
                    },
                    local: Local {
                        directory: row.get(5)?,
                        size: row.get::<_, i64>(6)? as u64,
                        modified: modified.parse().unwrap_or_default(),
                        file: file.parse().unwrap_or_default(),
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
                "INSERT INTO base
                   (path, id, directory, blob, size, local_directory, local_size, local_modified, vault, local_file)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
                    base.local.modified.to_string(),
                    base.remote.vault,
                    base.local.file.to_string()
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// The blob a download into a path's partial file was for, if one broke off.
    pub fn download(&self, path: &str) -> Result<Option<String>> {
        Ok(self.db.query_row("SELECT blob FROM downloads WHERE path = ?1", [path], |row| row.get(0)).optional()?)
    }

    /// Records a download begun (`Some`) or ended (`None`).
    pub fn set_download(&self, path: &str, blob: Option<&str>) -> Result<()> {
        match blob {
            Some(blob) => {
                self.db.execute("INSERT OR REPLACE INTO downloads (path, blob) VALUES (?1, ?2)", [path, blob])?
            }
            None => self.db.execute("DELETE FROM downloads WHERE path = ?1", [path])?,
        };
        Ok(())
    }

    /// The paths of downloads that broke off.
    pub fn downloads(&self) -> Result<Vec<RelPath>> {
        let mut query = self.db.prepare("SELECT path FROM downloads")?;
        let rows = query.query_map([], |row| row.get(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// The pieces of an upload of a path sent so far.
    pub fn upload(&self, path: &str) -> Result<Option<Pieces>> {
        let row = self
            .db
            .query_row("SELECT size, modified, blobs, started FROM uploads WHERE path = ?1", [path], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, i64>(3)?))
            })
            .optional()?;
        Ok(row.map(|(size, modified, blobs, started)| Pieces {
            size: size as u64,
            modified: modified.parse().unwrap_or_default(),
            blobs: serde_json::from_str(&blobs).unwrap_or_default(),
            started,
        }))
    }

    /// Records the pieces of an upload (`Some`), or that it ended (`None`).
    pub fn set_upload(&self, path: &str, pieces: Option<&Pieces>) -> Result<()> {
        match pieces {
            Some(p) => self.db.execute(
                "INSERT OR REPLACE INTO uploads (path, size, modified, blobs, started) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    path,
                    p.size as i64,
                    p.modified.to_string(),
                    serde_json::to_string(&p.blobs).unwrap_or_default(),
                    p.started
                ],
            )?,
            None => self.db.execute("DELETE FROM uploads WHERE path = ?1", [path])?,
        };
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
            vault: Some("v".into()),
            sealed_name: Some("c2VhbGVk".into()),
            locked: false,
        };
        state.set_remote(&BTreeMap::from([("n1".to_owned(), node.clone())]), "7").unwrap();
        let base = Base {
            remote: Remote {
                id: "n1".into(),
                directory: false,
                blob: Some("b1".into()),
                size: 3,
                vault: Some("v".into()),
            },
            local: Local { directory: false, size: 3, modified: 1_761_000_000_123_456_789, file: u64::MAX },
        };
        state.set_base(&BTreeMap::from([("a.txt".to_owned(), base.clone())])).unwrap();
        drop(state);
        let state = State::open(&path).unwrap();
        assert_eq!(state.meta("state").unwrap().as_deref(), Some("7"));
        assert_eq!(state.remote().unwrap()["n1"], node);
        assert_eq!(state.base().unwrap()["a.txt"], base);
        // Transfers that broke off.
        state.set_download("a.txt", Some("b2")).unwrap();
        assert_eq!(state.download("a.txt").unwrap().as_deref(), Some("b2"));
        assert_eq!(state.downloads().unwrap(), ["a.txt"]);
        state.set_download("a.txt", None).unwrap();
        assert_eq!(state.download("a.txt").unwrap(), None);
        let pieces = Pieces { size: 20, modified: 5, blobs: vec!["p1".into(), "p2".into()], started: 1 };
        state.set_upload("big.bin", Some(&pieces)).unwrap();
        assert_eq!(state.upload("big.bin").unwrap(), Some(pieces));
        state.set_upload("big.bin", None).unwrap();
        assert_eq!(state.upload("big.bin").unwrap(), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
