// SPDX-License-Identifier: MIT
//! The store: a device's spaces in SQLite – part of kernoid's foundation (RFC 0010): the events and member records of every space a
//! device holds, which originals belong to it, its settings, and what it has sent to a relay. The bytes of originals are
//! not here but in `kernoid-blob`.
//!
//! One database holds all spaces of a device, so that spaces that belong together can be written in one transaction.
//! Every event and record is kept in its canonical encoding – the form it is hashed and passed on in. The store
//! knows the frame of events, not their kinds; a program builds its own views on the events.
//!
//! What the foundation keeps is the trait [`Backend`] (and [`streams::StreamBackend`] for spaces of streams): [`Store`]
//! keeps them in SQLite, on a device (the feature `sqlite`). A server keeps the spaces of the relay in `kernoid-relay`, and
//! those it is a node of in its module `node` – both on PostgreSQL.

pub mod streams;

#[cfg(feature = "sqlite")]
use std::path::Path;
use std::{collections::BTreeSet, fmt};

#[cfg(feature = "sqlite")]
use kernoid_base::to_root;
use kernoid_base::{Sha256Hash, SpaceId};
use kernoid_crypt::{Domain, MemberList, MemberRecord, RecordProblem};
use kernoid_log::{EventError, Log};
/// The SQLite binding of the store, for programs that keep tables of their own beside it ([`Store::connection`]).
#[cfg(feature = "sqlite")]
pub use rusqlite;
#[cfg(feature = "sqlite")]
use rusqlite::{Connection, OptionalExtension, params};

/// Why the store failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database.
    #[cfg(feature = "sqlite")]
    #[error("database: {0}")]
    Database(#[from] rusqlite::Error),
    /// The store of another backend – a server's database.
    #[error("store: {0}")]
    Backend(String),
    /// A name of a schema in PostgreSQL that is not a plain one.
    #[error("{0:?} is not a name of a schema: a–z, 0–9 and _, starting with a letter, at most 63")]
    Schema(String),
    /// A stored event could not be read – the database was changed from outside.
    #[error("stored event of space {space}: {error}")]
    Event {
        /// The space.
        space: SpaceId,
        /// What was wrong.
        error: EventError,
    },
    /// A stored member record could not be read, or the records do not form a valid list.
    #[error("member records of space {space}: {error}")]
    Record {
        /// The space.
        space: SpaceId,
        /// What was wrong.
        error: String,
    },
    /// A member record that does not follow the stored ones.
    #[error(transparent)]
    NotNext(#[from] RecordProblem),
    /// A stored identity that is not one – the database was changed from outside.
    #[error("stored identity {0:?} is not valid")]
    Identity(String),
    /// A database of a later version of the schema.
    #[error("the database has schema version {0}, this version knows up to {SCHEMA_VERSION}")]
    Version(i64),
}

/// The version of the schema, kept in `user_version`.
pub const SCHEMA_VERSION: i64 = 2;

#[cfg(feature = "sqlite")]
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS settings (
    space TEXT NOT NULL,          -- '' for settings of the device
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (space, key)
) STRICT;
CREATE TABLE IF NOT EXISTS events (
    space TEXT NOT NULL,
    hash TEXT NOT NULL,           -- sha256:… of the canonical encoding
    canonical BLOB NOT NULL,
    PRIMARY KEY (space, hash)
) STRICT;
CREATE TABLE IF NOT EXISTS members (
    space TEXT NOT NULL,
    seq INTEGER NOT NULL,         -- the record's position, from 0
    hash TEXT NOT NULL,
    canonical BLOB NOT NULL,
    PRIMARY KEY (space, seq)
) STRICT;
CREATE TABLE IF NOT EXISTS originals (
    space TEXT NOT NULL,
    hash TEXT NOT NULL,           -- sha256:… of the bytes, kept in kernoid-blob
    PRIMARY KEY (space, hash)
) STRICT;
CREATE TABLE IF NOT EXISTS sent (
    space TEXT NOT NULL,
    kind TEXT NOT NULL,           -- 'event' or 'original'
    id TEXT NOT NULL,             -- its hash
    PRIMARY KEY (space, kind, id)
) STRICT;
";

/// What the core keeps: the events and member records of spaces, the originals that belong to them, settings, and
/// what was sent to a relay. [`Store`] keeps it in SQLite.
pub trait Backend: fmt::Debug + Send {
    /// The spaces with events or member records, in order.
    fn spaces(&self) -> Result<Vec<SpaceId>, StoreError>;

    /// The log of a space: all its events.
    fn load(&self, space: &SpaceId) -> Result<Log, StoreError>;

    /// Stores the events of logs, all or none – one transaction over every space given. Events stored already are
    /// left as they are; returns how many were new.
    fn save(&mut self, logs: &[(&SpaceId, &Log)]) -> Result<usize, StoreError>;

    /// The member records of a space, in order.
    fn records(&self, space: &SpaceId) -> Result<Vec<MemberRecord>, StoreError>;

    /// The member list of a space, every record checked again.
    fn member_list(&self, domain: Domain, space: &SpaceId) -> Result<MemberList, StoreError> {
        MemberList::from_records(domain, space.clone(), &self.records(space)?)
            .map_err(|error| StoreError::Record { space: space.clone(), error: error.to_string() })
    }

    /// Applies a record to the member list of its space and stores it – only if it is the next valid one.
    fn add_record(&mut self, domain: Domain, record: &MemberRecord) -> Result<(), StoreError>;

    /// Notes that an original belongs to a space – its bytes are kept in `kernoid-blob`.
    fn add_original(&self, space: &SpaceId, hash: &Sha256Hash) -> Result<(), StoreError>;

    /// The originals that belong to a space, in order.
    fn originals(&self, space: &SpaceId) -> Result<Vec<Sha256Hash>, StoreError>;

    /// A setting of a space, or of the device when `space` is none.
    fn setting(&self, space: Option<&SpaceId>, key: &str) -> Result<Option<String>, StoreError>;

    /// Sets a setting of a space, or of the device when `space` is none.
    fn set_setting(&self, space: Option<&SpaceId>, key: &str, value: &str) -> Result<(), StoreError>;

    /// The hashes of what was sent to the relay for a space: `kind` is `event` or `original`.
    fn sent(&self, space: &SpaceId, kind: &str) -> Result<BTreeSet<Sha256Hash>, StoreError>;

    /// Notes that something was sent to the relay.
    fn mark_sent(&self, space: &SpaceId, kind: &str, id: &Sha256Hash) -> Result<(), StoreError>;
}

/// Reads stored identities – a space's or a hash.
#[cfg(feature = "sqlite")]
fn parse<T: std::str::FromStr>(id: String) -> Result<T, StoreError> {
    id.parse().map_err(|_| StoreError::Identity(id))
}

/// The store of a device.
#[cfg(feature = "sqlite")]
#[derive(Debug)]
pub struct Store {
    connection: Connection,
}

#[cfg(feature = "sqlite")]
impl Store {
    /// Opens the database file at `path`, creating it if needed.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let connection = Connection::open(path)?;
        connection.execute_batch("PRAGMA journal_mode = WAL;")?;
        Self::prepare(connection)
    }

    /// Opens the database file at `path` encrypted as a whole with SQLCipher under a raw 256-bit `key`, creating it
    /// if needed. A wrong key, or a file that is not encrypted, fails here – with the error of the database ("file is
    /// not a database") – before anything is read.
    #[cfg(feature = "sqlcipher")]
    pub fn open_encrypted(path: &Path, key: &[u8; 32]) -> Result<Self, StoreError> {
        let connection = Connection::open(path)?;
        let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
        // A raw key in hexadecimal: SQLCipher uses it as it is, without deriving it from a passphrase.
        connection.execute_batch(&format!("PRAGMA key = \"x'{hex}'\";"))?;
        connection.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get::<_, i64>(0))?;
        connection.execute_batch("PRAGMA journal_mode = WAL;")?;
        Self::prepare(connection)
    }

    /// A store in memory, gone when dropped – for tests.
    pub fn in_memory() -> Result<Self, StoreError> {
        Self::prepare(Connection::open_in_memory()?)
    }

    /// A store in memory with what `bytes` holds – a whole database as [`Store::to_bytes`] gave it –, brought to this
    /// version. Where a program keeps it elsewhere than in a file: a web page's IndexedDB.
    #[cfg(feature = "serialize")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        let mut connection = Connection::open_in_memory()?;
        connection.deserialize_read_exact(rusqlite::MAIN_DB, bytes, bytes.len(), false)?;
        Self::prepare(connection)
    }

    /// The whole database, to keep it elsewhere than in a file.
    #[cfg(feature = "serialize")]
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, StoreError> {
        Ok(self.connection.serialize(rusqlite::MAIN_DB)?.to_vec())
    }

    fn prepare(connection: Connection) -> Result<Self, StoreError> {
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::Version(version));
        }
        connection.execute_batch(SCHEMA)?;
        // Version 2: the tables of streams (RFC 0012), added beside those of 1.
        connection.execute_batch(streams::SCHEMA)?;
        connection.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
        Ok(Store { connection })
    }

    /// The connection, for a program's own tables beside the core's schema – views to search, for example (0001: no
    /// general SQL layer in the core). They are in the same database, encrypted with it under `sqlcipher`. The core's
    /// own tables (`settings`, `events`, `members`, `originals`, `sent`) are written through the store only.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

#[cfg(feature = "sqlite")]
impl Backend for Store {
    fn spaces(&self) -> Result<Vec<SpaceId>, StoreError> {
        let mut statement =
            self.connection.prepare("SELECT space FROM events UNION SELECT space FROM members ORDER BY space")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|id| parse(id?)).collect()
    }

    fn load(&self, space: &SpaceId) -> Result<Log, StoreError> {
        let mut statement = self.connection.prepare("SELECT canonical FROM events WHERE space = ?1")?;
        let mut rows = statement.query(params![space.as_str()])?;
        let mut log = Log::new();
        while let Some(row) = rows.next()? {
            let canonical: Vec<u8> = row.get(0)?;
            log.receive(&canonical).map_err(|error| StoreError::Event { space: space.clone(), error })?;
        }
        Ok(log)
    }

    fn save(&mut self, logs: &[(&SpaceId, &Log)]) -> Result<usize, StoreError> {
        let transaction = self.connection.transaction()?;
        let mut new = 0;
        {
            let mut insert =
                transaction.prepare("INSERT OR IGNORE INTO events (space, hash, canonical) VALUES (?1, ?2, ?3)")?;
            for (space, log) in logs {
                for hash in log.hashes() {
                    let canonical = log.canonical(hash).expect("a hash of the log");
                    new += insert.execute(params![space.as_str(), hash.to_string(), canonical])?;
                }
            }
        }
        transaction.commit()?;
        Ok(new)
    }

    fn records(&self, space: &SpaceId) -> Result<Vec<MemberRecord>, StoreError> {
        let mut statement = self.connection.prepare("SELECT canonical FROM members WHERE space = ?1 ORDER BY seq")?;
        let rows = statement.query_map(params![space.as_str()], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|canonical| {
            kernoid_base::from_root(&canonical?)
                .map_err(|error| StoreError::Record { space: space.clone(), error: error.to_string() })
        })
        .collect()
    }

    fn add_record(&mut self, domain: Domain, record: &MemberRecord) -> Result<(), StoreError> {
        let mut list = self.member_list(domain, &record.space)?;
        list.apply(record.clone())?;
        let canonical = to_root(record).expect("a record has a canonical encoding");
        self.connection.execute(
            "INSERT INTO members (space, seq, hash, canonical) VALUES (?1, ?2, ?3, ?4)",
            params![record.space.as_str(), record.seq as i64, record.hash().to_string(), canonical],
        )?;
        Ok(())
    }

    fn add_original(&self, space: &SpaceId, hash: &Sha256Hash) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT OR IGNORE INTO originals (space, hash) VALUES (?1, ?2)",
            params![space.as_str(), hash.to_string()],
        )?;
        Ok(())
    }

    fn originals(&self, space: &SpaceId) -> Result<Vec<Sha256Hash>, StoreError> {
        let mut statement = self.connection.prepare("SELECT hash FROM originals WHERE space = ?1 ORDER BY hash")?;
        let rows = statement.query_map(params![space.as_str()], |row| row.get::<_, String>(0))?;
        rows.map(|id| parse(id?)).collect()
    }

    fn setting(&self, space: Option<&SpaceId>, key: &str) -> Result<Option<String>, StoreError> {
        let space = space.map_or("", SpaceId::as_str);
        let value = self
            .connection
            .query_row("SELECT value FROM settings WHERE space = ?1 AND key = ?2", params![space, key], |row| {
                row.get(0)
            })
            .optional()?;
        Ok(value)
    }

    fn set_setting(&self, space: Option<&SpaceId>, key: &str, value: &str) -> Result<(), StoreError> {
        let space = space.map_or("", SpaceId::as_str);
        self.connection.execute(
            "INSERT INTO settings (space, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT (space, key) DO UPDATE SET value = excluded.value",
            params![space, key, value],
        )?;
        Ok(())
    }

    fn sent(&self, space: &SpaceId, kind: &str) -> Result<BTreeSet<Sha256Hash>, StoreError> {
        let mut statement = self.connection.prepare("SELECT id FROM sent WHERE space = ?1 AND kind = ?2")?;
        let rows = statement.query_map(params![space.as_str(), kind], |row| row.get::<_, String>(0))?;
        rows.map(|id| parse(id?)).collect()
    }

    fn mark_sent(&self, space: &SpaceId, kind: &str, id: &Sha256Hash) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT OR IGNORE INTO sent (space, kind, id) VALUES (?1, ?2, ?3)",
            params![space.as_str(), kind, id.to_string()],
        )?;
        Ok(())
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use std::path::PathBuf;

    use kernoid_crypt::{Member, MemberKeys, Rights};
    use kernoid_log::Clock;
    use serde_json::json;

    use super::*;

    fn space(n: u8) -> SpaceId {
        format!("0192f1e4-0000-7000-8000-0000000000{n:02x}").parse().unwrap()
    }

    /// A temporary folder, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("kernoid-spaces-store-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Scratch(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn events_are_kept_per_space_and_survive_reopening() {
        let scratch = Scratch::new("events");
        let file = scratch.0.join("spaces.sqlite");
        let mut log = Log::new();
        let mut clock = Clock::new("laptop".parse().unwrap());
        log.append(&mut clock, 1_000, &json!({"kind": "document_added", "title": "Lease"})).unwrap();
        log.append(&mut clock, 2_000, &json!({"kind": "label_set", "label": "home"})).unwrap();
        {
            let mut store = Store::open(&file).unwrap();
            assert_eq!(store.save(&[(&space(1), &log)]).unwrap(), 2);
            assert_eq!(store.save(&[(&space(1), &log)]).unwrap(), 0);
            store.set_setting(Some(&space(1)), "name", "Home").unwrap();
            store.set_setting(Some(&space(1)), "name", "Household").unwrap();
            store.mark_sent(&space(1), "event", log.hashes().next().unwrap()).unwrap();
        }
        let store = Store::open(&file).unwrap();
        assert_eq!(store.spaces().unwrap(), vec![space(1)]);
        assert_eq!(store.load(&space(1)).unwrap(), log);
        assert!(store.load(&space(2)).unwrap().is_empty());
        assert_eq!(store.setting(Some(&space(1)), "name").unwrap().as_deref(), Some("Household"));
        assert_eq!(store.setting(None, "name").unwrap(), None);
        assert_eq!(store.sent(&space(1), "event").unwrap().len(), 1);
    }

    #[test]
    fn originals_belong_to_spaces() {
        originals(Store::in_memory().unwrap());
    }

    #[test]
    fn member_records_are_stored_only_in_order_and_valid() {
        members(Store::in_memory().unwrap());
    }

    #[test]
    fn events_and_settings_are_kept_per_space() {
        events_and_settings(Store::in_memory().unwrap());
    }

    /// Originals of a space, on any backend.
    pub(crate) fn originals(store: impl Backend) {
        let hash = Sha256Hash::of(b"scan");
        store.add_original(&space(1), &hash).unwrap();
        store.add_original(&space(1), &hash).unwrap();
        assert_eq!(store.originals(&space(1)).unwrap(), vec![hash]);
        assert!(store.originals(&space(2)).unwrap().is_empty());
    }

    /// Member records of a space, on any backend.
    pub(crate) fn members(mut store: impl Backend) {
        let domain = Domain::KERNOID;
        let (laptop, phone) = (MemberKeys::generate(domain), MemberKeys::generate(domain));
        let device = |keys: &MemberKeys, name: &str| Member::device(keys, name.parse().unwrap(), None, Rights::Manage);
        let (first, key) = MemberRecord::found(&space(1), &laptop, vec![device(&laptop, "laptop")]);
        store.add_record(domain, &first).unwrap();
        let list = store.member_list(domain, &space(1)).unwrap();
        let second = list.add(&laptop, &key, vec![device(&phone, "phone")]);
        assert!(matches!(store.add_record(domain, &first), Err(StoreError::NotNext(_))));
        store.add_record(domain, &second).unwrap();
        assert!(matches!(store.add_record(domain, &second), Err(StoreError::NotNext(_))));
        let list = store.member_list(domain, &space(1)).unwrap();
        assert_eq!(list.members().count(), 2);
        assert_eq!(store.spaces().unwrap(), vec![space(1)]);
        assert!(list.keys(&phone).is_ok());
    }

    /// Events, settings and what was sent, on any backend.
    pub(crate) fn events_and_settings(mut store: impl Backend) {
        let mut log = Log::new();
        let mut clock = Clock::new("laptop".parse().unwrap());
        log.append(&mut clock, 1_000, &json!({"kind": "document_added", "title": "Lease"})).unwrap();
        log.append(&mut clock, 2_000, &json!({"kind": "label_set", "label": "home"})).unwrap();
        let mut other = Log::new();
        other.append(&mut clock, 3_000, &json!({"kind": "document_added", "title": "Car"})).unwrap();
        assert_eq!(store.save(&[(&space(1), &log), (&space(2), &other)]).unwrap(), 3);
        assert_eq!(store.save(&[(&space(1), &log)]).unwrap(), 0);
        assert_eq!(store.spaces().unwrap(), vec![space(1), space(2)]);
        assert_eq!(store.load(&space(1)).unwrap(), log);
        assert_eq!(store.load(&space(2)).unwrap(), other);
        assert!(store.load(&space(3)).unwrap().is_empty());
        store.set_setting(Some(&space(1)), "name", "Home").unwrap();
        store.set_setting(Some(&space(1)), "name", "Household").unwrap();
        store.set_setting(None, "device", "laptop").unwrap();
        assert_eq!(store.setting(Some(&space(1)), "name").unwrap().as_deref(), Some("Household"));
        assert_eq!(store.setting(None, "name").unwrap(), None);
        assert_eq!(store.setting(None, "device").unwrap().as_deref(), Some("laptop"));
        let first = *log.hashes().next().unwrap();
        store.mark_sent(&space(1), "event", &first).unwrap();
        store.mark_sent(&space(1), "event", &first).unwrap();
        assert_eq!(store.sent(&space(1), "event").unwrap(), BTreeSet::from([first]));
        assert!(store.sent(&space(1), "original").unwrap().is_empty());
    }

    #[test]
    fn a_later_schema_is_refused() {
        let scratch = Scratch::new("version");
        let file = scratch.0.join("spaces.sqlite");
        Connection::open(&file).unwrap().execute_batch("PRAGMA user_version = 99;").unwrap();
        assert!(matches!(Store::open(&file), Err(StoreError::Version(99))));
    }

    #[cfg(feature = "sqlcipher")]
    #[test]
    fn an_encrypted_store_opens_only_with_its_key() {
        let scratch = Scratch::new("encrypted");
        let file = scratch.0.join("spaces.sqlite");
        let key = [7u8; 32];
        {
            let store = Store::open_encrypted(&file, &key).unwrap();
            store.set_setting(None, "secret", "a word that must not be found").unwrap();
        }
        let bytes = std::fs::read(&file).unwrap();
        assert!(!bytes.windows(b"must not be found".len()).any(|w| w == b"must not be found"));
        assert!(!bytes.starts_with(b"SQLite format 3"));
        assert!(Store::open_encrypted(&file, &[8u8; 32]).is_err());
        assert!(Store::open(&file).is_err());
        let store = Store::open_encrypted(&file, &key).unwrap();
        assert_eq!(store.setting(None, "secret").unwrap().as_deref(), Some("a word that must not be found"));
    }
}
