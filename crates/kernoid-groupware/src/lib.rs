// SPDX-License-Identifier: AGPL-3.0-or-later
//! Calendars and contacts of each account (RFC 0004): calendars with their events, address books with their
//! contacts, in PostgreSQL with the iCalendar and vCard data sealed per tenant, and a journal of changes for CalDAV,
//! CardDAV and JMAP.
//!
//! They live in the account's mail store (`kernoid-mail`): every change takes the store's row, its next modification
//! sequence and counts against its quota. Who may reach which account is decided by the protocols above with
//! [`Groupware::access`]; the functions here act on the account they are given.

mod access;
mod addressbook;
mod calendar;
mod changes;
mod contact;
mod event;
pub mod ical;
mod itip;
mod notification;
mod principal;
#[allow(clippy::all, missing_debug_implementations)]
pub mod scheduling;
pub mod sealed;
mod send;
mod transfer;

use std::sync::Arc;

pub use access::{CollectionAccess, CollectionType, Level, SharedCollection};
pub use addressbook::{AddressBookInfo, AddressBookUpdate, NewAddressBook};
pub use calendar::{CalendarInfo, CalendarUpdate, NewCalendar};
pub use changes::{ObjectType, Sync, prune_changes};
pub use contact::ContactInfo;
pub use event::{EventInfo, Written};
pub use itip::{ScheduleRefusal, Scheduled};
pub use kernoid_mail::Changes;
pub use notification::{NotificationInfo, prune_notifications};
pub use principal::PrincipalInfo;
pub use transfer::Imported;

use kernoid_mail::{Mail, MailError, StoreChange, StoreRead};
use kernoid_store::{PgPool, TenantKeys, crypto};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum GroupwareError {
    #[error("{0} does not exist")]
    NotFound(&'static str),
    #[error("{0}")]
    Invalid(String),
    #[error("the object is larger than {limit} bytes")]
    TooLarge { limit: u64 },
    #[error("the account's quota does not leave room for it")]
    OverQuota,
    /// Another resource of the collection has the same UID (CalDAV `no-uid-conflict`); its resource name.
    #[error("another resource has the same UID")]
    UidConflict(String),
    /// The resource name is taken, or the resource changed since the client read it (`If-Match`,
    /// `If-None-Match`).
    #[error("the resource is not as expected")]
    PreconditionFailed,
    #[error("the default calendar or address book cannot be destroyed")]
    IsDefault,
    #[error("the collection is not empty")]
    NotEmpty,
    /// The state is older than the journal kept (JMAP `cannotCalculateChanges`, DAV `valid-sync-token`).
    #[error("the changes since this state are no longer known")]
    CannotCalculateChanges,
    #[error("the content cannot be read")]
    Unreadable,
    #[error(transparent)]
    Mail(MailError),
    #[error(transparent)]
    Store(#[from] sqlx::Error),
}

impl From<MailError> for GroupwareError {
    fn from(error: MailError) -> Self {
        match error {
            MailError::OverQuota => Self::OverQuota,
            MailError::NotFound(what) => Self::NotFound(what),
            MailError::Store(error) => Self::Store(error),
            other => Self::Mail(other),
        }
    }
}

pub type Result<T> = std::result::Result<T, GroupwareError>;

/// Precondition of a write by resource (`If-Match` / `If-None-Match: *`, JMAP's `ifInState` is the caller's).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Expect {
    #[default]
    Any,
    /// The resource must not exist yet.
    New,
    /// The resource must exist with this ETag (the modification sequence of its last change).
    Version(i64),
}

#[derive(Debug, Clone)]
pub struct Groupware {
    mail: Mail,
    keys: Arc<TenantKeys>,
}

/// What kernoid writes as `PRODID` into what it makes.
pub const PROD_ID: &str = "-//kernoid//kernoid//EN";

/// Default names of what the first use creates (RFC 0004, 2).
const DEFAULT_CALENDAR: &str = "Calendar";
const DEFAULT_ADDRESSBOOK: &str = "Contacts";

impl Groupware {
    pub fn new(mail: Mail, keys: Arc<TenantKeys>) -> Self {
        Self { mail, keys }
    }

    pub fn pool(&self) -> &PgPool {
        self.mail.pool()
    }

    pub fn mail(&self) -> &Mail {
        &self.mail
    }

    /// Starts a change: takes the store's row and creates the default calendar and address book if they are missing.
    async fn change(&self, account: Uuid) -> Result<StoreChange> {
        let mut change = self.mail.begin_change(account).await?;
        let created = sqlx::query_scalar!(
            "INSERT INTO groupware_accounts (account_id) VALUES ($1) ON CONFLICT DO NOTHING RETURNING account_id",
            account,
        )
        .fetch_optional(change.connection())
        .await?;
        if created.is_some() {
            calendar::create_default(&mut change, DEFAULT_CALENDAR).await?;
            addressbook::create_default(&mut change, DEFAULT_ADDRESSBOOK).await?;
        }
        Ok(change)
    }

    /// Starts a read; the first one creates the defaults.
    async fn read(&self, account: Uuid) -> Result<StoreRead> {
        let ready = sqlx::query_scalar!("SELECT 1 AS \"one!\" FROM groupware_accounts WHERE account_id = $1", account)
            .fetch_optional(self.pool())
            .await?;
        if ready.is_none() {
            self.change(account).await?.commit().await?;
        }
        Ok(self.mail.begin_read(account).await?)
    }

    /// The account's state: the modification sequence of its last change, shared with mail (RFC 0004, 2).
    pub async fn state(&self, account: Uuid) -> Result<i64> {
        let read = self.read(account).await?;
        let state = read.modseq();
        read.finish().await?;
        Ok(state)
    }

    /// Seals an iCalendar object or vCard with the tenant's current key, bound to its path (RFC 0004, 3).
    async fn seal(&self, tenant: Uuid, path: &str, text: &str) -> Result<Vec<u8>> {
        let (number, key) = self.keys.current(tenant).await.map_err(|_| GroupwareError::Unreadable)?;
        crypto::seal(&key, number, path, text.as_bytes()).map_err(|_| GroupwareError::Unreadable)
    }

    /// Opens what [`Groupware::seal`] sealed, with the key it names.
    async fn open(&self, tenant: Uuid, path: &str, sealed: &[u8]) -> Result<String> {
        let number = crypto::key_number(sealed).map_err(|_| GroupwareError::Unreadable)?;
        let key = self.keys.get(tenant, number).await.map_err(|_| GroupwareError::Unreadable)?;
        let plain = crypto::open(&key, path, sealed).map_err(|_| GroupwareError::Unreadable)?;
        String::from_utf8(plain).map_err(|_| GroupwareError::Unreadable)
    }
}

/// Where an event's sealed iCalendar object belongs.
fn event_path(tenant: Uuid, account: Uuid, event: Uuid) -> String {
    format!("tenants/{tenant}/calendar/{account}/{event}")
}

/// Where a contact's sealed vCard belongs.
fn contact_path(tenant: Uuid, account: Uuid, contact: Uuid) -> String {
    format!("tenants/{tenant}/contacts/{account}/{contact}")
}

/// Checks a resource name a client chose: a path segment without `/`, not `.` or `..`.
fn check_resource_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 255 || name == "." || name == ".." || name.contains(['/', '\0']) {
        return Err(GroupwareError::Invalid("not a valid resource name".into()));
    }
    Ok(())
}

/// Checks the name of a calendar or address book in a home: a resource name that the scheduling collections and
/// shared collections do not use (RFC 0004, 8.1).
fn check_collection_name(name: &str) -> Result<()> {
    check_resource_name(name)?;
    if matches!(name, "inbox" | "outbox") || name.starts_with("shared-") {
        return Err(GroupwareError::Invalid(format!("{name} is reserved")));
    }
    Ok(())
}

/// The resource name of an object made through JMAP: its UID if that is a safe path segment, else its id.
pub fn resource_name(uid: &str, id: Uuid, extension: &str) -> String {
    let safe = uid.len() <= 200 && uid.chars().all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c));
    if safe && !uid.starts_with('.') { format!("{uid}.{extension}") } else { format!("{id}.{extension}") }
}
