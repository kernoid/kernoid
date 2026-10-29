// SPDX-License-Identifier: AGPL-3.0-or-later
//! JMAP (RFC 8620) and JMAP Mail (RFC 8621) on the mail store (RFC 0002, 11.1): the session object, the API's
//! requests with result references, the mail methods, blobs; calendars and contacts (RFC 0004, 8.2) and files
//! (RFC 0005, 8). HTTP, authentication and the push stream are the server's; this crate takes a caller that is logged
//! in already.

pub mod blob;
mod calendars;
mod contacts;
mod email;
mod email_set;
mod files;
mod js;
mod mailbox;
mod other;
mod principals;
mod query;
mod request;

use kernoid_mail::Mail;
use serde_json::{Value, json};
use uuid::Uuid;

pub use blob::{BlobId, Download};
pub use files::FileDownload;
pub use request::RequestError;

pub const CORE: &str = "urn:ietf:params:jmap:core";
pub const MAIL: &str = "urn:ietf:params:jmap:mail";
pub const SUBMISSION: &str = "urn:ietf:params:jmap:submission";
pub const CALENDARS: &str = "urn:ietf:params:jmap:calendars";
pub const CONTACTS: &str = "urn:ietf:params:jmap:contacts";
pub const FILENODE: &str = "urn:ietf:params:jmap:filenode";
pub const PRINCIPALS: &str = "urn:ietf:params:jmap:principals";
/// JMAP over WebSocket (RFC 8887).
pub const WEBSOCKET: &str = "urn:ietf:params:jmap:websocket";
/// kernoid's own: earlier contents of files (`FileVersion/get`, RFC 0005, 6).
pub const FILE_VERSIONS: &str = "https://kernoid.dev/jmap/file-versions";

/// Limits announced in the session and kept by the API.
pub const MAX_SIZE_REQUEST: usize = 10 * 1024 * 1024;
pub const MAX_CALLS_IN_REQUEST: usize = 32;
pub const MAX_OBJECTS_IN_GET: usize = 500;
pub const MAX_OBJECTS_IN_SET: usize = 500;

/// Who calls: an account, logged in, with the services it has (RFC 0003, 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub account: Uuid,
    pub tenant: Uuid,
    /// The account's login name.
    pub username: String,
    /// Mail, and with it calendars and contacts.
    pub mail: bool,
    pub files: bool,
}

/// JMAP for one installation.
#[derive(Debug, Clone)]
pub struct Jmap {
    mail: Mail,
    /// Largest upload: the larger of `mail.max_message_size` and `files.max_file_size`.
    max_size: u64,
    /// How long submitted mail is tried (`smtp.queue_days`).
    queue_lifetime: chrono::Duration,
    /// Calendars and contacts (RFC 0004, 8.2), where the installation has them.
    groupware: Option<kernoid_groupware::Groupware>,
    /// Files (RFC 0005, 8), where the installation has them.
    files: Option<kernoid_files::Files>,
    /// Grants on files and the tenant's people and groups (RFC 0005, 11).
    identity: Option<kernoid_identity::Identity>,
}

impl Jmap {
    pub fn new(mail: Mail, max_size: u64, queue_lifetime: chrono::Duration) -> Self {
        Self { mail, max_size, queue_lifetime, groupware: None, files: None, identity: None }
    }

    pub fn with_identity(mut self, identity: kernoid_identity::Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    pub fn with_files(mut self, files: kernoid_files::Files) -> Self {
        self.files = Some(files);
        self
    }

    pub fn with_groupware(mut self, groupware: kernoid_groupware::Groupware) -> Self {
        self.groupware = Some(groupware);
        self
    }

    /// Largest upload, in bytes.
    pub fn max_size(&self) -> u64 {
        self.max_size
    }

    pub fn mail(&self) -> &Mail {
        &self.mail
    }

    /// The session object (RFC 8620, 2) for `caller`, with URLs below `base` (`https://host`): its own account and
    /// those shared with it (RFC 0002, 12.2), with the capabilities of the services it has.
    pub async fn session(&self, caller: &Caller, base: &str) -> Result<Value, SessionError> {
        let own = caller.account.to_string();
        let mut accounts = serde_json::Map::new();
        let mut primary = serde_json::Map::new();
        if caller.mail {
            accounts
                .insert(own.clone(), self.account_object(&caller.username, &kernoid_mail::Access::own(caller.account)));
            for store in self.mail.shared_with(caller.account).await? {
                let access = self.mail.access(caller.account, store.owner).await?;
                if access.any() {
                    accounts.insert(store.owner.to_string(), self.account_object(&store.address, &access));
                }
            }
            primary.insert(MAIL.into(), json!(own));
            primary.insert(SUBMISSION.into(), json!(own));
        }
        // Calendars and address books: the own account has both; one that shares some has those (RFC 0004, 9).
        if caller.mail
            && let Some(groupware) = &self.groupware
        {
            add_groupware(accounts.get_mut(&own), true, true, true);
            primary.insert(CALENDARS.into(), json!(own));
            primary.insert(CONTACTS.into(), json!(own));
            for shared in groupware.shared_with(caller.account).await.unwrap_or_default() {
                let key = shared.owner.to_string();
                let entry = accounts.entry(key).or_insert_with(|| {
                    json!({
                        "name": shared.owner_address.clone().unwrap_or_else(|| shared.owner_name.clone()),
                        "isPersonal": false,
                        "isReadOnly": true,
                        "accountCapabilities": {},
                    })
                });
                let calendar = shared.collection_type == kernoid_groupware::CollectionType::Calendar;
                add_groupware(Some(entry), calendar, !calendar, false);
                if shared.level >= kernoid_groupware::Level::Write {
                    entry["isReadOnly"] = json!(false);
                }
            }
        }
        // Files: the own store, and those shared with the caller – other accounts' and the tenant's drives (RFC 0005,
        // 11, 12).
        if let Some(files) = &self.files {
            if caller.files {
                let entry = accounts.entry(own.clone()).or_insert_with(|| {
                    json!({ "name": caller.username, "isPersonal": true, "isReadOnly": false, "accountCapabilities": {} })
                });
                entry["accountCapabilities"][FILENODE] =
                    files::capability(&kernoid_files::FileAccess::own(caller.account));
                entry["accountCapabilities"][FILE_VERSIONS] = json!({});
                primary.insert(FILENODE.into(), json!(own));
                primary.insert(FILE_VERSIONS.into(), json!(own));
            }
            for store in files.shared_with(caller.account).await? {
                let access = files.access(caller.account, store.owner).await?;
                let entry = accounts.entry(store.owner.to_string()).or_insert_with(|| {
                    json!({ "name": store.name, "isPersonal": false, "isReadOnly": true, "accountCapabilities": {} })
                });
                entry["accountCapabilities"][FILENODE] = files::capability(&access);
                entry["accountCapabilities"][FILE_VERSIONS] = json!({});
                let writes = access.store.contains(kernoid_files::Rights::ADD)
                    || access.nodes.values().any(|rights| {
                        rights.contains(kernoid_files::Rights::ADD) || rights.contains(kernoid_files::Rights::WRITE)
                    });
                if writes {
                    entry["isReadOnly"] = json!(false);
                }
                if store.drive {
                    entry["kernoid:drive"] = json!(true);
                }
            }
        }
        if self.identity.is_some() {
            let entry = accounts.entry(own.clone()).or_insert_with(|| {
                json!({ "name": caller.username, "isPersonal": true, "isReadOnly": false, "accountCapabilities": {} })
            });
            entry["accountCapabilities"][PRINCIPALS] = json!({ "currentUserPrincipalId": own });
            primary.insert(PRINCIPALS.into(), json!(own));
        }
        let mut capabilities = json!({
            CORE: {
                "maxSizeUpload": self.max_size,
                "maxConcurrentUpload": 4,
                "maxSizeRequest": MAX_SIZE_REQUEST,
                "maxConcurrentRequests": 4,
                "maxCallsInRequest": MAX_CALLS_IN_REQUEST,
                "maxObjectsInGet": MAX_OBJECTS_IN_GET,
                "maxObjectsInSet": MAX_OBJECTS_IN_SET,
                "collationAlgorithms": ["i;ascii-casemap", "i;unicode-casemap"],
            },
        });
        if caller.mail {
            for capability in [MAIL, SUBMISSION, CALENDARS, CONTACTS] {
                capabilities[capability] = json!({});
            }
        }
        if self.files.is_some() {
            capabilities[FILENODE] = json!({});
            capabilities[FILE_VERSIONS] = json!({});
        }
        if self.identity.is_some() {
            capabilities[PRINCIPALS] = json!({});
        }
        // RFC 8887: requests and push over one WebSocket.
        let websocket = base.replacen("https://", "wss://", 1).replacen("http://", "ws://", 1);
        capabilities[WEBSOCKET] = json!({ "url": format!("{websocket}/jmap/ws"), "supportsPush": true });
        Ok(json!({
            "capabilities": capabilities,
            "accounts": accounts,
            "primaryAccounts": primary,
            "username": caller.username,
            "apiUrl": format!("{base}/jmap/api"),
            "downloadUrl": format!("{base}/jmap/download/{{accountId}}/{{blobId}}/{{name}}?accept={{type}}"),
            "uploadUrl": format!("{base}/jmap/upload/{{accountId}}/"),
            "eventSourceUrl": format!("{base}/jmap/eventsource?types={{types}}&closeafter={{closeafter}}&ping={{ping}}"),
            "state": self.session_state(caller).await?,
        }))
    }

    /// The session's state: the mail store's for an account with mail, else the file store's.
    pub(crate) async fn session_state(&self, caller: &Caller) -> Result<String, SessionError> {
        if caller.mail {
            return Ok(self.mail.state(caller.account).await?.to_string());
        }
        match &self.files {
            Some(files) if caller.files => Ok(files.state(caller.account).await?.to_string()),
            _ => Ok("0".into()),
        }
    }

    fn account_object(&self, name: &str, access: &kernoid_mail::Access) -> Value {
        let mut capabilities = serde_json::Map::new();
        capabilities.insert(
            MAIL.into(),
            json!({
                "maxMailboxesPerEmail": null,
                "maxMailboxDepth": null,
                "maxSizeMailboxName": 255,
                "maxSizeAttachmentsPerEmail": self.max_size,
                "emailQuerySortOptions": query::SORT_PROPERTIES,
                "mayCreateTopLevelMailbox": access.store.contains(kernoid_mail::Rights::CREATE),
            }),
        );
        if access.send_as {
            capabilities.insert(SUBMISSION.into(), json!({ "maxDelayedSend": 0, "submissionExtensions": {} }));
        }
        json!({
            "name": name,
            "isPersonal": access.owned,
            "isReadOnly": !access.may_change(),
            "accountCapabilities": capabilities,
        })
    }

    pub fn groupware(&self) -> Option<&kernoid_groupware::Groupware> {
        self.groupware.as_ref()
    }

    /// The accounts whose changes the caller hears of: its own and those whose mail or files are shared with it.
    pub async fn watched(&self, caller: &Caller) -> Result<Vec<Uuid>, SessionError> {
        let mut accounts = vec![caller.account];
        if caller.mail {
            accounts.extend(self.mail.shared_with(caller.account).await?.into_iter().map(|store| store.owner));
        }
        if let Some(files) = &self.files {
            for store in files.shared_with(caller.account).await? {
                if !accounts.contains(&store.owner) {
                    accounts.push(store.owner);
                }
            }
        }
        Ok(accounts)
    }

    /// A `StateChange` (RFC 8620, 7.1) for `accounts` at their current states: mail, calendars and contacts of
    /// accounts the caller reaches as mail, files of those whose files it reaches.
    pub async fn state_change(&self, caller: &Caller, accounts: &[Uuid]) -> Result<Value, SessionError> {
        let mut changed = serde_json::Map::new();
        let shared_mail: Vec<Uuid> = match caller.mail {
            true => self.mail.shared_with(caller.account).await?.into_iter().map(|store| store.owner).collect(),
            false => Vec::new(),
        };
        for account in accounts {
            let own = *account == caller.account;
            let mut types = serde_json::Map::new();
            if caller.mail && (own || shared_mail.contains(account)) {
                let state = json!(self.mail.state(*account).await?.to_string());
                for kind in [
                    "Mailbox",
                    "Email",
                    "Thread",
                    "EmailDelivery",
                    "EmailSubmission",
                    "Calendar",
                    "CalendarEvent",
                    "CalendarEventNotification",
                    "AddressBook",
                    "ContactCard",
                ] {
                    types.insert(kind.into(), state.clone());
                }
            }
            if let Some(files) = &self.files
                && (own && caller.files || !own && files.access(caller.account, *account).await?.any())
            {
                types.insert("FileNode".into(), json!(files.state(*account).await?.to_string()));
            }
            changed.insert(account.to_string(), Value::Object(types));
        }
        Ok(json!({ "@type": "StateChange", "changed": changed }))
    }
}

/// Why the session or its states could not be read.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Mail(#[from] kernoid_mail::MailError),
    #[error(transparent)]
    Files(#[from] kernoid_files::FilesError),
}

/// Adds the calendar and contacts capabilities to an account object of the session (draft-ietf-jmap-calendars;
/// RFC 9610, 1.5).
fn add_groupware(account: Option<&mut Value>, calendars: bool, contacts: bool, owned: bool) {
    let Some(account) = account else { return };
    let capabilities = &mut account["accountCapabilities"];
    if calendars {
        capabilities[CALENDARS] = json!({
            "maxCalendarsPerEvent": 1,
            "minDateTime": "0001-01-01T00:00:00Z",
            "maxDateTime": "9999-12-31T23:59:59Z",
            "maxExpandedQueryDuration": "P400D",
            "maxParticipantsPerEvent": null,
            "mayCreateCalendar": owned,
        });
    }
    if contacts {
        capabilities[CONTACTS] = json!({ "maxAddressBooksPerCard": 1, "mayCreateAddressBook": owned });
    }
}
