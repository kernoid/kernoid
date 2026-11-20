// SPDX-License-Identifier: MIT
//! The API of a logged-in account, as Dart sees it: plain records in, plain records out. Every call runs on one tokio
//! runtime of the process; Dart awaits it. Secret keys stay here – Dart sees whether a key is unlocked, never the key.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, LazyLock};

use flutter_rust_bridge::frb;

use crate::frb_generated::StreamSink;
use tokio::sync::Mutex;

use kernoid_client::e2e::{E2e, Outgoing, Plan};
use kernoid_client::{self as client, Client, calendars, contacts, files, mail, reply};

pub(crate) static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("kernoid")
        .enable_all()
        .build()
        .expect("a tokio runtime")
});

/// Runs a future on the runtime, whichever executor awaits it.
async fn run<T: Send + 'static>(
    future: impl Future<Output = client::Result<T>> + Send + 'static,
) -> Result<T, KernoidError> {
    match RUNTIME.spawn(future).await {
        Ok(result) => result.map_err(KernoidError::from),
        Err(error) => Err(KernoidError { unauthorized: false, message: error.to_string() }),
    }
}

/// An error for people: the message is shown as it is.
#[derive(Debug, Clone)]
pub struct KernoidError {
    /// The address or the app password is wrong – ask again.
    pub unauthorized: bool,
    pub message: String,
}

impl From<client::Error> for KernoidError {
    fn from(error: client::Error) -> Self {
        KernoidError { unauthorized: matches!(error, client::Error::Unauthorized), message: error.to_string() }
    }
}

#[frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();
}

/// A logged-in account and the stores it reaches.
#[frb(opaque)]
#[derive(Debug)]
pub struct Kernoid {
    client: Client,
    e2e: Arc<Mutex<E2e>>,
    /// Decrypted messages by email id, for saving their attachments; forgotten when the key is locked.
    opened: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    /// For a login with OpenID Connect: its tokens and the task that renews them before the access token expires.
    login: Option<Arc<Login>>,
    /// Vaults on spaces (RFC 0010, 5), once the app opened their store on this device ([`Kernoid::open_vaults`]).
    vaults: Arc<std::sync::Mutex<Option<client::e2e::Vaults>>>,
    /// Where the codes of vaults entered go for the shell, and their key ([`Kernoid::share_vaults_with_shell`]).
    shell_codes: Arc<std::sync::Mutex<Option<CodesFile>>>,
}

/// A login with OpenID Connect while the app runs: the server, the tokens – renewed in the background –, and who
/// hears of each renewal (to keep the new refresh token).
struct Login {
    server: String,
    /// For a shell's login: where its vaults on spaces are kept, and the codes the app hands it (RFC 0010, 5).
    shell_vaults: std::sync::Mutex<Option<ShellVaults>>,
    tokens: std::sync::Mutex<client::oidc::Tokens>,
    watcher: std::sync::Mutex<Option<StreamSink<String>>>,
    renewal: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for Login {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Login").field("server", &self.server).finish_non_exhaustive()
    }
}

/// What the app keeps in the system's key store to stay signed in: the server and the SDK's saved login (the refresh
/// token, never the access token).
#[derive(serde::Serialize, serde::Deserialize)]
struct Kept {
    server: String,
    login: client::oidc::Saved,
    /// A shell's vaults on spaces – kept with its login in the system's key store, so that the shells need nothing new.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vaults: Option<ShellVaults>,
}

/// What a shell (the system's file manager) needs for vaults on spaces: its own sealed store – a device of its own,
/// written by it alone –, the sealed file of codes the app writes for it, and the key of both (hexadecimal).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ShellVaults {
    pub store: String,
    pub codes: String,
    pub key: String,
}

impl ShellVaults {
    pub(crate) fn key(&self) -> Option<[u8; 32]> {
        let bytes: Vec<u8> = (0..self.key.len())
            .step_by(2)
            .filter_map(|i| self.key.get(i..i + 2).and_then(|pair| u8::from_str_radix(pair, 16).ok()))
            .collect();
        bytes.try_into().ok()
    }
}

impl Login {
    fn kept(&self) -> Option<String> {
        let saved = self.tokens.lock().ok()?.saved()?;
        let vaults = self.shell_vaults.lock().ok()?.clone();
        serde_json::to_string(&Kept { server: self.server.clone(), login: saved, vaults }).ok()
    }
}

/// Where the app writes codes for the shell, and their key.
type CodesFile = (String, [u8; 32]);

/// The codes the app hands a shell: vault directory → space and recovery code (hexadecimal), sealed.
pub(crate) type ShellCodes = std::collections::BTreeMap<String, (String, String)>;

pub(crate) fn read_codes(path: &str, key: &[u8; 32]) -> ShellCodes {
    std::fs::read(path)
        .ok()
        .and_then(|sealed| kernoid_vault::sealed::open(key, &sealed).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Drop for Kernoid {
    fn drop(&mut self) {
        self.stop_renewing();
    }
}

/// A login with OpenID Connect begun: the URL to open in the system's browser, and what finishing it needs.
#[frb(opaque)]
#[derive(Debug)]
pub struct OidcLogin {
    login: client::oidc::Login,
    server: String,
}

impl OidcLogin {
    #[frb(sync, getter)]
    pub fn url(&self) -> String {
        self.login.url.clone()
    }
}

fn options() -> client::Options {
    client::Options { allow_http: false, user_agent: concat!("kernoid-app/", env!("CARGO_PKG_VERSION")).into() }
}

/// A mail account the user reaches: their own, or a shared mailbox granted to them.
#[derive(Debug, Clone)]
pub struct MailAccount {
    pub id: String,
    pub name: String,
    /// The user's own.
    pub is_personal: bool,
    pub read_only: bool,
}

#[derive(Debug, Clone)]
pub struct Mailbox {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub role: Option<String>,
    pub total: i64,
    pub unread: i64,
}

#[derive(Debug, Clone)]
pub struct Address {
    pub name: Option<String>,
    pub email: String,
}

#[derive(Debug, Clone)]
pub struct EmailSummary {
    pub id: String,
    pub from: Vec<Address>,
    pub subject: String,
    pub preview: String,
    /// RFC 3339, UTC.
    pub received_at: String,
    pub seen: bool,
    pub flagged: bool,
    pub has_attachment: bool,
    /// End-to-end encrypted.
    pub encrypted: bool,
    /// Encrypted, and the key that opens it is not unlocked here: subject and preview are not known.
    pub locked: bool,
}

#[derive(Debug, Clone)]
pub struct EmailPage {
    pub emails: Vec<EmailSummary>,
    pub total: i64,
}

/// A file attached to an email: on the server (`blob_id`), or inside a decrypted message (`part_index`).
#[derive(Debug, Clone)]
pub struct Attachment {
    pub blob_id: Option<String>,
    pub part_index: Option<u32>,
    pub name: String,
    pub media_type: String,
    pub size: i64,
}

#[derive(Debug, Clone)]
pub struct Email {
    pub id: String,
    pub from: Vec<Address>,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    pub subject: String,
    pub received_at: String,
    pub text: String,
    /// The HTML of the email, when it has HTML: shown by the app without running anything or loading what it links.
    pub html: Option<String>,
    pub attachments: Vec<Attachment>,
    pub encrypted: bool,
    pub locked: bool,
    pub signed: bool,
    /// The signature is valid and by a key of the sender.
    pub verified: bool,
}

#[derive(Debug, Clone)]
pub struct FileStore {
    pub account_id: String,
    pub name: String,
    pub is_personal: bool,
    /// A drive: folders the tenant owns, which the user has rights in.
    pub is_drive: bool,
    /// Whether the user may add at the top of the store.
    pub may_create_top_level: bool,
}

#[derive(Debug, Clone)]
pub struct FileNode {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub is_directory: bool,
    pub role: Option<String>,
    pub blob_id: Option<String>,
    pub size: i64,
    pub media_type: Option<String>,
    pub modified: Option<String>,
    /// The user's rights on it, as the server says them – `false` when it says none (a file takes those of where it
    /// lies).
    pub has_rights: bool,
    pub may_read: bool,
    pub may_add_children: bool,
    pub may_rename: bool,
    pub may_delete: bool,
    pub may_modify_content: bool,
    pub may_share: bool,
    /// With whom a directory is shared.
    pub shares: Vec<FileShare>,
    /// The vault it lies in – its own id on a vault (RFC 0006, 6).
    pub vault: Option<String>,
    /// A vault itself: a directory whose content only its members read.
    pub is_vault: bool,
    /// In a vault whose key is not at hand here: the name is an id.
    pub locked: bool,
    /// A vault on a space (RFC 0010, 5): its space – what is in it lives there, listed with [`Kernoid::vault_entries`].
    pub space: Option<String>,
}

/// Something in a directory of a vault on a space.
#[derive(Debug, Clone)]
pub struct VaultEntry {
    pub id: String,
    pub name: String,
    pub is_directory: bool,
    /// In the vault's trash (still shown in its directory there).
    pub trashed: bool,
    pub size: i64,
    pub media_type: Option<String>,
    pub modified: Option<String>,
}

/// A person or group a directory is shared with, and how far: `read`, `edit` or `full` (edit and share).
#[derive(Debug, Clone)]
pub struct FileShare {
    pub principal_id: String,
    pub level: String,
}

/// A person or group of the tenant (RFC 9670): `individual` or `group`.
#[derive(Debug, Clone)]
pub struct Principal {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub email: Option<String>,
}

/// A node found by a search, with the names of the directories above it.
#[derive(Debug, Clone)]
pub struct FoundFile {
    pub node: FileNode,
    pub path: Vec<FileNode>,
}

/// The content of a file: the current one or an earlier version.
#[derive(Debug, Clone)]
pub struct FileVersion {
    pub id: String,
    pub blob_id: String,
    pub size: i64,
    pub media_type: Option<String>,
    pub modified: Option<String>,
    pub created: Option<String>,
    pub is_current: bool,
}

/// A link for people without an account: `view`, `add` (view and add) or `drop` (only add).
#[derive(Debug, Clone)]
pub struct FileLink {
    pub id: String,
    pub mode: String,
    pub expires: Option<String>,
    pub has_password: bool,
    pub created: Option<String>,
}

/// The vacation response (RFC 8621, 8): on or off, from and until when – local times as `YYYY-MM-DDTHH:MM` –, its
/// subject and text.
#[derive(Debug, Clone)]
pub struct VacationResponse {
    pub on: bool,
    pub from: Option<String>,
    pub until: Option<String>,
    pub subject: String,
    pub text: String,
}

/// The language kernoid writes its emails to the account in: its own choice (none follows the tenant's), the one used,
/// and those there are.
#[derive(Debug, Clone)]
pub struct AccountLanguage {
    pub language: Option<String>,
    pub used: String,
    pub available: Vec<String>,
}

/// How the account writes mail and how long its Trash keeps it.
#[derive(Debug, Clone)]
pub struct MailSettings {
    /// Days the Trash keeps an email; none follows the tenant.
    pub trash_retention_days: Option<i32>,
    /// The tenant's days, only read; none keeps them until they are deleted.
    pub tenant_trash_retention_days: Option<i32>,
    /// The address new emails come from; none is the account's own.
    pub default_from: Option<String>,
    /// Seconds an email waits, to be taken back (0 to 30).
    pub undo_send_seconds: i32,
    /// The addresses the account may send from.
    pub senders: Vec<String>,
}

/// How far an upload is: the file (numbered in the order sent, and its path) and its bytes.
#[derive(Debug, Clone)]
pub struct UploadProgress {
    pub index: u32,
    /// The file's path below the target, `/` between names.
    pub name: String,
    pub sent: i64,
    pub total: i64,
}

/// A message being written: to whom, about what, the text, the thread it answers, and what is attached – files of
/// another message (forwarding) and files of the device.
#[derive(Debug, Clone)]
pub struct EmailDraft {
    /// Addresses as people type them: `Name <a@b>, c@d`.
    pub to: String,
    pub cc: String,
    pub bcc: String,
    pub subject: String,
    pub text: String,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    /// On the server already: the attachments of a message forwarded.
    pub attachments: Vec<DraftAttachment>,
    /// The attachments of an end-to-end encrypted message forwarded – decrypted here, held in memory, never on disk.
    pub parts: Vec<DraftPart>,
    /// Paths of files on the device.
    pub files: Vec<String>,
}

/// An attachment of a message decrypted here, forwarded: read again from that message when the draft is sent.
#[derive(Debug, Clone)]
pub struct DraftPart {
    pub email_id: String,
    /// An attachment inside a message decrypted here …
    pub part_index: Option<u32>,
    /// … or one on the server in another account – a shared mailbox's –, fetched again when the draft is sent.
    pub account_id: Option<String>,
    pub blob_id: Option<String>,
    pub name: String,
    pub media_type: String,
    pub size: i64,
}

#[derive(Debug, Clone)]
pub struct DraftAttachment {
    pub blob_id: String,
    pub name: String,
    pub media_type: String,
    pub size: i64,
}

/// The words around a quote, in the user's language: `{date}` and `{who}` are filled in.
#[derive(Debug, Clone)]
pub struct ReplyPhrases {
    pub wrote: String,
    pub forwarded: String,
    pub from: String,
    pub date: String,
    pub subject: String,
    pub to: String,
    /// The format of a date (strftime, as Jiff reads it), e.g. `%d.%m.%Y %H:%M`.
    pub date_format: String,
}

/// A calendar the account reaches: its own or one shared with it.
#[derive(Debug, Clone)]
pub struct Calendar {
    pub id: String,
    pub account_id: String,
    pub name: String,
    /// Events can be made and changed in it.
    pub writable: bool,
    /// CSS colour, if the calendar has one.
    pub color: Option<String>,
    /// The owner's name, for a calendar shared with the account.
    pub shared_by: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Participant {
    pub name: Option<String>,
    pub email: Option<String>,
    /// `needs-action`, `accepted`, `tentative` or `declined`.
    pub status: Option<String>,
}

/// An event, or one instance of a recurring one.
#[derive(Debug, Clone)]
pub struct Event {
    pub id: String,
    /// The event changes go to: for an instance, the recurring event it is of.
    pub event_id: String,
    /// For an instance of a recurring event: which one it is, to change or delete it alone.
    pub recurrence_id: Option<String>,
    pub account_id: String,
    pub calendar_ids: Vec<String>,
    pub title: String,
    /// RFC 3339, UTC; for an all-day event its first day, `YYYY-MM-DD`, in no time zone.
    pub start: Option<String>,
    /// RFC 3339, UTC; for an all-day event the day after its last, `YYYY-MM-DD`.
    pub end: Option<String>,
    pub all_day: bool,
    pub location: Option<String>,
    pub description: Option<String>,
    /// The organizer called it off.
    pub cancelled: bool,
    pub recurring: bool,
    pub participants: Vec<Participant>,
    /// The account is invited (not the organizer): its key among the participants and its answer so far.
    pub invitation_key: Option<String>,
    pub my_status: Option<String>,
    /// The account organizes it (or nobody does): it may change and delete it.
    pub editable: bool,
}

/// An event as the user writes it – to make one, or to change one (a recurring event as a whole).
#[derive(Debug, Clone)]
pub struct EventDraft {
    pub calendar_id: String,
    pub account_id: String,
    pub title: String,
    pub all_day: bool,
    /// Local times, `YYYY-MM-DDTHH:MM:SS`, in the device's time zone; for an all-day event the end is its last day.
    pub start: String,
    pub end: String,
    pub location: String,
    pub description: String,
    /// Addresses of the people invited – they get an invitation by email.
    pub participants: Vec<String>,
    /// `daily`, `weekly`, `monthly`, `yearly` or none.
    pub repeat: Option<String>,
}

/// An address or number with its labels: `work`, `private`, and for a phone what it is (`mobile`, `fax` …).
#[derive(Debug, Clone)]
pub struct LabelledValue {
    pub value: String,
    pub labels: Vec<String>,
}

/// A contact as the user writes it.
#[derive(Debug, Clone)]
pub struct ContactDraft {
    pub name: String,
    pub organization: String,
    pub emails: Vec<LabelledValue>,
    pub phones: Vec<LabelledValue>,
    pub note: String,
}

/// A contact card of one of the account's address books.
#[derive(Debug, Clone)]
pub struct Contact {
    pub id: String,
    pub account_id: String,
    pub name: String,
    pub organization: Option<String>,
    pub emails: Vec<LabelledValue>,
    pub phones: Vec<LabelledValue>,
    pub notes: Vec<String>,
}

/// What a round of keeping a folder in step did (kernoid-sync).
#[derive(Debug, Clone, Default)]
pub struct SyncReport {
    pub downloaded: u32,
    pub uploaded: u32,
    pub deleted_here: u32,
    pub deleted_there: u32,
    pub directories: u32,
    pub moved: u32,
    /// Files changed on both sides: the local version was kept as a copy beside the server's.
    pub conflicts: Vec<String>,
    /// Paths whose action failed, with why – tried again in the next round.
    pub failed: Vec<String>,
    /// Names of the store the folder's file system cannot hold.
    pub skipped: Vec<String>,
    /// Vaults left as they are: the account's key is locked, or no member gave it the vault's key.
    pub locked: u32,
}

/// Where end-to-end encryption stands for this account (RFC 0006).
#[derive(Debug, Clone)]
pub struct E2eStatus {
    /// The server has kernoid's end-to-end extension.
    pub available: bool,
    pub has_key: bool,
    pub unlocked: bool,
    pub fingerprint: Option<String>,
    /// `pqc` or `compatible`.
    pub kind: Option<String>,
    /// Mail is encrypted on arrival as well (an account setting for other software, RFC 0006, 5.1).
    pub mail_on_arrival: bool,
    /// The tenant can recover the key (RFC 0006, 8.2).
    pub tenant_recovers: bool,
    /// Vaults can be made: the server has them and the tenant does not forbid them (RFC 0006, 6).
    pub vaults_allowed: bool,
}

/// How a message to these recipients would go out.
#[derive(Debug, Clone)]
pub struct SendPlan {
    pub encrypted: bool,
    /// Why not, when it is not.
    pub reason: Option<String>,
}

/// The width HTML is set to as text: wide, so that the app wraps it, not the SDK.
const TEXT_WIDTH: usize = 10_000;

fn addresses(list: Option<Vec<mail::EmailAddress>>) -> Vec<Address> {
    list.unwrap_or_default().into_iter().map(|a| Address { name: a.name, email: a.email }).collect()
}

/// Local times as the app reads and writes them.
const LOCAL_TIME: &str = "%Y-%m-%dT%H:%M";

fn file_node(n: files::FileNode) -> FileNode {
    let rights = n.my_rights;
    let r = rights.unwrap_or_default();
    let shares = n
        .share_with
        .as_ref()
        .map(|with| {
            with.iter()
                .map(|(principal, rights)| FileShare {
                    principal_id: principal.clone(),
                    level: match files::Level::of(rights) {
                        files::Level::Full => "full",
                        files::Level::Edit => "edit",
                        files::Level::Read => "read",
                    }
                    .into(),
                })
                .collect()
        })
        .unwrap_or_default();
    let is_vault = n.vault.as_deref() == Some(n.id.as_str());
    FileNode {
        is_directory: n.is_directory(),
        id: n.id,
        parent_id: n.parent_id,
        name: n.name,
        role: n.role,
        blob_id: n.blob_id,
        size: count(n.size.unwrap_or_default()),
        media_type: n.media_type,
        modified: n.modified,
        has_rights: rights.is_some(),
        may_read: r.may_read,
        may_add_children: r.may_add_children,
        may_rename: r.may_rename,
        may_delete: r.may_delete,
        may_modify_content: r.may_modify_content,
        may_share: r.may_share,
        shares,
        is_vault,
        vault: n.vault,
        locked: n.locked,
        space: n.space,
    }
}

/// What the SDK needs of a node in a vault to act on it.
fn vault_node(vault: String, id: String, blob_id: Option<String>) -> files::FileNode {
    files::FileNode {
        kind: if blob_id.is_some() { "File" } else { "Directory" }.into(),
        id,
        parent_id: None,
        name: String::new(),
        role: None,
        blob_id,
        size: None,
        media_type: None,
        modified: None,
        my_rights: None,
        share_with: None,
        vault: Some(vault),
        vault_key: None,
        encrypted_name: None,
        space: None,
        locked: false,
    }
}

fn principal(p: files::Principal) -> Principal {
    Principal { id: p.id, kind: p.kind, name: p.name, email: p.email }
}

fn link_mode_name(mode: files::LinkMode) -> &'static str {
    match mode {
        files::LinkMode::View => "view",
        files::LinkMode::Add => "add",
        files::LinkMode::Drop => "drop",
    }
}

/// One step of an upload: a directory to have (its names from the target down) or a file to send into one.
enum Step {
    Directory(Vec<String>),
    File(Vec<String>, std::path::PathBuf),
}

/// Files the systems leave in directories, not worth uploading.
const LEFT_OUT: [&str; 3] = [".DS_Store", "Thumbs.db", "desktop.ini"];

/// What `path` holds, in the order to upload it: a file, or a directory and everything in it (names sorted, links
/// not followed).
fn walk(path: &std::path::Path, above: &[String], plan: &mut Vec<Step>) -> client::Result<()> {
    let kind = std::fs::symlink_metadata(path).map_err(client::Error::Io)?.file_type();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_owned();
    if kind.is_file() {
        if !LEFT_OUT.contains(&name.as_str()) {
            plan.push(Step::File(above.to_vec(), path.to_path_buf()));
        }
    } else if kind.is_dir() {
        let mut names = above.to_vec();
        names.push(name);
        plan.push(Step::Directory(names.clone()));
        let mut entries = std::fs::read_dir(path)
            .map_err(client::Error::Io)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .collect::<Vec<_>>();
        entries.sort();
        for entry in entries {
            walk(&entry, &names, plan)?;
        }
    }
    Ok(())
}

/// Where an upload goes: the directories it has found or made (by their names below the target) and what is in them.
struct Target<'a> {
    client: &'a Client,
    e2e: &'a Mutex<E2e>,
    account: &'a str,
    vault: Option<&'a str>,
    dirs: HashMap<Vec<String>, Option<String>>,
    listed: HashMap<Option<String>, Vec<files::FileNode>>,
}

impl Target<'_> {
    /// What is in a directory, names opened in a vault.
    async fn children(&mut self, parent: &Option<String>) -> client::Result<&Vec<files::FileNode>> {
        if !self.listed.contains_key(parent) {
            let mut nodes = files::children(self.client, self.account, parent.as_deref()).await?;
            if self.vault.is_some() {
                self.e2e.lock().await.open_names(self.client, self.account, &mut nodes).await;
            }
            self.listed.insert(parent.clone(), nodes);
        }
        Ok(&self.listed[parent])
    }

    /// The directory at `names` below the target: one of that name already there, or made.
    async fn directory(&mut self, names: &[String]) -> client::Result<Option<String>> {
        if let Some(id) = self.dirs.get(names) {
            return Ok(id.clone());
        }
        let (name, above) = names.split_last().expect("the target itself is always known");
        let parent = Box::pin(self.directory(above)).await?;
        let find = |nodes: &Vec<files::FileNode>| {
            nodes.iter().find(|n| n.is_directory() && &n.name == name).map(|n| n.id.clone())
        };
        let mut id = find(self.children(&parent).await?);
        if id.is_none() {
            match (self.vault, &parent) {
                (Some(vault), Some(inside)) => {
                    let mut e2e = self.e2e.lock().await;
                    e2e.create_directory_in(self.client, self.account, vault, inside, name).await?;
                }
                _ => files::create_directory(self.client, self.account, parent.as_deref(), name).await?,
            }
            self.listed.remove(&parent);
            id = find(self.children(&parent).await?);
        }
        let id = id.ok_or_else(|| client::Error::Protocol(format!("the directory {name} was not made")))?;
        self.dirs.insert(names.to_vec(), Some(id.clone()));
        Ok(Some(id))
    }
}

fn count(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn status(e2e: &E2e) -> E2eStatus {
    let key = e2e.current_key();
    E2eStatus {
        available: e2e.available,
        has_key: key.is_some(),
        unlocked: e2e.is_unlocked(),
        fingerprint: key.map(|k| k.id.clone()),
        kind: key.map(|k| k.kind.clone()),
        mail_on_arrival: e2e.settings.mail,
        tenant_recovers: e2e.settings.policy.recovery,
        vaults_allowed: e2e.vaults_allowed(),
    }
}

fn recipients(to: &[String]) -> Vec<String> {
    to.iter().map(|a| a.trim().to_owned()).filter(|a| a.contains('@')).collect()
}

/// A plain-text message to `to`.
fn draft(to: &[String], subject: &str, text: &str) -> mail::Draft {
    mail::Draft {
        from: None,
        to: recipients(to).into_iter().map(|email| mail::EmailAddress { name: None, email }).collect(),
        cc: Vec::new(),
        bcc: Vec::new(),
        subject: subject.to_owned(),
        body: text.to_owned(),
        in_reply_to: Vec::new(),
        references: Vec::new(),
        attachments: Vec::new(),
    }
}

/// The identity the account sends as: the one of its own address, else the first.
async fn identity(client: &Client, account: &str) -> client::Result<mail::Identity> {
    let identities = mail::identities(client, account).await?;
    let own = client.session.username.to_lowercase();
    identities
        .iter()
        .find(|identity| identity.email.to_lowercase() == own)
        .or(identities.first())
        .cloned()
        .ok_or_else(|| client::Error::Protocol("the account has no identity to send as".into()))
}

impl Kernoid {
    /// Logs in with an address and an app password (**OPEN**: OpenID Connect with PKCE, tokens in the system's
    /// key store – docs/plan.md, 7).
    pub async fn login(server: String, address: String, password: String) -> Result<Kernoid, KernoidError> {
        let (client, e2e) = run(async move {
            let url = client::session_url(Some(server.trim()), address.trim())?;
            let client = Client::connect(&url, address.trim(), &password, &options()).await?;
            // A server without the extension, or one that fails to answer it, is mail without end-to-end encryption.
            let e2e = E2e::load(&client).await.unwrap_or_default();
            Ok((client, e2e))
        })
        .await?;
        Ok(Kernoid {
            client,
            e2e: Arc::new(Mutex::new(e2e)),
            opened: Arc::default(),
            login: None,
            vaults: Arc::default(),
            shell_codes: Arc::default(),
        })
    }

    /// Begins a login with OpenID Connect at `server`: kernoid's login page in the system's browser, with a passkey,
    /// a password or a second factor – whatever the account and its tenant use. `redirect_uri` is where the browser
    /// comes back: `dev.kernoid.kernoid:/oauth` on Apple's systems and Android, `http://127.0.0.1:<port>/oauth` on
    /// desktops.
    pub async fn begin_login(
        server: String,
        redirect_uri: String,
        address: Option<String>,
    ) -> Result<OidcLogin, KernoidError> {
        run(async move {
            let login = client::oidc::begin(server.trim(), &redirect_uri, address.as_deref(), &options()).await?;
            Ok(OidcLogin { login, server: server.trim().to_owned() })
        })
        .await
    }

    /// Finishes a login with the URL the browser came back to. The access token is renewed in the background before
    /// it expires; [`Kernoid::kept_login`] and [`Kernoid::watch_login`] give what to keep to stay signed in.
    pub async fn finish_login(login: &OidcLogin, callback: String) -> Result<Kernoid, KernoidError> {
        let (inner, server) = (login.login.clone(), login.server.clone());
        let tokens = run(async move { client::oidc::finish(&inner, &callback, &options()).await }).await?;
        Kernoid::signed_in(server, tokens).await
    }

    /// Signs in again with what [`Kernoid::kept_login`] gave – after a restart. The refresh token is used up by it:
    /// keep the new one ([`Kernoid::kept_login`]). A login that ended is `unauthorized`: forget what was kept.
    pub async fn resume(kept: String) -> Result<Kernoid, KernoidError> {
        let kept: Kept = serde_json::from_str(&kept)
            .map_err(|_| KernoidError { unauthorized: true, message: "the kept login is unreadable".into() })?;
        let saved = kept.login.tokens();
        let tokens = run(async move { client::oidc::refresh(&saved, &options()).await }).await?;
        let account = Kernoid::signed_in(kept.server, tokens).await?;
        if let Some(login) = &account.login
            && let Ok(mut vaults) = login.shell_vaults.lock()
        {
            *vaults = kept.vaults;
        }
        Ok(account)
    }

    /// A shell's vaults on spaces, as its login was kept with them.
    pub(crate) fn shell_vaults(&self) -> Option<ShellVaults> {
        self.login.as_ref()?.shell_vaults.lock().ok()?.clone()
    }

    /// Gives this login – a shell's, before it is kept for the shell – what it needs for vaults on spaces: its store
    /// and the codes file in `directory`, sealed under `key` (32 bytes). The app hands it codes with
    /// [`Kernoid::share_vaults_with_shell`].
    #[frb(sync)]
    pub fn give_shell_vaults(&self, directory: String, key: Vec<u8>) -> Result<(), KernoidError> {
        let bad = || KernoidError { unauthorized: false, message: "a key of 32 bytes".into() };
        let key: [u8; 32] = key.try_into().map_err(|_| bad())?;
        let login = self.login.as_ref().ok_or_else(|| KernoidError {
            unauthorized: false,
            message: "only a login with OpenID Connect is kept".into(),
        })?;
        let at = |name: &str| std::path::Path::new(&directory).join(name).to_string_lossy().into_owned();
        let vaults = ShellVaults { store: at("shell.sealed"), codes: at("shell-codes.sealed"), key: hex(&key) };
        *login.shell_vaults.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(vaults);
        Ok(())
    }

    /// From now on, every vault on a space this app enters is handed to the shell too: its code, sealed into the codes
    /// file in `directory` under `key` – the shell comes in with it as a device of its own.
    #[frb(sync)]
    pub fn share_vaults_with_shell(&self, directory: String, key: Vec<u8>) -> Result<(), KernoidError> {
        let key: [u8; 32] =
            key.try_into().map_err(|_| KernoidError { unauthorized: false, message: "a key of 32 bytes".into() })?;
        let codes = std::path::Path::new(&directory).join("shell-codes.sealed").to_string_lossy().into_owned();
        *self.shell_codes.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((codes, key));
        Ok(())
    }

    async fn signed_in(server: String, tokens: client::oidc::Tokens) -> Result<Kernoid, KernoidError> {
        let (access, url_server) = (tokens.access_token.clone(), server.clone());
        let (client, e2e) = run(async move {
            let url = client::session_url(Some(&url_server), "")?;
            let client = Client::connect_with_token(&url, &access, &options()).await?;
            let e2e = E2e::load(&client).await.unwrap_or_default();
            Ok((client, e2e))
        })
        .await?;
        let login = Arc::new(Login {
            server,
            shell_vaults: std::sync::Mutex::new(None),
            tokens: std::sync::Mutex::new(tokens),
            watcher: std::sync::Mutex::new(None),
            renewal: std::sync::Mutex::new(None),
        });
        let task = RUNTIME.spawn(renew(client.clone(), login.clone()));
        if let Ok(mut renewal) = login.renewal.lock() {
            *renewal = Some(task);
        }
        Ok(Kernoid {
            client,
            e2e: Arc::new(Mutex::new(e2e)),
            opened: Arc::default(),
            login: Some(login),
            vaults: Arc::default(),
            shell_codes: Arc::default(),
        })
    }

    /// What to keep in the system's key store to stay signed in – none for a login with an app password.
    #[frb(sync)]
    pub fn kept_login(&self) -> Option<String> {
        self.login.as_ref()?.kept()
    }

    /// Hears of every renewal with what to keep from then on: kernoid rotates refresh tokens, and one used before
    /// would end the login at the next start.
    pub fn watch_login(&self, sink: StreamSink<String>) {
        if let Some(login) = &self.login
            && let Ok(mut watcher) = login.watcher.lock()
        {
            *watcher = Some(sink);
        }
    }

    /// Signs out: a login with OpenID Connect is revoked at the server – the browser's session there stays.
    pub async fn sign_out(&self) -> Result<(), KernoidError> {
        let Some(login) = self.login.clone() else { return Ok(()) };
        if let Ok(mut renewal) = login.renewal.lock()
            && let Some(task) = renewal.take()
        {
            task.abort();
        }
        let tokens = login
            .tokens
            .lock()
            .map(|t| t.clone())
            .map_err(|_| KernoidError { unauthorized: false, message: "the login is broken".into() })?;
        run(async move { client::oidc::revoke(&tokens, &options()).await }).await
    }

    /// Stops renewing the access token in the background – for the core of the file shells, which renews by opening
    /// again with the newest kept login, so that no process renews with a refresh token another one has used
    /// (`crate::provider`).
    #[frb(ignore)]
    pub(crate) fn stop_renewing(&self) {
        // No `let` chains: the attribute macro reads this function in an older edition.
        let renewal = self.login.as_ref().and_then(|login| login.renewal.lock().ok().and_then(|mut r| r.take()));
        if let Some(task) = renewal {
            task.abort();
        }
    }

    /// The SDK's client, for the core of the file shells (`crate::provider`).
    #[frb(ignore)]
    pub(crate) fn sdk_client(&self) -> Client {
        self.client.clone()
    }

    #[frb(sync, getter)]
    pub fn username(&self) -> String {
        self.client.session.username.clone()
    }

    /// Whether the account's server offers a capability of JMAP – for the account itself or one shared with it (RFC
    /// 0011, 3: the app shows what the server offers).
    #[frb(sync)]
    pub fn offers(&self, capability: String) -> bool {
        let session = &self.client.session;
        session.primary(&capability).is_some() || !session.accounts_with(&capability).is_empty()
    }

    #[frb(sync, getter)]
    pub fn server(&self) -> String {
        self.client.origin().to_owned()
    }

    fn account(&self, capability: &str) -> Result<String, KernoidError> {
        self.client
            .session
            .primary(capability)
            .map(str::to_owned)
            .ok_or_else(|| KernoidError { unauthorized: false, message: format!("the account has no {capability}") })
    }

    /// A mail account: the one named, or the user's own.
    fn mail_account(&self, account_id: Option<String>) -> Result<String, KernoidError> {
        match account_id {
            Some(id) => Ok(id),
            None => self.account(client::MAIL),
        }
    }

    /// The mail accounts the user reaches – their own first, then the shared mailboxes by name.
    #[frb(sync)]
    pub fn mail_accounts(&self) -> Vec<MailAccount> {
        self.client
            .session
            .accounts_with(client::MAIL)
            .into_iter()
            .map(|(id, a)| MailAccount {
                is_personal: Some(id) == self.client.session.primary(client::MAIL),
                id: id.to_owned(),
                name: a.name.clone(),
                read_only: a.is_read_only,
            })
            .collect()
    }

    pub async fn mailboxes(&self, account_id: Option<String>) -> Result<Vec<Mailbox>, KernoidError> {
        let (client, account) = (self.client.clone(), self.mail_account(account_id)?);
        let boxes = run(async move { mail::mailboxes(&client, &account).await }).await?;
        Ok(boxes
            .into_iter()
            .map(|b| Mailbox {
                id: b.id,
                name: b.name,
                parent_id: b.parent_id,
                role: b.role,
                total: count(b.total_emails),
                unread: count(b.unread_emails),
            })
            .collect())
    }

    /// A page of a mailbox – or, without one, of all the account's –, `search` searching it (full text); encrypted
    /// emails with their summary decrypted, when the key is unlocked.
    pub async fn emails(
        &self,
        account_id: Option<String>,
        mailbox_id: Option<String>,
        search: String,
        position: u32,
        limit: u32,
    ) -> Result<EmailPage, KernoidError> {
        let (client, account, e2e) = (self.client.clone(), self.mail_account(account_id)?, self.e2e.clone());
        run(async move {
            let (emails, total) =
                mail::emails(&client, &account, mailbox_id.as_deref(), &search, u64::from(position), u64::from(limit))
                    .await?;
            let e2e = e2e.lock().await;
            let emails = emails
                .into_iter()
                .map(|mut e| {
                    e2e.open_summary(&mut e);
                    let opened = e.opened;
                    EmailSummary {
                        seen: e.is_seen(),
                        flagged: e.is_flagged(),
                        encrypted: e.encrypted,
                        locked: e.encrypted && !opened,
                        id: e.id,
                        from: addresses(e.from),
                        subject: e.subject.unwrap_or_default(),
                        preview: if e.encrypted && !opened { String::new() } else { e.preview },
                        received_at: e.received_at,
                        has_attachment: e.has_attachment,
                    }
                })
                .collect();
            Ok(EmailPage { emails, total: count(total) })
        })
        .await
    }

    /// Makes a folder – in `parent_id`, or at the top – and returns its id.
    pub async fn create_mailbox(
        &self,
        account_id: Option<String>,
        name: String,
        parent_id: Option<String>,
    ) -> Result<String, KernoidError> {
        let (client, account) = (self.client.clone(), self.mail_account(account_id)?);
        run(async move { mail::create_mailbox(&client, &account, name.trim(), parent_id.as_deref()).await }).await
    }

    pub async fn rename_mailbox(
        &self,
        account_id: Option<String>,
        id: String,
        name: String,
    ) -> Result<(), KernoidError> {
        let (client, account) = (self.client.clone(), self.mail_account(account_id)?);
        run(async move { mail::rename_mailbox(&client, &account, &id, name.trim()).await }).await
    }

    /// Moves a folder into `parent_id`, or to the top.
    pub async fn move_mailbox(
        &self,
        account_id: Option<String>,
        id: String,
        parent_id: Option<String>,
    ) -> Result<(), KernoidError> {
        let (client, account) = (self.client.clone(), self.mail_account(account_id)?);
        run(async move { mail::move_mailbox(&client, &account, &id, parent_id.as_deref()).await }).await
    }

    /// Removes a folder, with the emails only in it when `with_emails`.
    pub async fn destroy_mailbox(
        &self,
        account_id: Option<String>,
        id: String,
        with_emails: bool,
    ) -> Result<(), KernoidError> {
        let (client, account) = (self.client.clone(), self.mail_account(account_id)?);
        run(async move { mail::destroy_mailbox(&client, &account, &id, with_emails).await }).await
    }

    /// Removes every email of a folder for good – the Trash, Junk – and returns how many.
    pub async fn empty_mailbox(&self, account_id: Option<String>, id: String) -> Result<i64, KernoidError> {
        let (client, account) = (self.client.clone(), self.mail_account(account_id)?);
        run(async move { mail::empty_mailbox(&client, &account, &id).await.map(count) }).await
    }

    /// Marks several emails: `$seen` (read) or `$flagged`, on or off.
    pub async fn mark_emails(
        &self,
        account_id: Option<String>,
        ids: Vec<String>,
        keyword: String,
        on: bool,
    ) -> Result<(), KernoidError> {
        let (client, account) = (self.client.clone(), self.mail_account(account_id)?);
        run(async move { mail::set_keywords(&client, &account, &ids, &keyword, on).await }).await
    }

    /// Moves several emails into one mailbox of their account.
    pub async fn move_emails(
        &self,
        account_id: Option<String>,
        ids: Vec<String>,
        mailbox_id: String,
    ) -> Result<(), KernoidError> {
        let (client, account) = (self.client.clone(), self.mail_account(account_id)?);
        run(async move { mail::move_all(&client, &account, &ids, &mailbox_id).await }).await
    }

    /// Removes several emails for good – the app moves them to the Trash first, and removes them only from there.
    pub async fn destroy_emails(&self, account_id: Option<String>, ids: Vec<String>) -> Result<(), KernoidError> {
        let (client, account) = (self.client.clone(), self.mail_account(account_id)?);
        run(async move { mail::destroy_all(&client, &account, &ids).await }).await
    }

    /// One message to read – an encrypted one decrypted here, with its signature checked.
    pub async fn email(&self, account_id: Option<String>, id: String) -> Result<Email, KernoidError> {
        let (client, account) = (self.client.clone(), self.mail_account(account_id)?);
        let (e2e, opened) = (self.e2e.clone(), self.opened.clone());
        run(async move {
            let email = mail::full(&client, &account, &[id.as_str()])
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| client::Error::Protocol("the email is gone".into()))?;
            let encrypted = email.summary.encrypted;
            let e = e2e.lock().await.open(&client, &account, email).await?;
            let sealed = e.sealed.unwrap_or_default();
            let attachments: Vec<Attachment> = e
                .attachments
                .iter()
                .filter(|part| part.blob_id.is_some() || part.inner.is_some())
                .map(|part| Attachment {
                    blob_id: part.blob_id.clone(),
                    part_index: part.inner.and_then(|index| u32::try_from(index).ok()),
                    name: part.name.clone().unwrap_or_else(|| "attachment".into()),
                    media_type: part.kind.clone(),
                    size: count(part.size),
                })
                .collect();
            if let Some(inner) = &e.inner {
                opened.lock().await.insert(e.summary.id.clone(), inner.0.clone());
            }
            let html = if sealed.locked { None } else { html_of(&e) };
            Ok(Email {
                text: if sealed.locked { String::new() } else { e.text(TEXT_WIDTH) },
                html,
                attachments,
                encrypted,
                locked: sealed.locked,
                signed: sealed.signed,
                verified: sealed.verified,
                id: e.summary.id,
                from: addresses(e.summary.from),
                to: addresses(e.summary.to),
                cc: addresses(e.cc),
                subject: e.summary.subject.unwrap_or_default(),
                received_at: e.summary.received_at,
            })
        })
        .await
    }

    /// How a message to `to` (every recipient, Cc and Bcc as well) would go out: end-to-end encrypted when the key is
    /// unlocked and every recipient has a key, else as before – with the reason.
    pub async fn send_plan(&self, to: Vec<String>) -> Result<SendPlan, KernoidError> {
        let (client, account, e2e) = (self.client.clone(), self.account(client::MAIL)?, self.e2e.clone());
        run(async move {
            let identity = identity(&client, &account).await?;
            Ok(match e2e.lock().await.plan(&client, &account, &identity, &draft(&to, "", "")).await {
                Plan::Sealed(_) => SendPlan { encrypted: true, reason: None },
                Plan::Plain(reason) => SendPlan { encrypted: false, reason: Some(reason) },
            })
        })
        .await
    }

    /// A reply (`reply`, `replyAll`) to or a forward (`forward`) of an email: recipients, `Re:`/`Fwd:`, the text quoted
    /// – an encrypted email's decrypted text, when the key is unlocked –, the thread, the attachments forwarded.
    /// The email is read from `account_id` (a shared mailbox) or the user's own; the draft is the user's own.
    pub async fn reply_draft(
        &self,
        account_id: Option<String>,
        email_id: String,
        kind: String,
        phrases: ReplyPhrases,
    ) -> Result<EmailDraft, KernoidError> {
        let own = self.account(client::MAIL)?;
        let (client, account, e2e) = (self.client.clone(), self.mail_account(account_id)?, self.e2e.clone());
        let opened = self.opened.clone();
        run(async move {
            let kind = match kind.as_str() {
                "reply" => reply::Kind::Reply,
                "replyAll" => reply::Kind::ReplyAll,
                "forward" => reply::Kind::Forward,
                other => return Err(client::Error::Protocol(format!("not a kind of reply: {other}"))),
            };
            let email = mail::full(&client, &account, &[email_id.as_str()])
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| client::Error::Protocol("the email is gone".into()))?;
            let email = e2e.lock().await.open(&client, &account, email).await?;
            let text = email.text(TEXT_WIDTH);
            // A forward carries the attachments of an encrypted message too: they are read from it again on sending.
            let mut parts: Vec<DraftPart> = match (&kind, &email.inner) {
                (reply::Kind::Forward, Some(inner)) => {
                    opened.lock().await.insert(email.summary.id.clone(), inner.0.clone());
                    email
                        .attachments
                        .iter()
                        .filter_map(|part| {
                            Some(DraftPart {
                                email_id: email.summary.id.clone(),
                                part_index: Some(u32::try_from(part.inner?).ok()?),
                                account_id: None,
                                blob_id: None,
                                name: part.name.clone().unwrap_or_else(|| "attachment".into()),
                                media_type: part.kind.clone(),
                                size: count(part.size),
                            })
                        })
                        .collect()
                }
                _ => Vec::new(),
            };
            let identities = mail::identities(&client, &own).await?;
            let phrases = reply::Phrases {
                wrote: phrases.wrote,
                forwarded: phrases.forwarded,
                from: phrases.from,
                date: phrases.date,
                subject: phrases.subject,
                to: phrases.to,
                date_format: phrases.date_format,
            };
            let mut draft = reply::start(kind, Some((&email, &text)), &identities, &phrases);
            // The attachments of a shared mailbox's message lie in that account: the draft fetches them when it is sent.
            if account != own {
                for a in std::mem::take(&mut draft.attachments) {
                    parts.push(DraftPart {
                        email_id: email.summary.id.clone(),
                        part_index: None,
                        account_id: Some(account.clone()),
                        blob_id: Some(a.blob_id),
                        name: a.name,
                        media_type: a.kind,
                        size: count(a.size),
                    });
                }
            }
            Ok(EmailDraft {
                to: mail::format_addresses(&draft.to),
                cc: mail::format_addresses(&draft.cc),
                bcc: String::new(),
                subject: draft.subject,
                text: draft.body,
                in_reply_to: draft.in_reply_to,
                references: draft.references,
                attachments: draft
                    .attachments
                    .into_iter()
                    .map(|a| DraftAttachment {
                        blob_id: a.blob_id,
                        name: a.name,
                        media_type: a.kind,
                        size: count(a.size),
                    })
                    .collect(),
                parts,
                files: Vec::new(),
            })
        })
        .await
    }

    /// Sends a message – end-to-end encrypted and signed whenever it can be (RFC 0006, 5.3): then the files go inside
    /// the encrypted message and nothing of them reaches the server as it is; else they are uploaded and attached.
    /// Returns whether it went encrypted.
    pub async fn send_draft(&self, draft: EmailDraft) -> Result<bool, KernoidError> {
        let (client, account, e2e) = (self.client.clone(), self.account(client::MAIL)?, self.e2e.clone());
        let opened = self.opened.clone();
        run(async move {
            let mut inline = Vec::new();
            for part in &draft.parts {
                let data = match (part.part_index, &part.account_id, &part.blob_id) {
                    (Some(index), _, _) => {
                        let message =
                            opened.lock().await.get(&part.email_id).cloned().ok_or_else(|| {
                                client::Error::E2e("open the message again: the key was locked".into())
                            })?;
                        kernoid_e2e::compose::part(&message, index as usize).map_err(client::Error::from)?
                    }
                    (None, Some(from), Some(blob)) => {
                        let mut data = Vec::new();
                        client.download(from, blob, &part.name, &part.media_type, &mut data, &mut |_, _| {}).await?;
                        data
                    }
                    _ => return Err(client::Error::Protocol("an attachment without its source".into())),
                };
                inline.push(mail::InlineFile { name: part.name.clone(), media_type: part.media_type.clone(), data });
            }
            let mut message = mail::Draft {
                from: None,
                to: mail::parse_addresses(&draft.to),
                cc: mail::parse_addresses(&draft.cc),
                bcc: mail::parse_addresses(&draft.bcc),
                subject: draft.subject.trim().to_owned(),
                body: draft.text,
                in_reply_to: draft.in_reply_to,
                references: draft.references,
                attachments: draft
                    .attachments
                    .into_iter()
                    .map(|a| mail::Attachment {
                        blob_id: a.blob_id,
                        kind: a.media_type,
                        name: a.name,
                        size: u64::try_from(a.size).unwrap_or_default(),
                    })
                    .collect(),
            };
            if message.to.is_empty() && message.cc.is_empty() && message.bcc.is_empty() {
                return Err(client::Error::Protocol("the message has no recipient".into()));
            }
            let files: Vec<std::path::PathBuf> = draft.files.iter().map(std::path::PathBuf::from).collect();
            let identity = identity(&client, &account).await?;
            let boxes = mail::mailboxes(&client, &account).await?;
            let mut e2e = e2e.lock().await;
            match e2e.plan(&client, &account, &identity, &message).await {
                Plan::Sealed(keys) => {
                    let outgoing = Outgoing {
                        account: &account,
                        identity: &identity,
                        draft: &message,
                        files: &files,
                        boxes: &boxes,
                    };
                    e2e.send_with(&client, outgoing, &inline, &keys).await?;
                    Ok(true)
                }
                Plan::Plain(_) => {
                    for path in &files {
                        message.attachments.push(mail::attach(&client, &account, path).await?);
                    }
                    for file in &inline {
                        message.attachments.push(mail::attach_bytes(&client, &account, file).await?);
                    }
                    mail::send(&client, &account, &identity, &message, &boxes).await?;
                    Ok(false)
                }
            }
        })
        .await
    }

    pub async fn key_status(&self) -> E2eStatus {
        status(&*self.e2e.lock().await)
    }

    /// Makes the account's key here and returns its recovery code – to be shown once.
    pub async fn make_key(&self) -> Result<String, KernoidError> {
        let (client, e2e) = (self.client.clone(), self.e2e.clone());
        run(async move { e2e.lock().await.setup(&client, kernoid_e2e::Kind::Pqc).await }).await
    }

    /// Unlocks the key with the recovery code; it stays in this process's memory only.
    pub async fn unlock_key(&self, code: String) -> Result<E2eStatus, KernoidError> {
        let (client, e2e) = (self.client.clone(), self.e2e.clone());
        run(async move {
            let mut e2e = e2e.lock().await;
            e2e.refresh(&client).await?;
            // Argon2 takes a moment; it does not hold the runtime's other work.
            tokio::task::block_in_place(|| e2e.unlock(&code))?;
            Ok(status(&e2e))
        })
        .await
    }

    /// Forgets the unlocked key and every message decrypted with it.
    pub async fn lock_key(&self) -> E2eStatus {
        let mut e2e = self.e2e.lock().await;
        e2e.lock();
        self.opened.lock().await.clear();
        status(&e2e)
    }

    #[frb(sync)]
    pub fn file_stores(&self) -> Vec<FileStore> {
        let session = &self.client.session;
        files::stores(&self.client)
            .into_iter()
            .map(|s| {
                let may_create_top_level = s.kind == files::StoreKind::Own
                    || session
                        .accounts
                        .get(&s.id)
                        .and_then(|a| a.account_capabilities.get(client::FILENODE))
                        .is_some_and(|c| {
                            c.get("mayCreateTopLevelFileNode").and_then(serde_json::Value::as_bool).unwrap_or(false)
                        });
                FileStore {
                    is_personal: s.kind == files::StoreKind::Own,
                    is_drive: s.kind == files::StoreKind::Drive,
                    may_create_top_level,
                    account_id: s.id,
                    name: s.name,
                }
            })
            .collect()
    }

    /// The nodes of a directory, or of the top of the store for `None`.
    pub async fn files(&self, account_id: String, parent_id: Option<String>) -> Result<Vec<FileNode>, KernoidError> {
        let (client, e2e) = (self.client.clone(), self.e2e.clone());
        let nodes = run(async move {
            let mut nodes = files::children(&client, &account_id, parent_id.as_deref()).await?;
            if nodes.iter().any(files::FileNode::in_vault) {
                e2e.lock().await.open_names(&client, &account_id, &mut nodes).await;
                files::sort(&mut nodes);
            }
            Ok(nodes)
        })
        .await?;
        Ok(nodes.into_iter().map(file_node).collect())
    }

    /// The directory with the role `trash`, if the store has one.
    pub async fn file_trash(&self, account_id: String) -> Result<Option<FileNode>, KernoidError> {
        let client = self.client.clone();
        Ok(run(async move { files::trash(&client, &account_id).await }).await?.map(file_node))
    }

    /// The nodes whose name or text holds `text`, anywhere in the store.
    pub async fn search_files(&self, account_id: String, text: String) -> Result<Vec<FoundFile>, KernoidError> {
        let (client, e2e) = (self.client.clone(), self.e2e.clone());
        let found = run(async move {
            let mut found = files::search(&client, &account_id, text.trim()).await?;
            let mut e2e = e2e.lock().await;
            for f in &mut found {
                e2e.open_names(&client, &account_id, std::slice::from_mut(&mut f.node)).await;
                e2e.open_names(&client, &account_id, &mut f.path).await;
            }
            Ok(found)
        })
        .await?;
        Ok(found
            .into_iter()
            .map(|f| FoundFile { node: file_node(f.node), path: f.path.into_iter().map(file_node).collect() })
            .collect())
    }

    pub async fn create_directory(
        &self,
        account_id: String,
        parent_id: Option<String>,
        name: String,
    ) -> Result<(), KernoidError> {
        let client = self.client.clone();
        run(async move { files::create_directory(&client, &account_id, parent_id.as_deref(), name.trim()).await }).await
    }

    pub async fn rename_file(&self, account_id: String, id: String, name: String) -> Result<(), KernoidError> {
        let client = self.client.clone();
        run(async move { files::rename(&client, &account_id, &id, name.trim()).await }).await
    }

    /// Moves or copies a node into a directory (`None`: the top) – of the same store or another; a name taken there
    /// gets a number.
    pub async fn copy_file(
        &self,
        from_account_id: String,
        to_account_id: String,
        id: String,
        parent_id: Option<String>,
        move_it: bool,
    ) -> Result<(), KernoidError> {
        let client = self.client.clone();
        run(async move {
            if move_it && from_account_id == to_account_id {
                files::move_to(&client, &to_account_id, &id, parent_id.as_deref()).await
            } else {
                files::copy_to(&client, &from_account_id, &to_account_id, &id, parent_id.as_deref(), move_it).await
            }
        })
        .await
    }

    /// Removes a node and all it holds, for good.
    pub async fn destroy_file(&self, account_id: String, id: String) -> Result<(), KernoidError> {
        let client = self.client.clone();
        run(async move { files::destroy(&client, &account_id, &id).await }).await
    }

    /// Uploads files and whole directories into `parent_id` (in `vault_id`, encrypted, when it lies in a vault). A
    /// directory is made anew or, if one of the same name is there, filled; its files follow in name order. A file of
    /// the same name gets the new content, and what it had stays as a version. Progress
    /// is told per file, numbered in the order they are sent, with the path below the target (`Photos/a.jpg`).
    pub fn upload_files(
        &self,
        account_id: String,
        parent_id: Option<String>,
        vault_id: Option<String>,
        paths: Vec<String>,
        sink: StreamSink<UploadProgress>,
    ) {
        let (client, e2e) = (self.client.clone(), self.e2e.clone());
        RUNTIME.spawn(async move {
            let result = async {
                let mut plan = Vec::new();
                for path in &paths {
                    walk(std::path::Path::new(path), &[], &mut plan)?;
                }
                let mut target = Target {
                    client: &client,
                    e2e: &e2e,
                    account: &account_id,
                    vault: vault_id.as_deref(),
                    dirs: HashMap::from([(Vec::new(), parent_id.clone())]),
                    listed: HashMap::new(),
                };
                let mut index = 0u32;
                for step in plan {
                    match step {
                        Step::Directory(names) => {
                            target.directory(&names).await?;
                        }
                        Step::File(names, path) => {
                            let parent = target.directory(&names).await?;
                            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_owned();
                            let same = target.children(&parent).await?.iter().find(|n| n.name == name).cloned();
                            let shown = names.iter().chain([&name]).cloned().collect::<Vec<_>>().join("/");
                            let progress = sink.clone();
                            let _ = progress.add(UploadProgress { index, name: shown.clone(), sent: 0, total: 0 });
                            let tell = move |sent, total| {
                                let _ = progress.add(UploadProgress {
                                    index,
                                    name: shown.clone(),
                                    sent: count(sent),
                                    total: count(total),
                                });
                            };
                            match (target.vault, &parent) {
                                (Some(vault), Some(parent)) => {
                                    let mut e2e = e2e.lock().await;
                                    e2e.upload_into(&client, &account_id, vault, parent, &path, same.as_ref(), tell)
                                        .await?;
                                }
                                _ => {
                                    files::upload_file(
                                        &client,
                                        &account_id,
                                        parent.as_deref(),
                                        &path,
                                        same.as_ref(),
                                        tell,
                                    )
                                    .await?
                                }
                            }
                            index = index.saturating_add(1);
                        }
                    }
                }
                client::Result::Ok(())
            }
            .await;
            if let Err(error) = result {
                let _ = sink.add_error(KernoidError::from(error));
            }
        });
    }

    /// The current content and the earlier versions of a file, newest first.
    pub async fn file_versions(&self, account_id: String, id: String) -> Result<Vec<FileVersion>, KernoidError> {
        let client = self.client.clone();
        let versions = run(async move { files::versions(&client, &account_id, &id).await }).await?;
        Ok(versions
            .into_iter()
            .map(|v| FileVersion {
                id: v.id,
                blob_id: v.blob_id,
                size: count(v.size),
                media_type: v.media_type,
                modified: v.modified,
                created: v.created,
                is_current: v.is_current,
            })
            .collect())
    }

    /// Makes an earlier version the file's content again.
    pub async fn restore_version(
        &self,
        account_id: String,
        id: String,
        version_id: String,
    ) -> Result<(), KernoidError> {
        let client = self.client.clone();
        run(async move {
            let versions = files::versions(&client, &account_id, &id).await?;
            let version = versions
                .iter()
                .find(|v| v.id == version_id)
                .ok_or_else(|| client::Error::Protocol("the version is gone".into()))?;
            files::restore(&client, &account_id, &id, version).await
        })
        .await
    }

    /// Sets with whom a directory is shared, replacing what was.
    pub async fn share_directory(
        &self,
        account_id: String,
        id: String,
        shares: Vec<FileShare>,
    ) -> Result<(), KernoidError> {
        let client = self.client.clone();
        let with: Vec<(String, files::Level)> = shares
            .into_iter()
            .map(|s| {
                let level = match s.level.as_str() {
                    "full" => files::Level::Full,
                    "edit" => files::Level::Edit,
                    _ => files::Level::Read,
                };
                (s.principal_id, level)
            })
            .collect();
        run(async move { files::share(&client, &account_id, &id, &with).await }).await
    }

    /// Makes a vault (RFC 0006, 6) in a directory – `None`: the top of the store. Needs the account's key unlocked.
    pub async fn create_vault(
        &self,
        account_id: String,
        parent_id: Option<String>,
        name: String,
    ) -> Result<String, KernoidError> {
        let (client, e2e) = (self.client.clone(), self.e2e.clone());
        run(async move { e2e.lock().await.create_vault(&client, &account_id, parent_id.as_deref(), name.trim()).await })
            .await
    }

    /// A directory inside a vault, its name encrypted.
    pub async fn create_directory_in_vault(
        &self,
        account_id: String,
        vault_id: String,
        parent_id: String,
        name: String,
    ) -> Result<(), KernoidError> {
        let (client, e2e) = (self.client.clone(), self.e2e.clone());
        run(async move {
            e2e.lock().await.create_directory_in(&client, &account_id, &vault_id, &parent_id, name.trim()).await
        })
        .await
    }

    /// Renames a node in a vault: the new name encrypted.
    pub async fn rename_in_vault(
        &self,
        account_id: String,
        vault_id: String,
        id: String,
        name: String,
    ) -> Result<(), KernoidError> {
        let (client, e2e) = (self.client.clone(), self.e2e.clone());
        run(async move {
            let node = vault_node(vault_id, id, None);
            e2e.lock().await.rename_in(&client, &account_id, &node, name.trim()).await
        })
        .await
    }

    /// Downloads a file of a vault, decrypts it here and writes it into `directory` under `name` (made unique);
    /// returns the path.
    pub async fn download_from_vault(
        &self,
        account_id: String,
        vault_id: String,
        id: String,
        blob_id: String,
        name: String,
        directory: String,
    ) -> Result<String, KernoidError> {
        let (client, e2e) = (self.client.clone(), self.e2e.clone());
        run(async move {
            let node = vault_node(vault_id, id, Some(blob_id));
            let data = e2e.lock().await.download_from(&client, &account_id, &node).await?;
            write(&directory, &name, data).await
        })
        .await
    }

    /// Tells which types changed at the server (`FileNode`, `Email` …), as kernoid pushes them (EventSource), until
    /// the stream is no longer listened to; after a break it connects again by itself.
    pub fn watch_changes(&self, sink: StreamSink<Vec<String>>) {
        let client = self.client.clone();
        let _guard = RUNTIME.enter();
        kernoid_client::push::listen(client, move |push| match push {
            kernoid_client::push::Push::Changed(types) => sink.add(types.into_iter().collect()).is_ok(),
            _ => true,
        });
    }

    /// One round of keeping a folder of the device in step with a store (kernoid-sync): what changed on both sides is
    /// carried over, conflicts keep both versions. `state` is the round's database, outside the folder and one per
    /// folder. Vaults are kept in step while the account's key is unlocked, else left as they are; vaults on spaces
    /// once this device has them (or comes in with the key) and their store is open.
    pub async fn sync_folder(
        &self,
        account_id: String,
        root: String,
        state: String,
    ) -> Result<SyncReport, KernoidError> {
        let (client, e2e) = (self.client.clone(), self.e2e.clone());
        // Vaults on spaces too, once their store is open here (RFC 0010, 5).
        let vaults = self.vaults.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        let report = RUNTIME
            .spawn(async move {
                let mut folder = kernoid_sync::Folder::open(&root, &account_id, std::path::Path::new(&state))?;
                let mut e2e = e2e.lock().await;
                folder.sync_all(&client, Some(&mut e2e), vaults.as_ref()).await
            })
            .await
            .map_err(|error| KernoidError { message: error.to_string(), unauthorized: false })?
            .map_err(|error| match error {
                kernoid_sync::Error::Client(error) => KernoidError::from(error),
                error => KernoidError { message: error.to_string(), unauthorized: false },
            })?;
        let n = |count: usize| u32::try_from(count).unwrap_or(u32::MAX);
        Ok(SyncReport {
            downloaded: n(report.downloaded),
            uploaded: n(report.uploaded),
            deleted_here: n(report.deleted_here),
            deleted_there: n(report.deleted_there),
            directories: n(report.directories),
            moved: n(report.moved),
            conflicts: report.conflicts,
            failed: report.failed.into_iter().map(|(path, why)| format!("{path}: {why}")).collect(),
            skipped: report.skipped,
            locked: n(report.locked.len()),
        })
    }

    /// After sharing a vault: gives its key to those shared with who have a key of their own. Returns those who still
    /// wait – groups, and people without a key.
    pub async fn give_vault_keys(
        &self,
        account_id: String,
        vault_id: String,
        principal_ids: Vec<String>,
    ) -> Result<Vec<Principal>, KernoidError> {
        let (client, e2e) = (self.client.clone(), self.e2e.clone());
        let waiting = run(async move {
            let ids: Vec<&str> = principal_ids.iter().map(String::as_str).collect();
            let people = files::principals(&client, &ids).await?;
            e2e.lock().await.give_vault_keys(&client, &account_id, &vault_id, &people).await
        })
        .await?;
        Ok(waiting.into_iter().map(principal).collect())
    }

    /// People and groups of the tenant whose name or address holds `text`.
    pub async fn find_principals(&self, text: String) -> Result<Vec<Principal>, KernoidError> {
        let client = self.client.clone();
        Ok(run(async move { files::find_principals(&client, &text).await }).await?.into_iter().map(principal).collect())
    }

    /// The people and groups named.
    pub async fn principals(&self, ids: Vec<String>) -> Result<Vec<Principal>, KernoidError> {
        let client = self.client.clone();
        let found = run(async move {
            let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
            files::principals(&client, &ids).await
        })
        .await?;
        Ok(found.into_iter().map(principal).collect())
    }

    /// The vacation response; none when the server has none for the user.
    pub async fn vacation(&self) -> Result<Option<VacationResponse>, KernoidError> {
        let client = self.client.clone();
        let found = run(async move { mail::vacation(&client).await }).await?;
        let time = |t: Option<jiff::civil::DateTime>| t.map(|t| t.strftime(LOCAL_TIME).to_string());
        Ok(found.map(|v| VacationResponse {
            on: v.on,
            from: time(v.from),
            until: time(v.until),
            subject: v.subject,
            text: v.text,
        }))
    }

    pub async fn set_vacation(&self, vacation: VacationResponse) -> Result<(), KernoidError> {
        let time = |t: Option<String>| -> Result<Option<jiff::civil::DateTime>, KernoidError> {
            t.filter(|t| !t.is_empty())
                .map(|t| jiff::civil::DateTime::strptime(LOCAL_TIME, &t))
                .transpose()
                .map_err(|error| KernoidError { unauthorized: false, message: error.to_string() })
        };
        let vacation = mail::Vacation {
            on: vacation.on,
            from: time(vacation.from)?,
            until: time(vacation.until)?,
            subject: vacation.subject.trim().to_owned(),
            text: vacation.text,
        };
        let client = self.client.clone();
        run(async move { mail::set_vacation(&client, &vacation).await }).await
    }

    /// Whether the login reaches the account's everyday settings: a login with OpenID Connect does, an app password –
    /// given to other programs – does not.
    #[frb(sync)]
    pub fn settings_available(&self) -> bool {
        self.login.is_some()
    }

    /// The account's display name.
    pub async fn own_name(&self) -> Result<String, KernoidError> {
        let client = self.client.clone();
        let own = self.account(client::PRINCIPALS)?;
        let found = run(async move { files::principals(&client, &[own.as_str()]).await }).await?;
        Ok(found.into_iter().next().map(|p| p.name).unwrap_or_default())
    }

    pub async fn set_own_name(&self, name: String) -> Result<(), KernoidError> {
        let client = self.client.clone();
        run(async move { client::account::set_name(&client, name.trim()).await }).await
    }

    pub async fn account_language(&self) -> Result<AccountLanguage, KernoidError> {
        let client = self.client.clone();
        let l = run(async move { client::account::language(&client).await }).await?;
        Ok(AccountLanguage { language: l.language, used: l.used, available: l.available })
    }

    /// Chooses the language of kernoid's emails; none follows the tenant's.
    pub async fn set_account_language(&self, language: Option<String>) -> Result<(), KernoidError> {
        let client = self.client.clone();
        run(async move { client::account::set_language(&client, language.as_deref()).await }).await
    }

    pub async fn mail_settings(&self) -> Result<MailSettings, KernoidError> {
        let client = self.client.clone();
        let account = self.account(client::MAIL)?;
        run(async move {
            let settings = client::account::mail_settings(&client).await?;
            let senders = mail::identities(&client, &account).await?.into_iter().map(|i| i.email).collect();
            Ok(MailSettings {
                trash_retention_days: settings.trash_retention_days,
                tenant_trash_retention_days: settings.tenant_trash_retention_days,
                default_from: settings.default_from,
                undo_send_seconds: settings.undo_send_seconds,
                senders,
            })
        })
        .await
    }

    pub async fn set_mail_settings(&self, settings: MailSettings) -> Result<(), KernoidError> {
        let client = self.client.clone();
        let settings = client::account::MailSettings {
            trash_retention_days: settings.trash_retention_days,
            tenant_trash_retention_days: None,
            default_from: settings.default_from,
            undo_send_seconds: settings.undo_send_seconds,
        };
        run(async move { client::account::set_mail_settings(&client, &settings).await }).await
    }

    /// The account's own picture, or none.
    pub async fn own_avatar(&self) -> Result<Option<Vec<u8>>, KernoidError> {
        let client = self.client.clone();
        let own = self.account(client::PRINCIPALS)?;
        run(async move { client::account::avatar(&client, &own).await }).await
    }

    /// Sets the picture: a PNG, JPEG or WebP image of up to 1 MiB.
    pub async fn set_own_avatar(&self, image: Vec<u8>, media_type: String) -> Result<(), KernoidError> {
        let client = self.client.clone();
        run(async move { client::account::set_avatar(&client, image, &media_type).await }).await
    }

    pub async fn remove_own_avatar(&self) -> Result<(), KernoidError> {
        let client = self.client.clone();
        run(async move { client::account::remove_avatar(&client).await }).await
    }

    /// Whether the server makes links for people without an account.
    #[frb(sync)]
    pub fn links_available(&self) -> bool {
        files::links_available(&self.client)
    }

    pub async fn file_links(&self, account_id: String, id: String) -> Result<Vec<FileLink>, KernoidError> {
        let client = self.client.clone();
        let links = run(async move { files::links(&client, &account_id, &id).await }).await?;
        Ok(links
            .into_iter()
            .map(|l| FileLink {
                mode: link_mode_name(files::LinkMode::of(&l)).into(),
                id: l.id,
                expires: l.expires,
                has_password: l.has_password,
                created: l.created,
            })
            .collect())
    }

    /// Makes a link – `mode` is `view`, `add` or `drop` –, with an expiry (a UTCDate) and a password if given, and
    /// answers its address: the only time it can be known.
    pub async fn create_file_link(
        &self,
        account_id: String,
        id: String,
        mode: String,
        expires: Option<String>,
        password: Option<String>,
    ) -> Result<String, KernoidError> {
        let client = self.client.clone();
        let mode = match mode.as_str() {
            "add" => files::LinkMode::Add,
            "drop" => files::LinkMode::Drop,
            _ => files::LinkMode::View,
        };
        run(async move {
            files::create_link(&client, &account_id, &id, mode, expires.as_deref(), password.as_deref()).await
        })
        .await
    }

    pub async fn remove_file_link(&self, account_id: String, id: String) -> Result<(), KernoidError> {
        let client = self.client.clone();
        run(async move { files::remove_link(&client, &account_id, &id).await }).await
    }

    /// Downloads a blob of a store – or of the mail account, for `None` – into `directory` under `name` (made unique)
    /// and returns the path.
    pub async fn download(
        &self,
        account_id: Option<String>,
        blob_id: String,
        name: String,
        media_type: String,
        directory: String,
    ) -> Result<String, KernoidError> {
        let account_id = match account_id {
            Some(id) => id,
            None => self.account(client::MAIL)?,
        };
        let client = self.client.clone();
        run(async move {
            let path = unique_path(std::path::Path::new(&directory), &name).await;
            let mut file = tokio::fs::File::create(&path).await?;
            let result = client.download(&account_id, &blob_id, &name, &media_type, &mut file, &mut |_, _| {}).await;
            if let Err(error) = result {
                drop(file);
                let _ = tokio::fs::remove_file(&path).await;
                return Err(error);
            }
            Ok(path.to_string_lossy().into_owned())
        })
        .await
    }

    /// Saves an attachment of a decrypted message – read from the message decrypted here, never from the server.
    pub async fn save_part(
        &self,
        email_id: String,
        part_index: u32,
        name: String,
        directory: String,
    ) -> Result<String, KernoidError> {
        let opened = self.opened.clone();
        run(async move {
            let inner = opened
                .lock()
                .await
                .get(&email_id)
                .cloned()
                .ok_or_else(|| client::Error::E2e("open the message again: the key was locked".into()))?;
            let bytes = kernoid_e2e::compose::part(&inner, part_index as usize).map_err(client::Error::from)?;
            write(&directory, &name, bytes).await
        })
        .await
    }
}

/// Renews the access token a minute before it expires, as long as the refresh token is good, and tells the watcher
/// what to keep from then on.
async fn renew(client: Client, login: Arc<Login>) {
    loop {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let Ok(tokens) = login.tokens.lock().map(|t| t.clone()) else { return };
        let wait = tokens.expires_at.saturating_sub(now).saturating_sub(60).max(10);
        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
        match client::oidc::refresh(&tokens, &options()).await {
            Ok(new) => {
                client.set_access_token(&new.access_token);
                if let Ok(mut kept) = login.tokens.lock() {
                    *kept = new;
                }
                if let (Some(text), Ok(watcher)) = (login.kept(), login.watcher.lock())
                    && let Some(sink) = watcher.as_ref()
                {
                    let _ = sink.add(text);
                }
            }
            // Signed out elsewhere, or the refresh token revoked: calls fail with "unauthorized", and the app asks again.
            Err(client::Error::Unauthorized) => return,
            // Offline for now: try again shortly.
            Err(_) => {
                if let Ok(mut kept) = login.tokens.lock() {
                    kept.expires_at = now + 120;
                }
            }
        }
    }
}

/// The addresses that are the user: the login and the addresses the account sends from.
async fn own_addresses(client: &Client) -> Vec<String> {
    let mut own = vec![client.session.username.clone()];
    if let Some(account) = client.session.primary(client::MAIL)
        && let Ok(identities) = mail::identities(client, account).await
    {
        own.extend(identities.into_iter().map(|identity| identity.email));
    }
    own
}

/// The HTML parts of an email, joined; none when it has no HTML (its HTML body is its text parts then).
fn html_of(email: &mail::Email) -> Option<String> {
    let parts: Vec<&str> = email
        .html_body
        .iter()
        .filter(|part| part.kind == "text/html")
        .filter_map(|part| email.body_values.get(part.part_id.as_ref()?))
        .map(|value| value.value.as_str())
        .collect();
    if parts.is_empty() { None } else { Some(parts.join("\n")) }
}

/// The SDK's form of an event the user wrote, in the device's time zone; `earlier` is the event as it was, whose answers
/// stay while its time does.
fn event_form(draft: EventDraft, earlier: Option<calendars::EventForm>) -> client::Result<calendars::EventForm> {
    let time = |text: &str| {
        jiff::civil::DateTime::strptime("%Y-%m-%dT%H:%M:%S", text)
            .map_err(|_| client::Error::Protocol(format!("not a time: {text}")))
    };
    let form = calendars::EventForm {
        title: draft.title.trim().to_owned(),
        all_day: draft.all_day,
        start: time(&draft.start)?,
        end: time(&draft.end)?,
        time_zone: if draft.all_day { None } else { calendars::local_time_zone() },
        location: draft.location.trim().to_owned(),
        description: draft.description,
        participants: draft.participants.iter().map(|a| a.trim().to_owned()).filter(|a| a.contains('@')).collect(),
        repeat: draft.repeat.filter(|r| !r.is_empty()),
        answers: earlier.as_ref().map(|form| form.answers.clone()).unwrap_or_default(),
        was: earlier.map(|form| (form.start, form.end, form.all_day)),
    };
    if form.end < form.start {
        return Err(client::Error::Protocol("the end is before the start".into()));
    }
    Ok(form)
}

fn event(e: calendars::Event, own: &[String]) -> Event {
    let invitation = if e.organized_by(own) { None } else { e.me(own).map(|(key, p)| (key.to_owned(), p.clone())) };
    let rfc3339 = |time: jiff::Timestamp| format!("{time:.0}");
    // An all-day event is days, not times: its local start date and as many days as its duration says.
    let (start, end) = if e.show_without_time {
        let first = e.start.as_deref().and_then(|s| jiff::civil::Date::strptime("%Y-%m-%d", s.get(..10)?).ok());
        let days = e.duration.as_deref().and_then(calendars::parse_duration).map_or(1, |s| (s / 86_400).max(1));
        (
            first.map(|d| d.to_string()),
            first.and_then(|d| d.checked_add(jiff::Span::new().days(days)).ok()).map(|d| d.to_string()),
        )
    } else {
        (e.starts().map(rfc3339), e.ends().map(rfc3339))
    };
    Event {
        event_id: e.event_id().to_owned(),
        recurrence_id: e.recurrence_id.clone().filter(|_| e.base_event_id.is_some()),
        start,
        end,
        cancelled: e.is_cancelled(),
        location: e.location(),
        recurring: e.base_event_id.is_some() || e.recurrence_rule.is_some(),
        editable: e.organized_by(own),
        invitation_key: invitation.as_ref().map(|(key, _)| key.clone()),
        my_status: invitation.and_then(|(_, p)| p.participation_status),
        participants: e
            .participants
            .iter()
            .flat_map(|map| map.values())
            .map(|p| Participant {
                name: p.name.clone(),
                email: p.calendar_address.as_deref().map(|a| a.strip_prefix("mailto:").unwrap_or(a).to_owned()),
                status: p.participation_status.clone(),
            })
            .collect(),
        calendar_ids: e.calendar_ids.keys().cloned().collect(),
        title: e.title.unwrap_or_default(),
        all_day: e.show_without_time,
        description: e.description.filter(|d| !d.trim().is_empty()),
        account_id: e.account,
        id: e.id,
    }
}

impl Kernoid {
    /// The calendars of every account with calendars – the own ones first.
    pub async fn calendars(&self) -> Result<Vec<Calendar>, KernoidError> {
        let client = self.client.clone();
        let list = run(async move { calendars::calendars(&client).await }).await?;
        Ok(list
            .into_iter()
            .map(|c| Calendar {
                writable: c.writable(),
                id: c.id,
                account_id: c.account,
                name: c.name,
                color: c.color,
                shared_by: c.shared,
            })
            .collect())
    }

    /// The events of the visible calendars between `from` and `to` (RFC 3339) – recurring ones as their instances,
    /// by start.
    pub async fn events(&self, from: String, to: String) -> Result<Vec<Event>, KernoidError> {
        let client = self.client.clone();
        run(async move {
            let parse = |text: &str| {
                text.parse::<jiff::Timestamp>().map_err(|_| client::Error::Protocol(format!("not a time: {text}")))
            };
            let (after, before) = (parse(&from)?, parse(&to)?);
            let list = calendars::calendars(&client).await?;
            let mut found = calendars::instances(&client, &list, after, before).await?;
            found.sort_by_key(|e| e.starts());
            let own = own_addresses(&client).await;
            Ok(found.into_iter().map(|e| event(e, &own)).collect())
        })
        .await
    }

    /// Answers an invitation: `accepted`, `tentative` or `declined`; the organizer hears of it by email.
    pub async fn answer_event(
        &self,
        account_id: String,
        event_id: String,
        invitation_key: String,
        status: String,
    ) -> Result<(), KernoidError> {
        let client = self.client.clone();
        run(async move { calendars::answer(&client, &account_id, &event_id, &invitation_key, &status).await }).await
    }

    /// An event as a draft, to change it: for an instance of a recurring event, the event as a whole.
    pub async fn event_draft(&self, account_id: String, event_id: String) -> Result<EventDraft, KernoidError> {
        let client = self.client.clone();
        run(async move {
            let own = own_addresses(&client).await;
            let event = calendars::event(&client, &account_id, &event_id)
                .await?
                .ok_or_else(|| client::Error::Protocol("the event is gone".into()))?;
            let form = calendars::EventForm::of(&event, &own)
                .ok_or_else(|| client::Error::Protocol("the event has no start".into()))?;
            let local = |time: jiff::civil::DateTime| time.strftime("%Y-%m-%dT%H:%M:%S").to_string();
            Ok(EventDraft {
                calendar_id: event.calendar_ids.keys().next().cloned().unwrap_or_default(),
                account_id,
                title: form.title,
                all_day: form.all_day,
                start: local(form.start),
                end: local(form.end),
                location: form.location,
                description: form.description,
                participants: form.participants,
                repeat: form.repeat,
            })
        })
        .await
    }

    /// Makes an event, or – with `event_id` – changes one; the people invited hear of it by email. The time zone is the
    /// device's.
    pub async fn save_event(&self, event_id: Option<String>, draft: EventDraft) -> Result<(), KernoidError> {
        let client = self.client.clone();
        run(async move {
            let calendar = calendars::calendars(&client)
                .await?
                .into_iter()
                .find(|c| c.id == draft.calendar_id && c.account == draft.account_id)
                .ok_or_else(|| client::Error::Protocol("the calendar is gone".into()))?;
            let own = own_addresses(&client).await;
            // A change keeps the answers given, as long as the time stays (RFC 5546, 2.1.4).
            let earlier = match &event_id {
                Some(id) => calendars::event(&client, &calendar.account, id)
                    .await?
                    .and_then(|event| calendars::EventForm::of(&event, &own)),
                None => None,
            };
            let form = event_form(draft, earlier)?;
            let organizer = client.session.username.clone();
            match event_id {
                Some(id) => calendars::update(&client, &calendar, &id, &form, &organizer).await,
                None => calendars::create(&client, &calendar, &form, &organizer).await.map(|_| ()),
            }
        })
        .await
    }

    /// Changes one instance of a recurring event alone – its title, time, place and description; the people invited
    /// hear of it by email.
    pub async fn save_instance(
        &self,
        account_id: String,
        event_id: String,
        recurrence_id: String,
        draft: EventDraft,
    ) -> Result<(), KernoidError> {
        let client = self.client.clone();
        run(async move {
            let series = calendars::event(&client, &account_id, &event_id)
                .await?
                .ok_or_else(|| client::Error::Protocol("the event is gone".into()))?;
            let form = event_form(EventDraft { repeat: None, ..draft }, None)?;
            let organizer = client.session.username.clone();
            calendars::update_instance(&client, &series, &recurrence_id, &form, &organizer).await
        })
        .await
    }

    /// Leaves one instance of a recurring event out; the people invited hear of it by email.
    pub async fn delete_instance(
        &self,
        account_id: String,
        event_id: String,
        recurrence_id: String,
    ) -> Result<(), KernoidError> {
        let client = self.client.clone();
        run(async move {
            let series = calendars::event(&client, &account_id, &event_id)
                .await?
                .ok_or_else(|| client::Error::Protocol("the event is gone".into()))?;
            calendars::destroy_instance(&client, &series, &recurrence_id).await
        })
        .await
    }

    /// Deletes an event – a recurring one as a whole; the people invited hear of it by email.
    pub async fn delete_event(&self, account_id: String, event_id: String) -> Result<(), KernoidError> {
        let client = self.client.clone();
        run(async move { calendars::destroy(&client, &account_id, &event_id).await }).await
    }

    /// Makes a contact in the account's default address book, or – with `account_id` and `contact_id` – changes one.
    /// Addresses and numbers that stay keep their labels (work, home, mobile …).
    pub async fn save_contact(
        &self,
        account_id: Option<String>,
        contact_id: Option<String>,
        draft: ContactDraft,
    ) -> Result<(), KernoidError> {
        let client = self.client.clone();
        run(async move {
            let books = contacts::address_books(&client).await?;
            let earlier = match (&account_id, &contact_id) {
                (Some(account), Some(id)) => contacts::cards(&client, "")
                    .await?
                    .into_iter()
                    .find(|c| &c.account == account && &c.id == id)
                    .map(|card| (contacts::CardForm::of(&card), card.address_book_ids.keys().next().cloned())),
                _ => None,
            };
            let labelled = |values: Vec<LabelledValue>, allowed: &[&str]| -> Vec<contacts::Labelled> {
                values
                    .into_iter()
                    .map(|v| contacts::Labelled {
                        value: v.value.trim().to_owned(),
                        labels: v.labels.into_iter().filter(|l| allowed.contains(&l.as_str())).collect(),
                    })
                    .filter(|v| !v.value.is_empty())
                    .collect()
            };
            let form = contacts::CardForm {
                name: draft.name.trim().to_owned(),
                emails: labelled(draft.emails, &contacts::CONTEXTS),
                phones: labelled(draft.phones, &[&contacts::CONTEXTS[..], &contacts::FEATURES[..]].concat()),
                organizations: Some(draft.organization.trim().to_owned())
                    .filter(|o| !o.is_empty())
                    .into_iter()
                    .collect(),
                note: draft.note.trim().to_owned(),
            };
            match (account_id, contact_id, earlier) {
                (Some(account), Some(id), Some((_, book))) => {
                    let book = books
                        .iter()
                        .find(|b| b.account == account && Some(&b.id) == book.as_ref())
                        .ok_or_else(|| client::Error::Protocol("the address book is gone".into()))?;
                    contacts::update(&client, book, &id, &form).await
                }
                (Some(_), Some(_), None) => Err(client::Error::Protocol("the contact is gone".into())),
                _ => {
                    let own = client.session.primary(client::CONTACTS);
                    let book = books
                        .iter()
                        .filter(|b| b.writable())
                        .find(|b| Some(b.account.as_str()) == own && b.is_default)
                        .or_else(|| books.iter().find(|b| b.writable()))
                        .ok_or_else(|| client::Error::Protocol("there is no address book to write to".into()))?;
                    contacts::create(&client, book, &form).await
                }
            }
        })
        .await
    }

    pub async fn delete_contact(&self, account_id: String, contact_id: String) -> Result<(), KernoidError> {
        let client = self.client.clone();
        run(async move { contacts::destroy(&client, &account_id, &contact_id).await }).await
    }

    /// The contacts of every address book, `search` searching them; by name.
    pub async fn contacts(&self, search: String) -> Result<Vec<Contact>, KernoidError> {
        let client = self.client.clone();
        let cards = run(async move { contacts::cards(&client, search.trim()).await }).await?;
        Ok(cards
            .into_iter()
            .map(|c| {
                let form = contacts::CardForm::of(&c);
                let values = |list: Vec<contacts::Labelled>| {
                    list.into_iter().map(|l| LabelledValue { value: l.value, labels: l.labels }).collect()
                };
                Contact {
                    name: c.full_name(),
                    organization: c.organization(),
                    emails: values(form.emails),
                    phones: values(form.phones),
                    notes: c.notes().into_iter().filter(|n| !n.trim().is_empty()).collect(),
                    account_id: c.account,
                    id: c.id,
                }
            })
            .collect())
    }

    /// The labels an email address may have.
    #[frb(sync)]
    pub fn email_labels() -> Vec<String> {
        contacts::CONTEXTS.iter().map(|l| (*l).to_owned()).collect()
    }

    /// The labels a phone number may have: where it is, then what it is.
    #[frb(sync)]
    pub fn phone_labels() -> Vec<String> {
        contacts::CONTEXTS.iter().chain(contacts::FEATURES.iter()).map(|l| (*l).to_owned()).collect()
    }
}

async fn write(directory: &str, name: &str, bytes: Vec<u8>) -> client::Result<String> {
    let path = unique_path(std::path::Path::new(directory), name).await;
    tokio::fs::write(&path, bytes).await?;
    Ok(path.to_string_lossy().into_owned())
}

/// `name` in `directory`, or `name (2)`, `name (3)` … if taken. Only the last part of `name` counts, so a name from
/// the server cannot leave the directory.
async fn unique_path(directory: &std::path::Path, name: &str) -> std::path::PathBuf {
    let name = std::path::Path::new(name).file_name().and_then(|n| n.to_str()).unwrap_or("download");
    let name = if name.is_empty() || name == ".." { "download" } else { name };
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => (stem.to_owned(), format!(".{extension}")),
        _ => (name.to_owned(), String::new()),
    };
    let mut path = directory.join(name);
    let mut n = 2;
    while tokio::fs::try_exists(&path).await.unwrap_or(false) {
        path = directory.join(format!("{stem} ({n}){extension}"));
        n += 1;
    }
    path
}

/// What the SDK needs of a vault on a space to act in it.
fn space_vault(vault_id: String, space: String) -> files::FileNode {
    files::FileNode { space: Some(space), ..vault_node(vault_id.clone(), vault_id, None) }
}

fn vault_entry(e: client::e2e::Entry) -> VaultEntry {
    VaultEntry {
        id: e.id,
        name: e.name,
        is_directory: e.directory,
        trashed: e.trashed,
        size: count(e.size),
        media_type: e.media_type,
        modified: e.modified,
    }
}

/// Vaults on spaces (RFC 0010, 5): what lies in one is kept end to end through the foundation's streams.
impl Kernoid {
    /// Opens this account's store of vaults on spaces on this device – `path`, a file in the app's own directory, one
    /// per account, sealed under `key` (32 bytes from the system's key store) – with `device` (e.g. the host's name)
    /// as the start of this device's name in them.
    pub fn open_vaults(&self, path: String, device: String, key: Vec<u8>) -> Result<(), KernoidError> {
        let key: [u8; 32] =
            key.try_into().map_err(|_| KernoidError { unauthorized: false, message: "a key of 32 bytes".into() })?;
        let vaults = client::e2e::Vaults::open_sealed(std::path::Path::new(&path), key, &device)?;
        *self.vaults.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(vaults);
        Ok(())
    }

    /// Whether new vaults are made on spaces: the server names a relay for them, the login is by token and the store
    /// is open.
    #[frb(sync)]
    pub fn space_vaults(&self) -> bool {
        client::e2e::relay_url(&self.client).is_some()
            && self.login.is_some()
            && self.vaults.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).is_some()
    }

    fn vaults(&self) -> Result<client::e2e::Vaults, KernoidError> {
        self.vaults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or_else(|| KernoidError { unauthorized: false, message: "the vaults' store is not open".into() })
    }

    /// Makes a vault on a space in a directory – `None`: the top of the store. Needs the account's key unlocked.
    pub async fn create_space_vault(
        &self,
        account_id: String,
        parent_id: Option<String>,
        name: String,
    ) -> Result<String, KernoidError> {
        let (client, e2e, vaults) = (self.client.clone(), self.e2e.clone(), self.vaults()?);
        run(async move {
            let mut e2e = e2e.lock().await;
            vaults.create(&client, &mut e2e, &account_id, parent_id.as_deref(), name.trim()).await
        })
        .await
    }

    /// Brings this device into a vault on a space (with the account's code of it, opened with its key) or reads what
    /// is new there. False while no member made the account one.
    pub async fn enter_vault(&self, account_id: String, vault_id: String, space: String) -> Result<bool, KernoidError> {
        let (client, e2e, vaults) = (self.client.clone(), self.e2e.clone(), self.vaults()?);
        let shell = self.shell_codes.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        run(async move {
            let mut e2e = e2e.lock().await;
            let node = space_vault(vault_id.clone(), space.clone());
            let entered = vaults.enter(&client, &mut e2e, &account_id, &node).await?;
            // The shell gets the code too, once: it comes in with it as a device of its own.
            if entered
                && let Some((path, key)) = shell
                && !read_codes(&path, &key).contains_key(&vault_id)
                && let Ok(Some(code)) = client::e2e::Vaults::code(&client, &mut e2e, &account_id, &node).await
            {
                let mut codes = read_codes(&path, &key);
                codes.insert(vault_id, (space, hex(&code)));
                if let Ok(bytes) = serde_json::to_vec(&codes) {
                    let _ = std::fs::write(&path, kernoid_vault::sealed::seal(&key, &bytes));
                }
            }
            // Shares changed elsewhere (the administration, another app) reach the members here – where this device
            // may add members; a failure leaves the vault open as it is.
            if entered {
                let _ = vaults.reconcile(&client, &mut e2e, &account_id, &node).await;
            }
            Ok(entered)
        })
        .await
    }

    /// The name of a vault on a space this device has.
    pub async fn vault_name(&self, vault_id: String, space: String) -> Result<Option<String>, KernoidError> {
        let vaults = self.vaults()?;
        run(async move { vaults.name(&space_vault(vault_id, space)).await }).await
    }

    /// What lies in a directory of a vault on a space – `None`: its top.
    pub async fn vault_entries(
        &self,
        vault_id: String,
        space: String,
        directory: Option<String>,
    ) -> Result<Vec<VaultEntry>, KernoidError> {
        let vaults = self.vaults()?;
        let entries =
            run(async move { vaults.list(&space_vault(vault_id, space), directory.as_deref()).await }).await?;
        Ok(entries.into_iter().map(vault_entry).collect())
    }

    /// A directory in a directory of a vault on a space; returns its id.
    pub async fn vault_make_directory(
        &self,
        vault_id: String,
        space: String,
        parent: Option<String>,
        name: String,
    ) -> Result<String, KernoidError> {
        let vaults = self.vaults()?;
        run(async move { vaults.make_directory(&space_vault(vault_id, space), parent.as_deref(), name.trim()).await })
            .await
    }

    /// Uploads files and whole directories into a directory of a vault on a space; a file of the same name gets a
    /// new version. Progress as for [`Kernoid::upload_files`] (whole files: sent once done).
    pub fn vault_upload(
        &self,
        vault_id: String,
        space: String,
        parent: Option<String>,
        paths: Vec<String>,
        sink: StreamSink<UploadProgress>,
    ) {
        let vaults = match self.vaults() {
            Ok(vaults) => vaults,
            Err(error) => {
                let _ = sink.add_error(error);
                return;
            }
        };
        RUNTIME.spawn(async move {
            let node = space_vault(vault_id, space);
            let result = async {
                let mut plan = Vec::new();
                for path in &paths {
                    walk(std::path::Path::new(path), &[], &mut plan)?;
                }
                let mut dirs: HashMap<Vec<String>, Option<String>> = HashMap::from([(Vec::new(), parent.clone())]);
                let mut index = 0u32;
                for step in plan {
                    let names = match &step {
                        Step::Directory(names) | Step::File(names, _) => names.clone(),
                    };
                    // The directories on the way, found or made.
                    for depth in 1..=names.len() {
                        let key = names[..depth].to_vec();
                        if dirs.contains_key(&key) {
                            continue;
                        }
                        let above = dirs[&names[..depth - 1].to_vec()].clone();
                        let here = vaults.list(&node, above.as_deref()).await?;
                        let id = match here.iter().find(|e| e.directory && !e.trashed && e.name == names[depth - 1]) {
                            Some(found) => found.id.clone(),
                            None => vaults.make_directory(&node, above.as_deref(), &names[depth - 1]).await?,
                        };
                        dirs.insert(key, Some(id));
                    }
                    if let Step::File(names, path) = step {
                        let parent = dirs[&names].clone();
                        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_owned();
                        let shown = names.iter().chain([&name]).cloned().collect::<Vec<_>>().join("/");
                        let data = tokio::fs::read(&path).await?;
                        let total = count(data.len() as u64);
                        let _ = sink.add(UploadProgress { index, name: shown.clone(), sent: 0, total });
                        let same = vaults.list(&node, parent.as_deref()).await?;
                        let same = same.into_iter().find(|e| !e.directory && e.name == name).map(|e| e.id);
                        let modified = tokio::fs::metadata(&path)
                            .await?
                            .modified()
                            .ok()
                            .and_then(|time| jiff::Timestamp::try_from(time).ok())
                            .map(|time| format!("{time:.0}"));
                        let kind = files::media_type(&name);
                        vaults
                            .put_file(
                                &node,
                                parent.as_deref(),
                                &name,
                                data,
                                Some(kind),
                                modified.as_deref(),
                                same.as_deref(),
                            )
                            .await?;
                        let _ = sink.add(UploadProgress { index, name: shown, sent: total, total });
                        index = index.saturating_add(1);
                    }
                }
                client::Result::Ok(())
            }
            .await;
            if let Err(error) = result {
                let _ = sink.add_error(KernoidError::from(error));
            }
        });
    }

    /// Saves a file of a vault on a space, decrypted here, into `directory` under `name` (made unique); returns the
    /// path.
    pub async fn vault_save(
        &self,
        vault_id: String,
        space: String,
        entry: String,
        name: String,
        directory: String,
    ) -> Result<String, KernoidError> {
        let vaults = self.vaults()?;
        run(async move {
            let data = vaults.read_file(&space_vault(vault_id, space), &entry).await?;
            write(&directory, &name, data).await
        })
        .await
    }

    /// Renames something in a directory of a vault on a space.
    pub async fn vault_rename(
        &self,
        vault_id: String,
        space: String,
        parent: Option<String>,
        entry: String,
        name: String,
    ) -> Result<(), KernoidError> {
        let vaults = self.vaults()?;
        run(async move { vaults.rename(&space_vault(vault_id, space), parent.as_deref(), &entry, name.trim()).await })
            .await
    }

    /// Moves something into another directory of the same vault on a space (`to` `None`: its top).
    pub async fn vault_move(
        &self,
        vault_id: String,
        space: String,
        from: Option<String>,
        entry: String,
        to: Option<String>,
    ) -> Result<(), KernoidError> {
        let vaults = self.vaults()?;
        run(async move { vaults.move_to(&space_vault(vault_id, space), from.as_deref(), &entry, to.as_deref()).await })
            .await
    }

    /// Moves something of a vault on a space into its trash, or back.
    pub async fn vault_set_trashed(
        &self,
        vault_id: String,
        space: String,
        parent: Option<String>,
        entry: String,
        trashed: bool,
    ) -> Result<(), KernoidError> {
        let vaults = self.vaults()?;
        run(async move { vaults.set_trashed(&space_vault(vault_id, space), parent.as_deref(), &entry, trashed).await })
            .await
    }

    /// Removes something of a vault on a space for good.
    pub async fn vault_remove(
        &self,
        vault_id: String,
        space: String,
        parent: Option<String>,
        entry: String,
    ) -> Result<(), KernoidError> {
        let vaults = self.vaults()?;
        run(async move { vaults.remove(&space_vault(vault_id, space), parent.as_deref(), &entry).await }).await
    }

    /// After sharing a vault on a space: brings its members in line with `shares` (principal and level `read`, `edit`
    /// or `full`) – new ones get a code sealed to their key, those gone leave, those with another level come in again.
    /// Returns those who wait – groups, and people without a key.
    pub async fn share_space_vault(
        &self,
        account_id: String,
        vault_id: String,
        space: String,
        shares: Vec<FileShare>,
    ) -> Result<Vec<Principal>, KernoidError> {
        let (client, e2e, vaults) = (self.client.clone(), self.e2e.clone(), self.vaults()?);
        let waiting = run(async move {
            let ids: Vec<&str> = shares.iter().map(|s| s.principal_id.as_str()).collect();
            let found = files::principals(&client, &ids).await?;
            let people: Vec<(files::Principal, client::e2e::Level)> = found
                .into_iter()
                .map(|p| {
                    let level = match shares.iter().find(|s| s.principal_id == p.id).map(|s| s.level.as_str()) {
                        Some("full") => client::e2e::Level::Full,
                        Some("edit") => client::e2e::Level::Edit,
                        _ => client::e2e::Level::Read,
                    };
                    (p, level)
                })
                .collect();
            let mut e2e = e2e.lock().await;
            vaults.share(&client, &mut e2e, &account_id, &space_vault(vault_id, space), &people).await
        })
        .await?;
        Ok(waiting.into_iter().map(principal).collect())
    }

    /// How far this device may go in a vault on a space: `read`, `edit` or `full`.
    pub async fn vault_level(&self, vault_id: String, space: String) -> Result<String, KernoidError> {
        let vaults = self.vaults()?;
        let level = run(async move { vaults.level(&space_vault(vault_id, space)).await }).await?;
        Ok(match level {
            client::e2e::Level::Read => "read",
            client::e2e::Level::Edit => "edit",
            client::e2e::Level::Full => "full",
        }
        .into())
    }

    /// Renames a vault on a space.
    pub async fn rename_space_vault(&self, vault_id: String, space: String, name: String) -> Result<(), KernoidError> {
        let vaults = self.vaults()?;
        run(async move { vaults.rename_vault(&space_vault(vault_id, space), name.trim()).await }).await
    }

    /// Ends a member's membership of a vault on a space: what is written from now on is out of their reach.
    pub async fn remove_vault_member(
        &self,
        account_id: String,
        vault_id: String,
        space: String,
        member: String,
    ) -> Result<(), KernoidError> {
        let (client, vaults) = (self.client.clone(), self.vaults()?);
        run(async move { vaults.remove_member(&client, &account_id, &space_vault(vault_id, space), &member).await })
            .await
    }

    /// Copies an OpenPGP vault onto a space beside it (name, directories, files, members); returns the new vault's
    /// id. The old one stays until it is removed.
    pub async fn move_vault(&self, account_id: String, vault_id: String) -> Result<String, KernoidError> {
        let (client, e2e, vaults) = (self.client.clone(), self.e2e.clone(), self.vaults()?);
        run(async move {
            let old = files::get(&client, &account_id, &vault_id).await?;
            let mut e2e = e2e.lock().await;
            vaults.move_vault(&client, &mut e2e, &account_id, &old).await
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn downloads_stay_in_their_directory_and_do_not_overwrite() {
        let dir = std::env::temp_dir().join(format!("kernoid-test-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        assert_eq!(unique_path(&dir, "../../etc/passwd").await, dir.join("passwd"));
        tokio::fs::write(dir.join("a.txt"), b"x").await.unwrap();
        assert_eq!(unique_path(&dir, "a.txt").await, dir.join("a (2).txt"));
        assert_eq!(unique_path(&dir, "..").await, dir.join("download"));
        tokio::fs::remove_dir_all(&dir).await.unwrap();
    }

    #[test]
    fn only_addresses_are_recipients() {
        assert_eq!(recipients(&[" a@x ".into(), "".into(), "nope".into()]), vec!["a@x".to_owned()]);
    }
}
