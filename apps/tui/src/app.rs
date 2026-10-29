// SPDX-License-Identifier: MIT
//! What the app shows and how keys change it. Calls to the server run while the screen waits – they are short –;
//! downloads and uploads run in threads of their own and report how far they got; push tells what to load again.

use std::{
    path::{Path, PathBuf},
    sync::mpsc::Sender,
    thread,
};

use chrono::{DateTime, Datelike, Duration, Local, NaiveDate, TimeZone, Timelike, Utc};
use ratatui::{
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers},
    widgets::ListState,
};

use kernoid_tui::{
    compose::{self, Kind, Message},
    forms,
    jmap::{
        self, Client, MAIL,
        calendars::{self, Calendar, Event, EventForm},
        contacts::{self, AddressBook, Card, CardForm},
        files::{self, FileLink, FileNode, Level, LinkMode, Principal, Store, Version},
        mail::{self, Conversation, Email, EmailSummary, Identity, Mailbox, Vacation},
        push::Push,
        transfer,
    },
};

/// Emails loaded at once; more come when the selection reaches the end.
const PAGE: u64 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Mail,
    Files,
    Calendar,
    Contacts,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Mail, Tab::Files, Tab::Calendar, Tab::Contacts];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Mail => "Mail",
            Tab::Files => "Files",
            Tab::Calendar => "Calendar",
            Tab::Contacts => "Contacts",
        }
    }
}

/// What arrives from other threads.
#[derive(Debug)]
pub enum Background {
    Push(Push),
    Progress { id: u64, done: u64, total: Option<u64> },
    Finished { id: u64, result: Result<String, String> },
}

/// A download or upload under way.
#[derive(Debug, Clone)]
pub struct Transfer {
    pub id: u64,
    pub label: String,
    pub done: u64,
    pub total: Option<u64>,
    /// Load the files again once it is done (uploads).
    pub reload_files: bool,
}

/// What a line of input is for.
#[derive(Debug, Clone)]
pub enum Prompt {
    SearchMail,
    SearchContacts,
    /// Save a blob to the path typed.
    Download {
        account: String,
        blob: String,
        name: String,
        kind: String,
    },
    /// Upload the local file typed into the current directory.
    Upload,
    NewFolder,
    Rename {
        id: String,
    },
    /// Find people or groups to share with.
    SharePrincipal(Sharing),
    /// Until when a new link works: a date, or nothing.
    LinkExpiry(Linking),
    /// The password of a new link, or nothing; `expires` from the step before.
    LinkPassword {
        linking: Linking,
        expires: Option<String>,
    },
    /// Write the event to the `.ics` file typed.
    ExportEvent {
        account: String,
        id: String,
    },
    /// Read the `.ics` file typed into the first calendar the user may write.
    ImportEvents,
    /// Write the contacts listed to the `.vcf` file typed.
    ExportCards,
    /// Read the `.vcf` file typed into the first address book the user may write.
    ImportCards,
}

#[derive(Debug, Clone)]
pub struct Input {
    pub prompt: Prompt,
    pub label: String,
    pub text: String,
    /// Shown as dots: a password.
    pub secret: bool,
}

#[derive(Debug, Clone)]
pub enum Destroy {
    Emails {
        ids: Vec<String>,
    },
    Node {
        id: String,
        name: String,
    },
    /// An event – or, with `instance`, one instance of a series (`o`), the series being `y`.
    Event {
        account: String,
        id: String,
        title: String,
        instance: Option<String>,
    },
    Card {
        account: String,
        id: String,
        name: String,
    },
}

/// What is open in the user's editor.
#[derive(Debug, Clone)]
pub enum Edit {
    Message(Message),
    /// An event in the calendar of that index; `id` (account, event) when it exists already; `instance` the recurrence
    /// id of the one instance of the series changed alone.
    Event {
        form: EventForm,
        calendar: usize,
        id: Option<(String, String)>,
        instance: Option<String>,
    },
    /// A contact in the address book of that index; `id` (account, card) when it exists already.
    Card {
        form: CardForm,
        book: usize,
        id: Option<(String, String)>,
    },
    /// The vacation response.
    Vacation(Vacation),
}

/// With whom a directory is being shared, before it is saved.
#[derive(Debug, Clone)]
pub struct Sharing {
    pub node: FileNode,
    pub entries: Vec<(Principal, Level)>,
    pub selected: usize,
}

/// The links to a file or folder, and the mode of the next one.
#[derive(Debug, Clone)]
pub struct Linking {
    pub account: String,
    pub node: FileNode,
    pub list: Vec<FileLink>,
    pub selected: usize,
    pub mode: LinkMode,
    /// The address of the link just made – shown this once.
    pub made: Option<String>,
}

/// A window over the rest.
#[derive(Debug, Clone)]
pub enum Popup {
    Help,
    /// Choose the mailbox to move the open or selected emails to.
    Move {
        emails: Vec<String>,
        selected: usize,
    },
    /// The attachments of the open email; Enter saves one.
    Attachments {
        selected: usize,
    },
    /// The versions of a file; Enter saves one, `r` makes it current.
    Versions {
        node: FileNode,
        list: Vec<Version>,
        selected: usize,
    },
    /// A message written in the editor: send, keep as draft, edit again or drop.
    Written {
        message: Message,
        error: Option<String>,
    },
    Confirm {
        what: Destroy,
        text: String,
    },
    /// An event or contact the server did not take, or that could not be read: edit again or drop.
    Unsaved {
        edit: Edit,
        error: String,
    },
    /// With whom a directory is shared: add, change the level, remove, save.
    Share(Sharing),
    /// The links to a file or folder: make one (in a mode), remove one.
    Links(Linking),
    /// People and groups found for sharing: choose one.
    Pick {
        sharing: Sharing,
        found: Vec<Principal>,
        selected: usize,
    },
    /// Text to read (details of an event, of a file).
    Info {
        title: String,
        text: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailFocus {
    Mailboxes,
    List,
    Reader,
}

#[derive(Debug, Default)]
pub struct MailState {
    /// The accounts with mail: the own first, then shared mailboxes.
    pub accounts: Vec<(String, String)>,
    pub account: usize,
    pub mailboxes: Vec<Mailbox>,
    pub boxes: ListState,
    /// The rows of the list: conversations, or – without threads – single emails.
    pub emails: Vec<Conversation>,
    pub total: u64,
    pub list: ListState,
    pub search: String,
    /// Show conversations (threads) rather than single emails.
    pub threads: bool,
    /// The emails open in the reader, oldest first, and their text.
    pub open: Vec<Email>,
    pub texts: Vec<String>,
    pub scroll: u16,
    pub identities: Vec<Identity>,
    pub loaded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesFocus {
    Stores,
    Nodes,
}

#[derive(Debug, Default)]
pub struct FilesState {
    pub stores: Vec<Store>,
    pub store_list: ListState,
    /// The directories from the top of the store down to the one shown.
    pub path: Vec<FileNode>,
    pub nodes: Vec<FileNode>,
    pub list: ListState,
    pub loaded: bool,
}

#[derive(Debug, Default)]
pub struct CalendarState {
    pub calendars: Vec<Calendar>,
    /// The first day shown.
    pub from: Option<NaiveDate>,
    pub events: Vec<Event>,
    pub list: ListState,
    pub loaded: bool,
}

#[derive(Debug, Default)]
pub struct ContactsState {
    pub books: Vec<AddressBook>,
    pub cards: Vec<Card>,
    pub list: ListState,
    pub search: String,
    pub loaded: bool,
}

/// Days the calendar shows at once.
pub const DAYS: i64 = 14;

pub struct App {
    pub client: Client,
    pub tab: Tab,
    pub status: String,
    pub error: bool,
    pub online: bool,
    pub input: Option<Input>,
    pub popup: Option<Popup>,
    pub mail: MailState,
    pub mail_focus: MailFocus,
    pub files: FilesState,
    pub files_focus: FilesFocus,
    pub calendar: CalendarState,
    pub contacts: ContactsState,
    pub transfers: Vec<Transfer>,
    pub downloads: PathBuf,
    pub quit: bool,
    /// What to open in the editor; the main loop does it, as it owns the terminal.
    pub edit: Option<Edit>,
    /// Width of the reading pane, for HTML turned into text.
    pub reader_width: usize,
    background: Sender<Background>,
    next_transfer: u64,
}

impl std::fmt::Debug for App {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("App").field("tab", &self.tab).finish_non_exhaustive()
    }
}

fn select(state: &mut ListState, len: usize, index: usize) {
    state.select(if len == 0 { None } else { Some(index.min(len - 1)) });
}

/// Moves a selection by `delta`, staying in the list.
fn step(state: &mut ListState, len: usize, delta: isize) {
    let current = state.selected().unwrap_or(0) as isize;
    select(state, len, (current + delta).max(0) as usize);
}

/// A free path for a download: the name, or the name with a number.
pub fn free_path(dir: &Path, name: &str) -> PathBuf {
    let name = sanitize(name);
    let path = dir.join(&name);
    if !path.exists() {
        return path;
    }
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => (stem.to_owned(), format!(".{extension}")),
        _ => (name.clone(), String::new()),
    };
    (1..).map(|n| dir.join(format!("{stem} ({n}){extension}"))).find(|path| !path.exists()).unwrap_or(path)
}

/// A file name that stays in its directory: no separators, not `.` or `..`.
pub fn sanitize(name: &str) -> String {
    let name: String = name.chars().map(|c| if c == '/' || c == '\\' || c.is_control() { '_' } else { c }).collect();
    match name.trim() {
        "" | "." | ".." => "download".to_owned(),
        name => name.to_owned(),
    }
}

/// `~/x` as the home directory's `x`.
/// A file name from a title: what file systems refuse taken out.
fn file_name(title: &str, extension: &str) -> String {
    let name: String = title.chars().map(|c| if c.is_alphanumeric() || " -_.".contains(c) { c } else { '_' }).collect();
    let name = name.trim();
    format!("{}.{extension}", if name.is_empty() { "export" } else { name })
}

/// Writes a new file – one that is there already stays as it is.
fn write_new(path: &std::path::Path, text: &str) -> Result<(), String> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(text.as_bytes()).map_err(|error| format!("{}: {error}", path.display()))
}

pub fn expand(path: &str) -> PathBuf {
    match (path.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => PathBuf::from(path),
    }
}

impl App {
    pub fn new(client: Client, downloads: PathBuf, background: Sender<Background>) -> Self {
        let mut app = Self {
            client,
            tab: Tab::Mail,
            status: String::new(),
            error: false,
            online: false,
            input: None,
            popup: None,
            mail: MailState { threads: true, ..MailState::default() },
            mail_focus: MailFocus::List,
            files: FilesState::default(),
            files_focus: FilesFocus::Nodes,
            calendar: CalendarState::default(),
            contacts: ContactsState::default(),
            transfers: Vec::new(),
            downloads,
            quit: false,
            edit: None,
            reader_width: 80,
            background,
            next_transfer: 0,
        };
        let has =
            |capability| app.client.session.accounts.values().any(|a| a.account_capabilities.contains_key(capability));
        if !has(MAIL) && has(jmap::FILENODE) {
            app.tab = Tab::Files;
        }
        app.load_tab();
        app
    }

    fn info(&mut self, text: impl Into<String>) {
        self.status = text.into();
        self.error = false;
    }

    fn fail(&mut self, error: impl std::fmt::Display) {
        self.status = error.to_string();
        self.error = true;
    }

    /// Runs `f`; its error goes to the status line.
    fn attempt<T>(&mut self, f: impl FnOnce(&mut Self) -> jmap::Result<T>) -> Option<T> {
        match f(self) {
            Ok(value) => Some(value),
            Err(error) => {
                self.fail(error);
                None
            }
        }
    }

    /// Loads what the current tab shows, the first time.
    pub fn load_tab(&mut self) {
        self.status.clear();
        match self.tab {
            Tab::Mail if !self.mail.loaded => self.load_mail(),
            Tab::Files if !self.files.loaded => self.load_files(),
            Tab::Calendar if !self.calendar.loaded => self.load_calendar(),
            Tab::Contacts if !self.contacts.loaded => self.load_contacts(),
            _ => {}
        }
    }

    /// Loads the current tab again.
    pub fn reload(&mut self) {
        match self.tab {
            Tab::Mail => {
                self.load_mailboxes();
                self.load_emails(false);
            }
            Tab::Files => {
                // Stores shared since the login appear in a new session.
                let store = self.store().map(|s| s.id.clone());
                if self.attempt(|app| app.client.refresh_session()).is_some() {
                    self.files.stores = files::stores(&self.client);
                    match store.and_then(|id| self.files.stores.iter().position(|s| s.id == id)) {
                        Some(index) => self.files.store_list.select(Some(index)),
                        None => {
                            select(&mut self.files.store_list, self.files.stores.len(), 0);
                            self.files.path.clear();
                        }
                    }
                }
                self.load_nodes();
            }
            Tab::Calendar => self.load_events(),
            Tab::Contacts => self.load_cards(),
        }
    }

    // Mail.

    pub fn mail_account(&self) -> Option<&str> {
        self.mail.accounts.get(self.mail.account).map(|(id, _)| id.as_str())
    }

    pub fn mailbox(&self) -> Option<&Mailbox> {
        self.mail.boxes.selected().and_then(|i| self.mail.mailboxes.get(i))
    }

    pub fn selected_conversation(&self) -> Option<&Conversation> {
        self.mail.list.selected().and_then(|i| self.mail.emails.get(i))
    }

    /// What identifies a row of the list across loads: the thread, or the email.
    fn row_key(&self, conversation: &Conversation) -> String {
        if self.mail.threads { conversation.latest.thread_id.clone() } else { conversation.latest.id.clone() }
    }

    fn load_mail(&mut self) {
        self.mail.accounts = self
            .client
            .session
            .accounts_with(MAIL)
            .into_iter()
            .map(|(id, account)| (id.to_owned(), account.name.clone()))
            .collect();
        self.mail.loaded = true;
        if self.mail.accounts.is_empty() {
            self.info("this account has no mail");
            return;
        }
        self.switch_mail_account(0);
    }

    fn switch_mail_account(&mut self, index: usize) {
        self.mail.account = index;
        self.mail.mailboxes.clear();
        self.mail.boxes.select(None);
        self.close_reader();
        self.load_mailboxes();
        let inbox = self.mail.mailboxes.iter().position(|m| m.role.as_deref() == Some("inbox")).unwrap_or(0);
        select(&mut self.mail.boxes, self.mail.mailboxes.len(), inbox);
        self.load_emails(true);
        let Some(account) = self.mail_account().map(str::to_owned) else { return };
        self.mail.identities = mail::identities(&self.client, &account).unwrap_or_default();
    }

    fn load_mailboxes(&mut self) {
        let Some(account) = self.mail_account().map(str::to_owned) else { return };
        let selected = self.mailbox().map(|m| m.id.clone());
        if let Some(list) = self.attempt(|app| mail::mailboxes(&app.client, &account)) {
            self.mail.mailboxes = list;
            let index = selected.and_then(|id| self.mail.mailboxes.iter().position(|m| m.id == id)).unwrap_or(0);
            select(&mut self.mail.boxes, self.mail.mailboxes.len(), index);
        }
    }

    /// A page of the selected mailbox: conversations, or single emails.
    fn fetch_emails(&mut self, position: u64, limit: u64) -> Option<(Vec<Conversation>, u64)> {
        let account = self.mail_account()?.to_owned();
        let mailbox = self.mailbox()?.id.clone();
        let search = self.mail.search.clone();
        if self.mail.threads {
            self.attempt(|app| mail::conversations(&app.client, &account, Some(&mailbox), &search, position, limit))
        } else {
            self.attempt(|app| mail::emails(&app.client, &account, Some(&mailbox), &search, position, limit)).map(
                |(list, total)| {
                    let list = list
                        .into_iter()
                        .map(|email| Conversation { latest: email.clone(), emails: vec![email] })
                        .collect();
                    (list, total)
                },
            )
        }
    }

    /// Loads the first page of the selected mailbox; `reset` selects the first row, else the selected one stays.
    fn load_emails(&mut self, reset: bool) {
        if self.mail_account().is_none() || self.mailbox().is_none() {
            self.mail.emails.clear();
            return;
        }
        let selected = if reset { None } else { self.selected_conversation().map(|c| self.row_key(c)) };
        let limit = if reset { PAGE } else { (self.mail.emails.len() as u64).max(PAGE) };
        if let Some((list, total)) = self.fetch_emails(0, limit) {
            self.mail.emails = list;
            self.mail.total = total;
            let index =
                selected.and_then(|key| self.mail.emails.iter().position(|c| self.row_key(c) == key)).unwrap_or(0);
            select(&mut self.mail.list, self.mail.emails.len(), index);
        }
    }

    fn load_more_emails(&mut self) {
        let loaded = self.mail.emails.len() as u64;
        if loaded >= self.mail.total {
            return;
        }
        if let Some((list, total)) = self.fetch_emails(loaded, PAGE) {
            self.mail.emails.extend(list);
            self.mail.total = total;
        }
    }

    fn close_reader(&mut self) {
        self.mail.open.clear();
        self.mail.texts.clear();
        if self.mail_focus == MailFocus::Reader {
            self.mail_focus = MailFocus::List;
        }
    }

    /// Opens the selected row: all emails of the conversation, oldest first; the unread ones become read.
    fn open_email(&mut self) {
        let (Some(account), Some(conversation)) =
            (self.mail_account().map(str::to_owned), self.selected_conversation().cloned())
        else {
            return;
        };
        let ids: Vec<&str> = conversation.emails.iter().map(|e| e.id.as_str()).collect();
        let Some(emails) = self.attempt(|app| mail::full(&app.client, &account, &ids)) else { return };
        if emails.is_empty() {
            return;
        }
        let width = self.reader_width.saturating_sub(2);
        self.mail.texts = emails.iter().map(|email| email.text(width)).collect();
        self.mail.scroll = 0;
        let unread: Vec<String> =
            emails.iter().filter(|e| !e.summary.is_seen()).map(|e| e.summary.id.clone()).collect();
        if !unread.is_empty()
            && self.attempt(|app| mail::set_keywords(&app.client, &account, &unread, "$seen", true)).is_some()
        {
            if let Some(row) = self.mail.list.selected().and_then(|i| self.mail.emails.get_mut(i)) {
                for email in row.emails.iter_mut().chain(std::iter::once(&mut row.latest)) {
                    if unread.contains(&email.id) {
                        email.keywords.insert("$seen".into(), true);
                    }
                }
            }
            self.load_mailboxes();
        }
        self.mail.open = emails;
        self.mail_focus = MailFocus::Reader;
    }

    /// The emails keys act on: in the reader those open (of the mailbox shown), else the selected conversation's
    /// emails in the mailbox shown.
    fn target_emails(&self) -> Vec<String> {
        let mailbox = self.mailbox().map(|m| m.id.clone()).unwrap_or_default();
        if self.mail_focus == MailFocus::Reader && !self.mail.open.is_empty() {
            let here: Vec<String> = self
                .mail
                .open
                .iter()
                .filter(|e| e.summary.mailbox_ids.get(&mailbox).copied().unwrap_or(false))
                .map(|e| e.summary.id.clone())
                .collect();
            if !here.is_empty() {
                return here;
            }
            return self.mail.open.iter().map(|e| e.summary.id.clone()).collect();
        }
        self.selected_conversation().map(|c| c.ids_in(&mailbox)).unwrap_or_default()
    }

    fn toggle_keyword(&mut self, keyword: &str) {
        let (Some(account), ids) = (self.mail_account().map(str::to_owned), self.target_emails()) else { return };
        if ids.is_empty() {
            return;
        }
        let has = |email: &EmailSummary| email.keywords.get(keyword).copied().unwrap_or(false);
        let all = self
            .mail
            .emails
            .iter()
            .flat_map(|c| c.emails.iter().chain(std::iter::once(&c.latest)))
            .filter(|e| ids.contains(&e.id))
            .all(has);
        let on = !all;
        if self.attempt(|app| mail::set_keywords(&app.client, &account, &ids, keyword, on)).is_some() {
            for email in
                self.mail.emails.iter_mut().flat_map(|c| c.emails.iter_mut().chain(std::iter::once(&mut c.latest)))
            {
                if ids.contains(&email.id) {
                    email.keywords.insert(keyword.into(), on);
                }
            }
            self.load_mailboxes();
        }
    }

    fn delete_email(&mut self) {
        let (Some(account), ids) = (self.mail_account().map(str::to_owned), self.target_emails()) else { return };
        if ids.is_empty() {
            return;
        }
        let trash = self.mail.mailboxes.iter().find(|m| m.role.as_deref() == Some("trash")).map(|m| m.id.clone());
        let in_trash = self.mailbox().map(|m| Some(&m.id) == trash.as_ref()).unwrap_or(false);
        match trash {
            Some(trash) if !in_trash => {
                if self.attempt(|app| mail::move_all(&app.client, &account, &ids, &trash)).is_some() {
                    self.info(if ids.len() == 1 {
                        "moved to the trash".to_owned()
                    } else {
                        format!("{} emails moved to the trash", ids.len())
                    });
                    self.after_email_left(&ids);
                }
            }
            _ => {
                let text = if ids.len() == 1 {
                    "Delete this email for good? (y/n)".to_owned()
                } else {
                    format!("Delete these {} emails for good? (y/n)", ids.len())
                };
                self.popup = Some(Popup::Confirm { what: Destroy::Emails { ids }, text })
            }
        }
    }

    /// Emails left the mailbox shown.
    fn after_email_left(&mut self, ids: &[String]) {
        if self.mail.open.iter().any(|e| ids.contains(&e.summary.id)) {
            self.close_reader();
        }
        self.load_mailboxes();
        self.load_emails(false);
    }

    fn move_email(&mut self, to: usize) {
        let (Some(account), Some(Popup::Move { emails, .. })) =
            (self.mail_account().map(str::to_owned), self.popup.take())
        else {
            return;
        };
        let Some(mailbox) = self.mail.mailboxes.get(to).cloned() else { return };
        if self.attempt(|app| mail::move_all(&app.client, &account, &emails, &mailbox.id)).is_some() {
            self.info(format!("moved to {}", mailbox.name));
            self.after_email_left(&emails);
        }
    }

    fn write(&mut self, kind: Kind) {
        // A reply answers the newest message of the conversation.
        let original = if kind == Kind::New { None } else { self.mail.open.last().cloned() };
        if kind != Kind::New && original.is_none() {
            self.fail("open an email first");
            return;
        }
        let identity = compose::identity_for(original.as_ref(), &self.mail.identities).cloned();
        if identity.is_none() {
            self.fail("this account may not send");
            return;
        }
        let text = self.mail.texts.last().cloned().unwrap_or_default();
        let message = compose::start(
            kind,
            original.as_ref().map(|e| (e, text.as_str())),
            identity.as_ref(),
            &self.mail.identities,
        );
        self.edit = Some(Edit::Message(message));
    }

    /// The text the editor opens with.
    pub fn edit_text(&self, edit: &Edit) -> String {
        match edit {
            Edit::Message(message) => compose::render(message),
            Edit::Event { form, calendar, .. } => {
                let names: Vec<String> = self.writable_calendars().iter().map(|c| calendar_name(c)).collect();
                let name = self.calendar.calendars.get(*calendar).map(calendar_name).unwrap_or_default();
                forms::render_event(form, &name, &names)
            }
            Edit::Card { form, book, .. } => {
                let names: Vec<String> = self.writable_books().iter().map(|b| book_name(b)).collect();
                let name = self.contacts.books.get(*book).map(book_name).unwrap_or_default();
                forms::render_card(form, &name, &names)
            }
            Edit::Vacation(vacation) => forms::render_vacation(vacation),
        }
    }

    /// The editor closed with `text`, written from `edit`.
    pub fn edited(&mut self, edit: Edit, text: Result<String, String>) {
        match edit {
            Edit::Message(message) => {
                let popup = match text.and_then(|text| compose::parse(&text, &message)) {
                    Ok(message) => Popup::Written { message, error: None },
                    Err(error) => Popup::Written { message, error: Some(error) },
                };
                self.popup = Some(popup);
            }
            Edit::Event { form, calendar, id, instance } => {
                let parsed = text.and_then(|text| forms::parse_event(&text, &form));
                match parsed.and_then(|(new, name)| {
                    let index = self.calendar_named(&name, calendar)?;
                    Ok((new, index))
                }) {
                    Ok((new, index)) => self.save_event(new, index, id, instance),
                    Err(error) => {
                        self.popup = Some(Popup::Unsaved { edit: Edit::Event { form, calendar, id, instance }, error })
                    }
                }
            }
            Edit::Card { form, book, id } => {
                let parsed = text.and_then(|text| forms::parse_card(&text));
                match parsed.and_then(|(new, name)| Ok((new, self.book_named(&name, book)?))) {
                    Ok((new, index)) => self.save_card(new, index, id),
                    Err(error) => self.popup = Some(Popup::Unsaved { edit: Edit::Card { form, book, id }, error }),
                }
            }
            Edit::Vacation(vacation) => match text.and_then(|text| forms::parse_vacation(&text)) {
                Ok(new) => match mail::set_vacation(&self.client, &new) {
                    Ok(()) => {
                        self.info(if new.on { "the vacation response is on" } else { "the vacation response is off" })
                    }
                    Err(error) => {
                        self.popup = Some(Popup::Unsaved { edit: Edit::Vacation(new), error: error.to_string() })
                    }
                },
                Err(error) => self.popup = Some(Popup::Unsaved { edit: Edit::Vacation(vacation), error }),
            },
        }
    }

    /// Opens the vacation response in the editor.
    fn edit_vacation(&mut self) {
        match self.attempt(|app| mail::vacation(&app.client)) {
            Some(Some(vacation)) => self.edit = Some(Edit::Vacation(vacation)),
            Some(None) => self.fail("this server has no vacation response for you"),
            None => {}
        }
    }

    fn send(&mut self, message: Message, keep: bool) {
        let Some(account) = self.mail_account().map(str::to_owned) else { return };
        let identity = compose::chosen(&message.from, &self.mail.identities).cloned();
        let mut draft = message.draft.clone();
        if !keep && draft.to.is_empty() && draft.cc.is_empty() && draft.bcc.is_empty() {
            self.popup = Some(Popup::Written { message, error: Some("no recipients".into()) });
            return;
        }
        let Some(identity) = identity else {
            self.popup = Some(Popup::Written { message, error: Some("you may not send as this From address".into()) });
            return;
        };
        for path in &message.files {
            match mail::attach(&self.client, &account, path) {
                Ok(attachment) => draft.attachments.push(attachment),
                Err(error) => {
                    let error = format!("{}: {error}", path.display());
                    self.popup = Some(Popup::Written { message, error: Some(error) });
                    return;
                }
            }
        }
        let boxes = self.mail.mailboxes.clone();
        let result = if keep {
            draft.from = compose::chosen(&message.from, &self.mail.identities).map(|identity| mail::EmailAddress {
                name: (!identity.name.is_empty()).then(|| identity.name.clone()),
                email: identity.email.clone(),
            });
            mail::save_draft(&self.client, &account, &draft, &boxes).map(|_| "kept in Drafts")
        } else {
            mail::send(&self.client, &account, &identity, &draft, &boxes).map(|_| "sent")
        };
        match result {
            Ok(done) => {
                self.info(done);
                self.load_mailboxes();
                self.load_emails(false);
            }
            Err(error) => self.popup = Some(Popup::Written { message, error: Some(error.to_string()) }),
        }
    }

    /// The attachments of the open emails, with the account they are in.
    pub fn attachments(&self) -> Vec<mail::BodyPart> {
        self.mail.open.iter().flat_map(|e| e.attachments.iter().cloned()).collect()
    }

    // Files.

    pub fn store(&self) -> Option<&Store> {
        self.files.store_list.selected().and_then(|i| self.files.stores.get(i))
    }

    pub fn selected_node(&self) -> Option<&FileNode> {
        self.files.list.selected().and_then(|i| self.files.nodes.get(i))
    }

    fn load_files(&mut self) {
        self.files.stores = files::stores(&self.client);
        self.files.loaded = true;
        select(&mut self.files.store_list, self.files.stores.len(), 0);
        if self.files.stores.is_empty() {
            self.info("this account has no files");
        }
        self.files.path.clear();
        self.load_nodes();
    }

    fn load_nodes(&mut self) {
        let Some(store) = self.store().map(|s| s.id.clone()) else {
            self.files.nodes.clear();
            return;
        };
        let selected = self.selected_node().map(|n| n.id.clone());
        let parent = self.files.path.last().map(|n| n.id.clone());
        if let Some(nodes) = self.attempt(|app| files::children(&app.client, &store, parent.as_deref())) {
            self.files.nodes = nodes;
            let index = selected.and_then(|id| self.files.nodes.iter().position(|n| n.id == id)).unwrap_or(0);
            select(&mut self.files.list, self.files.nodes.len(), index);
        }
    }

    fn enter_node(&mut self) {
        let Some(node) = self.selected_node().cloned() else { return };
        if node.is_directory() {
            self.files.path.push(node);
            self.files.list.select(None);
            self.load_nodes();
            select(&mut self.files.list, self.files.nodes.len(), 0);
        } else {
            self.show_versions();
        }
    }

    fn leave_directory(&mut self) {
        if let Some(left) = self.files.path.pop() {
            self.load_nodes();
            if let Some(index) = self.files.nodes.iter().position(|n| n.id == left.id) {
                self.files.list.select(Some(index));
            }
        }
    }

    fn show_versions(&mut self) {
        let (Some(store), Some(node)) = (self.store().map(|s| s.id.clone()), self.selected_node().cloned()) else {
            return;
        };
        if node.is_directory() {
            return;
        }
        if let Some(list) = self.attempt(|app| files::versions(&app.client, &store, &node.id)) {
            self.popup = Some(Popup::Versions { node, list, selected: 0 });
        }
    }

    fn node_info(&mut self) {
        let Some(node) = self.selected_node().cloned() else { return };
        let mut text = format!("Name: {}\n", node.name);
        if let Some(size) = node.size {
            text.push_str(&format!("Size: {}\n", size_text(size)));
        }
        if let Some(kind) = &node.media_type {
            text.push_str(&format!("Type: {kind}\n"));
        }
        if let Some(modified) = &node.modified {
            text.push_str(&format!("Modified: {}\n", time_text(modified)));
        }
        // Rights are a directory's (draft-ietf-jmap-filenode, 3); a file has those of the directory it is in.
        let rights = node.my_rights.or_else(|| self.files.path.last().and_then(|parent| parent.my_rights));
        let mut may = Vec::new();
        let rights = rights.unwrap_or_default();
        for (on, name) in [
            (rights.may_read, "read"),
            (rights.may_add_children, "add"),
            (rights.may_rename, "rename"),
            (rights.may_delete, "delete"),
            (rights.may_modify_content, "change"),
            (rights.may_share, "share"),
        ] {
            if on {
                may.push(name);
            }
        }
        if !may.is_empty() {
            text.push_str(&format!("You may: {}\n", may.join(", ")));
        }
        if let Some(shared) = node.share_with.as_ref().filter(|s| !s.is_empty()) {
            let ids: Vec<&str> = shared.keys().map(String::as_str).collect();
            let people = files::principals(&self.client, &ids).unwrap_or_default();
            text.push_str("Shared with:\n");
            for (id, rights) in shared {
                let who = people
                    .iter()
                    .find(|p| &p.id == id)
                    .map(|p| match &p.email {
                        Some(email) => format!("{} <{email}>", p.name),
                        None => p.name.clone(),
                    })
                    .unwrap_or_else(|| id.clone());
                let level = if rights.may_share {
                    "full"
                } else if rights.may_modify_content || rights.may_add_children {
                    "edit"
                } else {
                    "read"
                };
                text.push_str(&format!("  {who}: {level}\n"));
            }
        }
        self.popup = Some(Popup::Info { title: node.name, text });
    }

    fn delete_node(&mut self) {
        let (Some(store), Some(node)) = (self.store().map(|s| s.id.clone()), self.selected_node().cloned()) else {
            return;
        };
        let in_trash = self.files.path.iter().any(|n| n.role.as_deref() == Some("trash"));
        let trash =
            if in_trash || node.role.is_some() { None } else { files::trash(&self.client, &store).ok().flatten() };
        match trash {
            Some(trash) => {
                if self.attempt(|app| files::move_to(&app.client, &store, &node.id, Some(&trash.id))).is_some() {
                    self.info(format!("{} moved to the trash", node.name));
                    self.load_nodes();
                }
            }
            None => {
                self.popup = Some(Popup::Confirm {
                    text: format!("Delete {} and all it holds for good? (y/n)", node.name),
                    what: Destroy::Node { id: node.id, name: node.name },
                })
            }
        }
    }

    /// Starts a download in a thread of its own.
    fn download(&mut self, account: String, blob: String, name: String, kind: String, path: PathBuf) {
        let id = self.next_transfer;
        self.next_transfer += 1;
        let label = format!("↓ {}", path.display());
        self.transfers.push(Transfer { id, label, done: 0, total: None, reload_files: false });
        let client = self.client.clone();
        let out = self.background.clone();
        thread::spawn(move || {
            let result = (|| -> Result<String, String> {
                if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
                }
                let partial = path.with_extension(match path.extension() {
                    Some(extension) => format!("{}.part", extension.to_string_lossy()),
                    None => "part".into(),
                });
                let mut file = std::fs::File::create(&partial).map_err(|e| format!("{}: {e}", partial.display()))?;
                let mut last = std::time::Instant::now();
                let done = client
                    .download(&account, &blob, &name, &kind, &mut file, &mut |done, total| {
                        if last.elapsed().as_millis() > 100 {
                            last = std::time::Instant::now();
                            let _ = out.send(Background::Progress { id, done, total });
                        }
                    })
                    .map_err(|e| {
                        let _ = std::fs::remove_file(&partial);
                        e.to_string()
                    })?;
                file.sync_all().map_err(|e| e.to_string())?;
                std::fs::rename(&partial, &path).map_err(|e| e.to_string())?;
                Ok(format!("saved {} ({})", path.display(), size_text(done)))
            })();
            let _ = out.send(Background::Finished { id, result });
        });
    }

    fn upload(&mut self, path: PathBuf) {
        let Some(store) = self.store().map(|s| s.id.clone()) else { return };
        if !path.is_file() {
            self.fail(format!("{}: no such file", path.display()));
            return;
        }
        let parent = self.files.path.last().map(|n| n.id.clone());
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let existing = self.files.nodes.iter().find(|n| n.name == name).cloned();
        let id = self.next_transfer;
        self.next_transfer += 1;
        self.transfers.push(Transfer { id, label: format!("↑ {name}"), done: 0, total: None, reload_files: true });
        let client = self.client.clone();
        let out = self.background.clone();
        thread::spawn(move || {
            let mut last = std::time::Instant::now();
            let result =
                files::upload_file(&client, &store, parent.as_deref(), &path, existing.as_ref(), &mut |done, total| {
                    if last.elapsed().as_millis() > 100 {
                        last = std::time::Instant::now();
                        let _ = out.send(Background::Progress { id, done, total: Some(total) });
                    }
                });
            let result = result
                .map(|()| match existing {
                    Some(_) => format!("uploaded {name} as a new version"),
                    None => format!("uploaded {name}"),
                })
                .map_err(|e| e.to_string());
            let _ = out.send(Background::Finished { id, result });
        });
    }

    // Calendar.

    fn load_calendar(&mut self) {
        self.calendar.loaded = true;
        if let Some(list) = self.attempt(|app| calendars::calendars(&app.client)) {
            self.calendar.calendars = list;
        }
        if self.calendar.from.is_none() {
            self.calendar.from = Some(Local::now().date_naive());
        }
        self.load_events();
    }

    pub fn calendar_window(&self) -> (DateTime<Utc>, DateTime<Utc>) {
        let from = self.calendar.from.unwrap_or_else(|| Local::now().date_naive());
        let start = Local
            .from_local_datetime(&from.and_hms_opt(0, 0, 0).unwrap_or_default())
            .earliest()
            .map(|t| t.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        (start, start + Duration::days(DAYS))
    }

    fn load_events(&mut self) {
        let (after, before) = self.calendar_window();
        let calendars = self.calendar.calendars.clone();
        let selected = self.selected_event().map(|e| e.id.clone());
        if let Some(events) = self.attempt(|app| calendars::instances(&app.client, &calendars, after, before)) {
            self.calendar.events = events;
            let index = selected.and_then(|id| self.calendar.events.iter().position(|e| e.id == id)).unwrap_or(0);
            select(&mut self.calendar.list, self.calendar.events.len(), index);
        }
    }

    fn shift_calendar(&mut self, days: i64) {
        let from = self.calendar.from.unwrap_or_else(|| Local::now().date_naive());
        self.calendar.from = Some(from + Duration::days(days));
        self.load_events();
    }

    fn event_info(&mut self) {
        let Some(event) = self.calendar.list.selected().and_then(|i| self.calendar.events.get(i)).cloned() else {
            return;
        };
        let mut text = String::new();
        text.push_str(&format!("When: {}\n", event_when(&event)));
        if event.is_cancelled() {
            text.push_str("Cancelled by the organizer\n");
        }
        if let Some(location) = event.location() {
            text.push_str(&format!("Where: {location}\n"));
        }
        let calendar = self
            .calendar
            .calendars
            .iter()
            .find(|c| c.account == event.account && event.calendar_ids.contains_key(&c.id));
        if let Some(calendar) = calendar {
            match &calendar.shared {
                Some(owner) => text.push_str(&format!("Calendar: {} ({owner})\n", calendar.name)),
                None => text.push_str(&format!("Calendar: {}\n", calendar.name)),
            }
        }
        if event.recurrence_rule.is_some() {
            text.push_str("Repeats\n");
        }
        if let Some(participants) = event.participants.as_ref().filter(|p| !p.is_empty()) {
            text.push_str("Participants:\n");
            for participant in participants.values() {
                let who = participant
                    .name
                    .clone()
                    .or_else(|| {
                        participant.calendar_address.as_ref().map(|a| a.trim_start_matches("mailto:").to_owned())
                    })
                    .unwrap_or_default();
                let status = participant.participation_status.as_deref().unwrap_or("needs-action");
                text.push_str(&format!("  {who} ({status})\n"));
            }
        }
        if let Some(description) = event.description.as_ref().filter(|d| !d.is_empty()) {
            text.push_str(&format!("\n{description}\n"));
        }
        let own = self.own_addresses();
        let mut keys = Vec::new();
        if let Some((_, me)) = event.me(&own).filter(|_| !event.organized_by(&own)) {
            let status = me.participation_status.clone().unwrap_or_else(|| "needs-action".into());
            text.push_str(&format!("\nYou are invited ({status})."));
            keys.push("a accept  m maybe  x decline");
        } else {
            keys.push("e edit");
        }
        keys.push("D delete");
        text.push_str(&format!("\n{}\n", keys.join("  ")));
        self.popup = Some(Popup::Info { title: event.title.clone().unwrap_or_else(|| "(no title)".into()), text });
    }

    /// The user's addresses: those they may send as, and the login.
    fn own_addresses(&mut self) -> Vec<String> {
        if self.mail.identities.is_empty()
            && let Some(account) = self.client.session.primary(MAIL).map(str::to_owned)
        {
            self.mail.identities = mail::identities(&self.client, &account).unwrap_or_default();
        }
        let mut out: Vec<String> = self.mail.identities.iter().map(|i| i.email.clone()).collect();
        out.push(self.client.session.username.clone());
        out
    }

    pub fn selected_event(&self) -> Option<&Event> {
        self.calendar.list.selected().and_then(|i| self.calendar.events.get(i))
    }

    pub fn writable_calendars(&self) -> Vec<&Calendar> {
        self.calendar.calendars.iter().filter(|c| c.writable()).collect()
    }

    /// The calendar a name in the editor means (as `calendar_name` writes them); empty: the one it was.
    fn calendar_named(&self, name: &str, current: usize) -> Result<usize, String> {
        if name.trim().is_empty() {
            return Ok(current);
        }
        self.calendar
            .calendars
            .iter()
            .position(|c| {
                c.writable()
                    && (calendar_name(c).eq_ignore_ascii_case(name.trim()) || c.name.eq_ignore_ascii_case(name.trim()))
            })
            .ok_or_else(|| format!("no calendar {name} that you may write"))
    }

    fn new_event(&mut self) {
        let Some(index) = self.calendar.calendars.iter().position(Calendar::writable) else {
            self.fail("no calendar you may write");
            return;
        };
        // The selected day, at the next full hour – or tomorrow at nine.
        let now = Local::now().naive_local();
        let day = self
            .selected_event()
            .and_then(|e| e.starts())
            .map(|s| s.with_timezone(&Local).date_naive())
            .unwrap_or(now.date());
        let hour = if day == now.date() { (now.time().hour() + 1).min(23) } else { 9 };
        let start = day.and_hms_opt(hour, 0, 0).unwrap_or(now);
        let form = EventForm {
            title: String::new(),
            all_day: false,
            start,
            end: start + Duration::hours(1),
            time_zone: calendars::local_time_zone(),
            location: String::new(),
            description: String::new(),
            participants: Vec::new(),
            repeat: None,
            answers: Vec::new(),
            was: None,
        };
        self.edit = Some(Edit::Event { form, calendar: index, id: None, instance: None });
    }

    /// The event an instance is of, as stored, with the index of its calendar.
    fn stored_event(&mut self) -> Option<(Event, usize)> {
        let instance = self.selected_event()?.clone();
        let stored = self.attempt(|app| calendars::event(&app.client, &instance.account, instance.event_id()))??;
        let index = self
            .calendar
            .calendars
            .iter()
            .position(|c| c.account == stored.account && stored.calendar_ids.contains_key(&c.id))?;
        Some((stored, index))
    }

    fn edit_event(&mut self) {
        let own = self.own_addresses();
        let Some((event, index)) = self.stored_event() else { return };
        if !self.calendar.calendars[index].writable() {
            self.fail("this calendar may not be written");
            return;
        }
        if !event.organized_by(&own) {
            self.fail("only the organizer changes it – answer with a, t or x");
            return;
        }
        let Some(form) = EventForm::of(&event, &own) else {
            self.fail("this event cannot be edited here");
            return;
        };
        let id = Some((event.account.clone(), event.id.clone()));
        self.edit = Some(Edit::Event { form, calendar: index, id, instance: None });
    }

    /// Changes the selected instance of a series alone.
    fn edit_instance(&mut self) {
        let own = self.own_addresses();
        let Some(instance) = self.selected_event().cloned() else { return };
        let (Some(_), Some(recurrence_id)) = (&instance.base_event_id, instance.recurrence_id.clone()) else {
            self.fail("not part of a series – change it with e");
            return;
        };
        let Some((series, index)) = self.stored_event() else { return };
        if !self.calendar.calendars[index].writable() || !series.organized_by(&own) {
            self.fail("only the organizer changes it, in a calendar that may be written");
            return;
        }
        let Some(mut form) = EventForm::of(&instance, &own) else {
            self.fail("this event cannot be edited here");
            return;
        };
        // An instance does not repeat; the series does.
        form.repeat = None;
        let id = Some((series.account.clone(), series.id.clone()));
        self.edit = Some(Edit::Event { form, calendar: index, id, instance: Some(recurrence_id) });
    }

    fn save_event(&mut self, form: EventForm, index: usize, id: Option<(String, String)>, instance: Option<String>) {
        let own = self.own_addresses().into_iter().next().unwrap_or_default();
        let Some(calendar) = self.calendar.calendars.get(index).cloned() else { return };
        let result = match (&id, &instance) {
            (Some((account, event)), Some(recurrence_id)) => calendars::event(&self.client, account, event)
                .and_then(|series| series.ok_or_else(|| jmap::Error::Protocol("the series is gone".into())))
                .and_then(|series| calendars::update_instance(&self.client, &series, recurrence_id, &form, &own))
                .map(|()| "this event of the series changed"),
            _ => self.save_whole_event(&calendar, &form, &id, &own),
        };

        match result {
            Ok(done) => {
                let invited = if form.participants.is_empty() {
                    String::new()
                } else {
                    format!(", {} invited", form.participants.len())
                };
                self.info(format!("{done}{invited}"));
                self.load_events();
            }
            Err(error) => {
                self.popup = Some(Popup::Unsaved {
                    edit: Edit::Event { form, calendar: index, id, instance },
                    error: error.to_string(),
                })
            }
        }
    }

    /// Makes an event, or changes one – all instances of a series.
    fn save_whole_event(
        &self,
        calendar: &Calendar,
        form: &EventForm,
        id: &Option<(String, String)>,
        own: &str,
    ) -> jmap::Result<&'static str> {
        match id {
            Some((account, event)) if *account == calendar.account => {
                calendars::update(&self.client, calendar, event, form, own).map(|()| "event changed")
            }
            Some(_) => Err(jmap::Error::Protocol("an event moves only between calendars of one account".into())),
            None => calendars::create(&self.client, calendar, form, own).map(|_| "event made"),
        }
    }

    fn delete_event(&mut self) {
        let own = self.own_addresses();
        let Some(instance) = self.selected_event().cloned() else { return };
        let title = instance.title.clone().unwrap_or_else(|| "(no title)".into());
        let repeats = self.stored_event().is_some_and(|(event, _)| event.recurrence_rule.is_some());
        let one = instance.recurrence_id.clone().filter(|_| repeats && instance.base_event_id.is_some());
        let text = if one.is_some() {
            format!("Delete {title}: this one (o), all of the series (y), or not (n)?")
        } else if repeats {
            format!("Delete {title} – all its instances – for good? (y/n)")
        } else {
            format!("Delete {title} for good? (y/n)")
        };
        let text = if instance.organized_by(&own) {
            text
        } else {
            format!("{text}\nYou are invited: the organizer is not told; decline with x for that.")
        };
        self.popup = Some(Popup::Confirm {
            what: Destroy::Event {
                account: instance.account.clone(),
                id: instance.event_id().to_owned(),
                title,
                instance: one,
            },
            text,
        });
    }

    fn answer_event(&mut self, status: &str) {
        let own = self.own_addresses();
        let Some(instance) = self.selected_event().cloned() else { return };
        let Some((key, _)) = instance.me(&own) else {
            self.fail("you are not invited to this event");
            return;
        };
        if instance.organized_by(&own) {
            self.fail("you organize this event");
            return;
        }
        let key = key.to_owned();
        if self
            .attempt(|app| calendars::answer(&app.client, &instance.account, instance.event_id(), &key, status))
            .is_some()
        {
            self.info(format!("answered: {status}"));
            self.load_events();
        }
    }

    // Contacts.

    fn load_contacts(&mut self) {
        self.contacts.loaded = true;
        if let Some(books) = self.attempt(|app| contacts::address_books(&app.client)) {
            self.contacts.books = books;
        }
        self.load_cards();
    }

    fn load_cards(&mut self) {
        let search = self.contacts.search.clone();
        let selected = self.selected_card().map(|c| c.id.clone());
        if let Some(cards) = self.attempt(|app| contacts::cards(&app.client, &search)) {
            self.contacts.cards = cards;
            let index = selected.and_then(|id| self.contacts.cards.iter().position(|c| c.id == id)).unwrap_or(0);
            select(&mut self.contacts.list, self.contacts.cards.len(), index);
        }
    }

    pub fn selected_card(&self) -> Option<&Card> {
        self.contacts.list.selected().and_then(|i| self.contacts.cards.get(i))
    }

    pub fn writable_books(&self) -> Vec<&AddressBook> {
        self.contacts.books.iter().filter(|b| b.writable()).collect()
    }

    fn book_named(&self, name: &str, current: usize) -> Result<usize, String> {
        if name.trim().is_empty() {
            return Ok(current);
        }
        self.contacts
            .books
            .iter()
            .position(|b| {
                b.writable()
                    && (book_name(b).eq_ignore_ascii_case(name.trim()) || b.name.eq_ignore_ascii_case(name.trim()))
            })
            .ok_or_else(|| format!("no address book {name} that you may write"))
    }

    fn export_event(&mut self, account: &str, id: &str, path: PathBuf) {
        let Some(event) = self.attempt(|app| calendars::raw_event(&app.client, account, id)) else { return };
        match transfer::ics_from_events(&[event]).and_then(|text| write_new(&path, &text)) {
            Ok(()) => self.info(format!("saved as {}", path.display())),
            Err(error) => self.fail(error),
        }
    }

    fn import_events(&mut self, path: PathBuf) {
        let Some(calendar) = self.calendar.calendars.iter().find(|c| c.writable()).cloned() else {
            self.fail("no calendar you may write");
            return;
        };
        let events = match std::fs::read_to_string(&path)
            .map_err(|error| error.to_string())
            .and_then(|text| transfer::events_from_ics(&text))
        {
            Ok(events) => events,
            Err(error) => return self.fail(format!("{}: {error}", path.display())),
        };
        if let Some((made, refused)) = self.attempt(|app| calendars::import(&app.client, &calendar, events)) {
            self.report_import(made, &refused, &calendar_name(&calendar));
            self.load_events();
        }
    }

    fn export_cards(&mut self, path: PathBuf) {
        let mut cards = Vec::new();
        let mut accounts: Vec<String> = self.contacts.cards.iter().map(|card| card.account.clone()).collect();
        accounts.dedup();
        for account in accounts {
            let ids: Vec<String> =
                self.contacts.cards.iter().filter(|card| card.account == account).map(|card| card.id.clone()).collect();
            let Some(found) = self.attempt(|app| contacts::raw_cards(&app.client, &account, &ids)) else { return };
            cards.extend(found);
        }
        if cards.is_empty() {
            return self.fail("no contacts listed");
        }
        match transfer::vcf_from_cards(&cards).and_then(|text| write_new(&path, &text)) {
            Ok(()) => self.info(format!("{} contacts saved as {}", cards.len(), path.display())),
            Err(error) => self.fail(error),
        }
    }

    fn import_cards(&mut self, path: PathBuf) {
        let Some(book) = self.contacts.books.iter().find(|b| b.writable()).cloned() else {
            self.fail("no address book you may write");
            return;
        };
        let cards = match std::fs::read_to_string(&path)
            .map_err(|error| error.to_string())
            .and_then(|text| transfer::cards_from_vcf(&text))
        {
            Ok(cards) => cards,
            Err(error) => return self.fail(format!("{}: {error}", path.display())),
        };
        if let Some((made, refused)) = self.attempt(|app| contacts::import(&app.client, &book, cards)) {
            self.report_import(made, &refused, &book_name(&book));
            self.load_cards();
        }
    }

    fn report_import(&mut self, made: usize, refused: &[String], into: &str) {
        match refused.first() {
            None => self.info(format!("{made} imported into {into}")),
            Some(first) => self.fail(format!("{made} imported into {into}, {} not: {first}", refused.len())),
        }
    }

    fn new_card(&mut self) {
        let Some(index) = self.contacts.books.iter().position(AddressBook::writable) else {
            self.fail("no address book you may write");
            return;
        };
        self.edit = Some(Edit::Card { form: CardForm::default(), book: index, id: None });
    }

    fn edit_card(&mut self) {
        let Some(card) = self.selected_card().cloned() else { return };
        let Some(index) = self
            .contacts
            .books
            .iter()
            .position(|b| b.account == card.account && card.address_book_ids.contains_key(&b.id))
        else {
            self.fail("its address book is not known");
            return;
        };
        if !self.contacts.books[index].writable() {
            self.fail("this address book may not be written");
            return;
        }
        let id = Some((card.account.clone(), card.id.clone()));
        self.edit = Some(Edit::Card { form: CardForm::of(&card), book: index, id });
    }

    fn save_card(&mut self, form: CardForm, index: usize, id: Option<(String, String)>) {
        let Some(book) = self.contacts.books.get(index).cloned() else { return };
        let result = match &id {
            Some((account, card)) if *account == book.account => {
                contacts::update(&self.client, &book, card, &form).map(|()| "contact changed")
            }
            Some(_) => Err(jmap::Error::Protocol("a contact moves only between address books of one account".into())),
            None => contacts::create(&self.client, &book, &form).map(|()| "contact made"),
        };
        match result {
            Ok(done) => {
                self.info(done);
                self.load_cards();
                if let Some(index) = self.contacts.cards.iter().position(|c| c.full_name() == form.name) {
                    self.contacts.list.select(Some(index));
                }
            }
            Err(error) => {
                self.popup =
                    Some(Popup::Unsaved { edit: Edit::Card { form, book: index, id }, error: error.to_string() })
            }
        }
    }

    // Sharing.

    /// Opens with whom the selected directory is shared.
    fn share_node(&mut self) {
        let (Some(store), Some(node)) = (self.store().cloned(), self.selected_node().cloned()) else { return };
        if !node.is_directory() || node.role.is_some() {
            self.fail("folders are shared, not files – share the folder it is in");
            return;
        }
        let may = store.kind == files::StoreKind::Own || node.my_rights.is_some_and(|r| r.may_share);
        if !may {
            self.fail("you may not share this folder");
            return;
        }
        let shared = node.share_with.clone().unwrap_or_default();
        let ids: Vec<&str> = shared.keys().map(String::as_str).collect();
        let Some(people) = self.attempt(|app| files::principals(&app.client, &ids)) else { return };
        let entries = shared
            .iter()
            .map(|(id, rights)| {
                let principal = people.iter().find(|p| &p.id == id).cloned().unwrap_or(Principal {
                    id: id.clone(),
                    kind: String::new(),
                    name: id.clone(),
                    email: None,
                });
                (principal, Level::of(rights))
            })
            .collect();
        self.popup = Some(Popup::Share(Sharing { node, entries, selected: 0 }));
    }

    /// Opens the links to the selected file or folder.
    fn link_node(&mut self) {
        let (Some(store), Some(node)) = (self.store().cloned(), self.selected_node().cloned()) else { return };
        if !files::links_available(&self.client) {
            self.fail("this server makes no links");
            return;
        }
        if node.role.is_some() {
            self.fail("the trash has no links");
            return;
        }
        let may = store.kind == files::StoreKind::Own || node.my_rights.is_some_and(|r| r.may_share);
        if !may {
            self.fail("you may not share this");
            return;
        }
        let Some(list) = self.attempt(|app| files::links(&app.client, &store.id, &node.id)) else { return };
        self.popup = Some(Popup::Links(Linking {
            account: store.id,
            node,
            list,
            selected: 0,
            mode: LinkMode::View,
            made: None,
        }));
    }

    fn find_people(&mut self, mut sharing: Sharing, text: &str) {
        let Some(found) = self.attempt(|app| files::find_principals(&app.client, text)) else {
            self.popup = Some(Popup::Share(sharing));
            return;
        };
        let own = self.client.session.username.to_lowercase();
        let found: Vec<Principal> = found
            .into_iter()
            .filter(|p| p.email.as_deref().is_none_or(|e| e.to_lowercase() != own))
            .filter(|p| !sharing.entries.iter().any(|(known, _)| known.id == p.id))
            .collect();
        match found.len() {
            0 => {
                self.fail(format!("nobody found for “{text}”"));
                self.popup = Some(Popup::Share(sharing));
            }
            1 => {
                sharing.entries.push((found[0].clone(), Level::Read));
                sharing.selected = sharing.entries.len() - 1;
                self.popup = Some(Popup::Share(sharing));
            }
            _ => self.popup = Some(Popup::Pick { sharing, found, selected: 0 }),
        }
    }

    fn save_sharing(&mut self, sharing: Sharing) {
        let Some(store) = self.store().map(|s| s.id.clone()) else { return };
        let with: Vec<(String, Level)> = sharing.entries.iter().map(|(p, level)| (p.id.clone(), *level)).collect();
        match files::share(&self.client, &store, &sharing.node.id, &with) {
            Ok(()) => {
                self.info(if with.is_empty() {
                    format!("{} is shared with nobody", sharing.node.name)
                } else {
                    format!("{} is shared with {}", sharing.node.name, with.len())
                });
                self.load_nodes();
            }
            Err(error) => {
                self.fail(error);
                self.popup = Some(Popup::Share(sharing));
            }
        }
    }

    // Background.

    pub fn background(&mut self, event: Background) {
        match event {
            Background::Push(Push::Connected) => self.online = true,
            Background::Push(Push::Lost(_)) => self.online = false,
            Background::Push(Push::Changed(types)) => {
                let has = |name: &str| types.contains(name);
                if self.mail.loaded && (has("Email") || has("Mailbox")) {
                    if self.tab == Tab::Mail {
                        self.load_mailboxes();
                        self.load_emails(false);
                    } else {
                        self.mail.loaded = false;
                    }
                }
                if self.files.loaded && has("FileNode") {
                    if self.tab == Tab::Files {
                        self.load_nodes();
                    } else {
                        self.files.loaded = false;
                    }
                }
                if self.calendar.loaded && (has("CalendarEvent") || has("Calendar")) {
                    if self.tab == Tab::Calendar { self.load_events() } else { self.calendar.loaded = false }
                }
                if self.contacts.loaded && (has("ContactCard") || has("AddressBook")) {
                    if self.tab == Tab::Contacts { self.load_cards() } else { self.contacts.loaded = false }
                }
            }
            Background::Progress { id, done, total } => {
                if let Some(transfer) = self.transfers.iter_mut().find(|t| t.id == id) {
                    transfer.done = done;
                    transfer.total = total;
                }
            }
            Background::Finished { id, result } => {
                let Some(index) = self.transfers.iter().position(|t| t.id == id) else { return };
                let transfer = self.transfers.remove(index);
                match result {
                    Ok(text) => self.info(text),
                    Err(error) => self.fail(format!("{}: {error}", transfer.label)),
                }
                if transfer.reload_files && self.tab == Tab::Files {
                    self.load_nodes();
                }
            }
        }
    }

    // Keys.

    pub fn key(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.quit = true;
            return;
        }
        if self.input.is_some() {
            self.input_key(key);
            return;
        }
        if self.popup.is_some() {
            self.popup_key(key);
            return;
        }
        match key.code {
            KeyCode::Char('q') => {
                self.quit = true;
                return;
            }
            KeyCode::Char('?') => {
                self.popup = Some(Popup::Help);
                return;
            }
            KeyCode::Char(c @ '1'..='4') => {
                self.tab = Tab::ALL[(c as u8 - b'1') as usize];
                self.load_tab();
                return;
            }
            KeyCode::Tab | KeyCode::BackTab => {
                let index = Tab::ALL.iter().position(|t| *t == self.tab).unwrap_or(0);
                let next = if key.code == KeyCode::Tab { index + 1 } else { index + Tab::ALL.len() - 1 };
                self.tab = Tab::ALL[next % Tab::ALL.len()];
                self.load_tab();
                return;
            }
            KeyCode::F(5) | KeyCode::Char('g') => {
                self.reload();
                self.info("loaded again");
                return;
            }
            _ => {}
        }
        match self.tab {
            Tab::Mail => self.mail_key(key),
            Tab::Files => self.files_key(key),
            Tab::Calendar => self.calendar_key(key),
            Tab::Contacts => self.contacts_key(key),
        }
    }

    fn prompt(&mut self, prompt: Prompt, label: &str, text: String) {
        self.input = Some(Input { prompt, label: label.to_owned(), text, secret: false });
    }

    fn prompt_secret(&mut self, prompt: Prompt, label: &str) {
        self.input = Some(Input { prompt, label: label.to_owned(), text: String::new(), secret: true });
    }

    fn input_key(&mut self, key: KeyEvent) {
        let Some(input) = self.input.as_mut() else { return };
        match key.code {
            KeyCode::Esc => {
                let input = self.input.take();
                // Esc on a search clears it.
                match input.map(|i| i.prompt) {
                    Some(Prompt::SearchMail) if !self.mail.search.is_empty() => {
                        self.mail.search.clear();
                        self.load_emails(true);
                    }
                    Some(Prompt::SearchContacts) if !self.contacts.search.is_empty() => {
                        self.contacts.search.clear();
                        self.load_cards();
                    }
                    _ => {}
                }
            }
            KeyCode::Backspace => {
                input.text.pop();
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => input.text.clear(),
            KeyCode::Char(c) => input.text.push(c),
            KeyCode::Enter => {
                if let Some(input) = self.input.take() {
                    self.submit(input);
                }
            }
            _ => {}
        }
    }

    fn submit(&mut self, input: Input) {
        let text = input.text.trim().to_owned();
        match input.prompt {
            Prompt::SearchMail => {
                self.mail.search = text;
                self.close_reader();
                self.load_emails(true);
            }
            Prompt::SearchContacts => {
                self.contacts.search = text;
                self.load_cards();
            }
            Prompt::Download { account, blob, name, kind } if !text.is_empty() => {
                let mut path = expand(&text);
                if path.is_dir() {
                    path = free_path(&path, &name);
                }
                self.download(account, blob, name, kind, path);
            }
            Prompt::Upload if !text.is_empty() => self.upload(expand(&text)),
            Prompt::ExportEvent { account, id } if !text.is_empty() => self.export_event(&account, &id, expand(&text)),
            Prompt::ImportEvents if !text.is_empty() => self.import_events(expand(&text)),
            Prompt::ExportCards if !text.is_empty() => self.export_cards(expand(&text)),
            Prompt::ImportCards if !text.is_empty() => self.import_cards(expand(&text)),
            Prompt::NewFolder if !text.is_empty() => {
                let Some(store) = self.store().map(|s| s.id.clone()) else { return };
                let parent = self.files.path.last().map(|n| n.id.clone());
                if self.attempt(|app| files::create_directory(&app.client, &store, parent.as_deref(), &text)).is_some()
                {
                    self.load_nodes();
                    if let Some(index) = self.files.nodes.iter().position(|n| n.name == text) {
                        self.files.list.select(Some(index));
                    }
                }
            }
            Prompt::LinkExpiry(linking) => match link_expiry(&text) {
                Ok(expires) => {
                    self.prompt_secret(Prompt::LinkPassword { linking, expires }, "Password for the link (empty: none)")
                }
                Err(error) => {
                    self.fail(&error);
                    self.popup = Some(Popup::Links(linking));
                }
            },
            Prompt::LinkPassword { mut linking, expires } => {
                // Not trimmed: a password is taken as typed.
                let password = Some(input.text.as_str()).filter(|password| !password.is_empty());
                let (account, node, mode) = (linking.account.clone(), linking.node.id.clone(), linking.mode);
                if let Some(url) = self
                    .attempt(|app| files::create_link(&app.client, &account, &node, mode, expires.as_deref(), password))
                {
                    linking.made = Some(url);
                    if let Some(list) = self.attempt(|app| files::links(&app.client, &account, &node)) {
                        linking.list = list;
                    }
                    self.info("link made – copy its address now; it is not shown again");
                }
                self.popup = Some(Popup::Links(linking));
            }
            Prompt::SharePrincipal(sharing) => {
                if text.is_empty() {
                    self.popup = Some(Popup::Share(sharing));
                } else {
                    self.find_people(sharing, &text);
                }
            }
            Prompt::Rename { id } if !text.is_empty() => {
                let Some(store) = self.store().map(|s| s.id.clone()) else { return };
                if self.attempt(|app| files::rename(&app.client, &store, &id, &text)).is_some() {
                    self.load_nodes();
                }
            }
            _ => {}
        }
    }

    fn popup_key(&mut self, key: KeyEvent) {
        let Some(popup) = self.popup.take() else { return };
        let up = matches!(key.code, KeyCode::Up | KeyCode::Char('k'));
        let down = matches!(key.code, KeyCode::Down | KeyCode::Char('j'));
        let delta = if up {
            -1
        } else if down {
            1
        } else {
            0
        };
        let moved =
            |selected: usize, len: usize| ((selected as isize + delta).max(0) as usize).min(len.saturating_sub(1));
        match popup {
            Popup::Help => {}
            // The keys of the calendar act on the event whose details are shown.
            Popup::Info { .. }
                if self.tab == Tab::Calendar && matches!(key.code, KeyCode::Char('a' | 'm' | 'x' | 'e' | 'D')) =>
            {
                self.calendar_key(key)
            }
            Popup::Info { .. } => {}
            Popup::Move { emails, selected } => match key.code {
                KeyCode::Enter => {
                    self.popup = Some(Popup::Move { emails, selected });
                    self.move_email(selected);
                }
                KeyCode::Esc | KeyCode::Char('q') => {}
                _ => self.popup = Some(Popup::Move { emails, selected: moved(selected, self.mail.mailboxes.len()) }),
            },
            Popup::Attachments { selected } => {
                let attachments = self.attachments();
                match key.code {
                    KeyCode::Enter => {
                        let (Some(part), Some(account)) =
                            (attachments.get(selected), self.mail_account().map(str::to_owned))
                        else {
                            return;
                        };
                        let Some(blob) = part.blob_id.clone() else { return };
                        let name = part.name.clone().unwrap_or_else(|| "attachment".into());
                        let path = free_path(&self.downloads, &name);
                        let kind = part.kind.clone();
                        self.prompt(
                            Prompt::Download { account, blob, name, kind },
                            "Save as",
                            path.display().to_string(),
                        );
                    }
                    KeyCode::Esc | KeyCode::Char('q') => {}
                    _ => self.popup = Some(Popup::Attachments { selected: moved(selected, attachments.len()) }),
                }
            }
            Popup::Versions { node, list, selected } => match key.code {
                KeyCode::Enter | KeyCode::Char('d') => {
                    let (Some(version), Some(store)) = (list.get(selected), self.store().map(|s| s.id.clone())) else {
                        return;
                    };
                    let name = if version.is_current {
                        node.name.clone()
                    } else {
                        let stamp = version.modified.as_deref().map(stamp_text).unwrap_or_default();
                        match node.name.rsplit_once('.') {
                            Some((stem, extension)) => format!("{stem} ({stamp}).{extension}"),
                            None => format!("{} ({stamp})", node.name),
                        }
                    };
                    let kind = version
                        .media_type
                        .clone()
                        .or(node.media_type.clone())
                        .unwrap_or_else(|| "application/octet-stream".into());
                    let path = free_path(&self.downloads, &name);
                    let download = Prompt::Download { account: store, blob: version.blob_id.clone(), name, kind };
                    self.prompt(download, "Save as", path.display().to_string());
                }
                KeyCode::Char('r') => {
                    let (Some(version), Some(store)) =
                        (list.get(selected).cloned(), self.store().map(|s| s.id.clone()))
                    else {
                        return;
                    };
                    if version.is_current {
                        self.popup = Some(Popup::Versions { node, list, selected });
                        self.info("this is the current version");
                    } else if self.attempt(|app| files::restore(&app.client, &store, &node.id, &version)).is_some() {
                        self.info(format!("{} restored", node.name));
                        self.load_nodes();
                    }
                }
                KeyCode::Esc | KeyCode::Char('q') => {}
                _ => {
                    let selected = moved(selected, list.len());
                    self.popup = Some(Popup::Versions { node, list, selected });
                }
            },
            Popup::Written { message, error } => match key.code {
                KeyCode::Char('s') | KeyCode::Char('y') => self.send(message, false),
                KeyCode::Char('d') => self.send(message, true),
                KeyCode::Char('e') => self.edit = Some(Edit::Message(message)),
                KeyCode::Char('c') | KeyCode::Char('n') | KeyCode::Esc => self.info("dropped"),
                _ => self.popup = Some(Popup::Written { message, error }),
            },
            Popup::Unsaved { edit, error } => match key.code {
                KeyCode::Char('e') | KeyCode::Enter => self.edit = Some(edit),
                KeyCode::Char('c') | KeyCode::Char('n') | KeyCode::Esc => self.info("dropped"),
                _ => self.popup = Some(Popup::Unsaved { edit, error }),
            },
            Popup::Share(mut sharing) => match key.code {
                KeyCode::Char('a') | KeyCode::Char('+') => {
                    self.prompt(Prompt::SharePrincipal(sharing), "Share with (name or address)", String::new())
                }
                KeyCode::Enter | KeyCode::Char('l') | KeyCode::Char(' ') => {
                    if let Some((_, level)) = sharing.entries.get_mut(sharing.selected) {
                        *level = level.next();
                    }
                    self.popup = Some(Popup::Share(sharing));
                }
                KeyCode::Char('x') | KeyCode::Char('-') | KeyCode::Delete => {
                    if sharing.selected < sharing.entries.len() {
                        sharing.entries.remove(sharing.selected);
                        sharing.selected = sharing.selected.min(sharing.entries.len().saturating_sub(1));
                    }
                    self.popup = Some(Popup::Share(sharing));
                }
                KeyCode::Char('s') => self.save_sharing(sharing),
                KeyCode::Esc | KeyCode::Char('q') => self.info("not changed"),
                _ => {
                    sharing.selected = moved(sharing.selected, sharing.entries.len());
                    self.popup = Some(Popup::Share(sharing));
                }
            },
            Popup::Links(mut linking) => match key.code {
                KeyCode::Char('m') => {
                    linking.mode = linking.mode.next(linking.node.is_directory());
                    self.popup = Some(Popup::Links(linking));
                }
                KeyCode::Char('n') | KeyCode::Char('a') | KeyCode::Char('+') => {
                    linking.made = None;
                    self.prompt(
                        Prompt::LinkExpiry(linking),
                        "Valid until (YYYY-MM-DD, empty: no expiry)",
                        String::new(),
                    )
                }
                KeyCode::Char('x') | KeyCode::Char('-') | KeyCode::Delete => {
                    if let Some(link) = linking.list.get(linking.selected).cloned() {
                        let account = linking.account.clone();
                        if self.attempt(|app| files::remove_link(&app.client, &account, &link.id)).is_some() {
                            linking.list.remove(linking.selected);
                            linking.selected = linking.selected.min(linking.list.len().saturating_sub(1));
                            self.info("link removed – its address no longer works");
                        }
                    }
                    self.popup = Some(Popup::Links(linking));
                }
                KeyCode::Esc | KeyCode::Char('q') => {}
                _ => {
                    linking.selected = moved(linking.selected, linking.list.len());
                    self.popup = Some(Popup::Links(linking));
                }
            },
            Popup::Pick { mut sharing, found, selected } => match key.code {
                KeyCode::Enter => {
                    if let Some(principal) = found.get(selected) {
                        sharing.entries.push((principal.clone(), Level::Read));
                        sharing.selected = sharing.entries.len() - 1;
                    }
                    self.popup = Some(Popup::Share(sharing));
                }
                KeyCode::Esc | KeyCode::Char('q') => self.popup = Some(Popup::Share(sharing)),
                _ => {
                    let selected = moved(selected, found.len());
                    self.popup = Some(Popup::Pick { sharing, found, selected });
                }
            },
            Popup::Confirm { what, text } => match key.code {
                KeyCode::Char('o') if matches!(what, Destroy::Event { instance: Some(_), .. }) => {
                    let Destroy::Event { account, id, title, instance: Some(recurrence_id) } = what else { return };
                    let removed = self.attempt(|app| {
                        let series = calendars::event(&app.client, &account, &id)?
                            .ok_or_else(|| jmap::Error::Protocol("the series is gone".into()))?;
                        calendars::destroy_instance(&app.client, &series, &recurrence_id)
                    });
                    if removed.is_some() {
                        self.info(format!("{title}: this event of the series deleted"));
                        self.load_events();
                    }
                }
                KeyCode::Char('y') | KeyCode::Char('j') => match what {
                    Destroy::Emails { ids } => {
                        let Some(account) = self.mail_account().map(str::to_owned) else { return };
                        if self.attempt(|app| mail::destroy_all(&app.client, &account, &ids)).is_some() {
                            self.info("deleted");
                            self.after_email_left(&ids);
                        }
                    }
                    Destroy::Event { account, id, title, .. } => {
                        if self.attempt(|app| calendars::destroy(&app.client, &account, &id)).is_some() {
                            self.info(format!("{title} deleted"));
                            self.load_events();
                        }
                    }
                    Destroy::Card { account, id, name } => {
                        if self.attempt(|app| contacts::destroy(&app.client, &account, &id)).is_some() {
                            self.info(format!("{name} deleted"));
                            self.load_cards();
                        }
                    }
                    Destroy::Node { id, name } => {
                        let Some(store) = self.store().map(|s| s.id.clone()) else { return };
                        if self.attempt(|app| files::destroy(&app.client, &store, &id)).is_some() {
                            self.info(format!("{name} deleted"));
                            self.load_nodes();
                        }
                    }
                },
                KeyCode::Char('n') | KeyCode::Esc | KeyCode::Char('q') => {}
                _ => self.popup = Some(Popup::Confirm { what, text }),
            },
        }
    }

    fn mail_key(&mut self, key: KeyEvent) {
        let up = matches!(key.code, KeyCode::Up | KeyCode::Char('k'));
        let down = matches!(key.code, KeyCode::Down | KeyCode::Char('j'));
        match (self.mail_focus, key.code) {
            (_, KeyCode::Char('c')) => self.write(Kind::New),
            (_, KeyCode::Char('V')) => self.edit_vacation(),
            (_, KeyCode::Char('/')) => self.prompt(Prompt::SearchMail, "Search", self.mail.search.clone()),
            (_, KeyCode::Char('a')) if self.mail.accounts.len() > 1 && self.mail_focus == MailFocus::Mailboxes => {
                let next = (self.mail.account + 1) % self.mail.accounts.len();
                self.switch_mail_account(next);
            }
            (MailFocus::Mailboxes, _) if up || down => {
                step(&mut self.mail.boxes, self.mail.mailboxes.len(), if up { -1 } else { 1 });
                self.close_reader();
                self.load_emails(true);
            }
            (MailFocus::Mailboxes, KeyCode::Enter | KeyCode::Right | KeyCode::Char('l')) => {
                self.mail_focus = MailFocus::List
            }
            (MailFocus::List, KeyCode::Left | KeyCode::Char('h')) => self.mail_focus = MailFocus::Mailboxes,
            (_, KeyCode::Char('t')) => {
                self.mail.threads = !self.mail.threads;
                self.close_reader();
                self.load_emails(true);
                self.info(if self.mail.threads { "conversations" } else { "single emails" });
            }
            (MailFocus::List, _) if up || down => {
                step(&mut self.mail.list, self.mail.emails.len(), if up { -1 } else { 1 });
                if self.mail.list.selected().is_some_and(|i| i + 1 >= self.mail.emails.len()) {
                    self.load_more_emails();
                }
            }
            (MailFocus::List, KeyCode::PageDown | KeyCode::PageUp) => {
                let delta = if key.code == KeyCode::PageDown { 20 } else { -20 };
                step(&mut self.mail.list, self.mail.emails.len(), delta);
                if self.mail.list.selected().is_some_and(|i| i + 1 >= self.mail.emails.len()) {
                    self.load_more_emails();
                }
            }
            (MailFocus::List, KeyCode::Enter | KeyCode::Right | KeyCode::Char('l')) => self.open_email(),
            (MailFocus::Reader, KeyCode::Esc | KeyCode::Left | KeyCode::Char('h')) => self.close_reader(),
            (MailFocus::Reader, _) if up || down => {
                self.mail.scroll =
                    if up { self.mail.scroll.saturating_sub(1) } else { self.mail.scroll.saturating_add(1) };
            }
            (MailFocus::Reader, KeyCode::PageDown | KeyCode::Char(' ')) => {
                self.mail.scroll = self.mail.scroll.saturating_add(20)
            }
            (MailFocus::Reader, KeyCode::PageUp) => self.mail.scroll = self.mail.scroll.saturating_sub(20),
            (MailFocus::Reader, KeyCode::Char('n')) => {
                step(&mut self.mail.list, self.mail.emails.len(), 1);
                self.open_email();
            }
            (MailFocus::Reader, KeyCode::Char('p')) => {
                step(&mut self.mail.list, self.mail.emails.len(), -1);
                self.open_email();
            }
            (MailFocus::Reader, KeyCode::Char('A')) => {
                if !self.attachments().is_empty() {
                    self.popup = Some(Popup::Attachments { selected: 0 });
                } else {
                    self.info("no attachments");
                }
            }
            (MailFocus::List | MailFocus::Reader, KeyCode::Char('r')) => self.reply(Kind::Reply),
            (MailFocus::List | MailFocus::Reader, KeyCode::Char('R')) => self.reply(Kind::ReplyAll),
            (MailFocus::List | MailFocus::Reader, KeyCode::Char('f')) => self.reply(Kind::Forward),
            (MailFocus::List | MailFocus::Reader, KeyCode::Char('u')) => self.toggle_keyword("$seen"),
            (MailFocus::List | MailFocus::Reader, KeyCode::Char('s')) => self.toggle_keyword("$flagged"),
            (MailFocus::List | MailFocus::Reader, KeyCode::Char('d') | KeyCode::Delete) => self.delete_email(),
            (MailFocus::List | MailFocus::Reader, KeyCode::Char('m')) => {
                let emails = self.target_emails();
                if !emails.is_empty() {
                    let selected = self.mail.boxes.selected().unwrap_or(0);
                    self.popup = Some(Popup::Move { emails, selected });
                }
            }
            _ => {}
        }
    }

    /// Replies to or forwards the open email – or the selected one, opened first.
    fn reply(&mut self, kind: Kind) {
        if self.mail.open.is_empty() || self.mail_focus != MailFocus::Reader {
            self.open_email();
        }
        self.write(kind);
    }

    fn files_key(&mut self, key: KeyEvent) {
        let up = matches!(key.code, KeyCode::Up | KeyCode::Char('k'));
        let down = matches!(key.code, KeyCode::Down | KeyCode::Char('j'));
        match (self.files_focus, key.code) {
            (FilesFocus::Stores, _) if up || down => {
                step(&mut self.files.store_list, self.files.stores.len(), if up { -1 } else { 1 });
                self.files.path.clear();
                self.files.list.select(None);
                self.load_nodes();
            }
            (FilesFocus::Stores, KeyCode::Enter | KeyCode::Right | KeyCode::Char('l')) => {
                self.files_focus = FilesFocus::Nodes
            }
            (FilesFocus::Nodes, _) if up || down => {
                step(&mut self.files.list, self.files.nodes.len(), if up { -1 } else { 1 })
            }
            (FilesFocus::Nodes, KeyCode::PageDown) => step(&mut self.files.list, self.files.nodes.len(), 20),
            (FilesFocus::Nodes, KeyCode::PageUp) => step(&mut self.files.list, self.files.nodes.len(), -20),
            (FilesFocus::Nodes, KeyCode::Enter | KeyCode::Right | KeyCode::Char('l')) => self.enter_node(),
            (FilesFocus::Nodes, KeyCode::Backspace | KeyCode::Left | KeyCode::Char('h')) => {
                if self.files.path.is_empty() {
                    self.files_focus = FilesFocus::Stores;
                } else {
                    self.leave_directory();
                }
            }
            (FilesFocus::Nodes, KeyCode::Char('d')) => {
                let (Some(store), Some(node)) = (self.store().map(|s| s.id.clone()), self.selected_node().cloned())
                else {
                    return;
                };
                let Some(blob) = node.blob_id.clone().filter(|_| !node.is_directory()) else {
                    self.fail("only files can be downloaded");
                    return;
                };
                let path = free_path(&self.downloads, &node.name);
                let kind = node.media_type.clone().unwrap_or_else(|| "application/octet-stream".into());
                let download = Prompt::Download { account: store, blob, name: node.name.clone(), kind };
                self.prompt(download, "Save as", path.display().to_string());
            }
            (FilesFocus::Nodes, KeyCode::Char('v')) => self.show_versions(),
            (FilesFocus::Nodes, KeyCode::Char('i')) => self.node_info(),
            (FilesFocus::Nodes, KeyCode::Char('S')) => self.share_node(),
            (FilesFocus::Nodes, KeyCode::Char('L')) => self.link_node(),
            (_, KeyCode::Char('u')) => self.prompt(Prompt::Upload, "Upload file", String::new()),
            (_, KeyCode::Char('n')) => self.prompt(Prompt::NewFolder, "New folder", String::new()),
            (FilesFocus::Nodes, KeyCode::Char('R')) => {
                if let Some(node) = self.selected_node().cloned() {
                    self.prompt(Prompt::Rename { id: node.id }, "Rename to", node.name);
                }
            }
            (FilesFocus::Nodes, KeyCode::Char('D') | KeyCode::Delete) => self.delete_node(),
            _ => {}
        }
    }

    fn calendar_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => step(&mut self.calendar.list, self.calendar.events.len(), -1),
            KeyCode::Down | KeyCode::Char('j') => step(&mut self.calendar.list, self.calendar.events.len(), 1),
            KeyCode::Right | KeyCode::Char('l') | KeyCode::Char(']') => self.shift_calendar(7),
            KeyCode::Left | KeyCode::Char('h') | KeyCode::Char('[') => self.shift_calendar(-7),
            KeyCode::Char('t') => {
                self.calendar.from = Some(Local::now().date_naive());
                self.load_events();
            }
            KeyCode::Enter => self.event_info(),
            KeyCode::Char('n') => self.new_event(),
            KeyCode::Char('e') => self.edit_event(),
            KeyCode::Char('E') => self.edit_instance(),
            KeyCode::Char('D') | KeyCode::Delete => self.delete_event(),
            KeyCode::Char('a') => self.answer_event("accepted"),
            KeyCode::Char('m') => self.answer_event("tentative"),
            KeyCode::Char('x') => self.answer_event("declined"),
            KeyCode::Char('X') => {
                let Some(event) = self.selected_event().cloned() else { return };
                let name = file_name(event.title.as_deref().unwrap_or("event"), "ics");
                let prompt = Prompt::ExportEvent { account: event.account.clone(), id: event.event_id().to_owned() };
                self.prompt(prompt, "Save the event as", format!("~/{name}"));
            }
            KeyCode::Char('I') => self.prompt(Prompt::ImportEvents, "Import the events of", "~/".into()),
            _ => {}
        }
    }

    fn contacts_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => step(&mut self.contacts.list, self.contacts.cards.len(), -1),
            KeyCode::Down | KeyCode::Char('j') => step(&mut self.contacts.list, self.contacts.cards.len(), 1),
            KeyCode::Char('/') => self.prompt(Prompt::SearchContacts, "Search", self.contacts.search.clone()),
            KeyCode::Char('c') => {
                let Some(card) = self.contacts.list.selected().and_then(|i| self.contacts.cards.get(i)) else { return };
                let Some(email) = card.emails().into_iter().next() else {
                    self.fail("no address");
                    return;
                };
                let name = card.full_name();
                self.tab = Tab::Mail;
                self.load_tab();
                self.write(Kind::New);
                if let Some(Edit::Message(message)) = self.edit.as_mut() {
                    message.draft.to = vec![mail::EmailAddress { name: (name != email).then_some(name), email }];
                }
            }
            KeyCode::Char('n') => self.new_card(),
            KeyCode::Char('X') => {
                self.prompt(Prompt::ExportCards, "Save the contacts listed as", "~/contacts.vcf".into())
            }
            KeyCode::Char('I') => self.prompt(Prompt::ImportCards, "Import the contacts of", "~/".into()),
            KeyCode::Char('e') | KeyCode::Enter => self.edit_card(),
            KeyCode::Char('D') | KeyCode::Delete => {
                if let Some(card) = self.selected_card().cloned() {
                    let name = card.full_name();
                    self.popup = Some(Popup::Confirm {
                        text: format!("Delete {name} for good? (y/n)"),
                        what: Destroy::Card { account: card.account, id: card.id, name },
                    });
                }
            }
            _ => {}
        }
    }
}

/// A size for people (powers of 1000).
pub fn size_text(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 || value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// A time of the protocol (RFC 3339) in local time: the time alone today, else date and time.
pub fn time_text(time: &str) -> String {
    let Ok(time) = DateTime::parse_from_rfc3339(time) else { return time.to_owned() };
    let local = time.with_timezone(&Local);
    if local.date_naive() == Local::now().date_naive() {
        local.format("%H:%M").to_string()
    } else if local.year() == Local::now().year() {
        local.format("%d %b %H:%M").to_string()
    } else {
        local.format("%Y-%m-%d").to_string()
    }
}

/// A time of the protocol in local time for a file name: `2026-10-28 18-24-05`.
pub fn stamp_text(time: &str) -> String {
    match DateTime::parse_from_rfc3339(time) {
        Ok(time) => time.with_timezone(&Local).format("%Y-%m-%d %H-%M-%S").to_string(),
        Err(_) => time.replace(':', "-"),
    }
}

/// A time of the protocol in local time, to the second.
pub fn exact_time_text(time: &str) -> String {
    match DateTime::parse_from_rfc3339(time) {
        Ok(time) => time.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S").to_string(),
        Err(_) => time.to_owned(),
    }
}

/// A calendar as the editor names it: its name, and whose it is when shared.
pub fn calendar_name(calendar: &Calendar) -> String {
    match &calendar.shared {
        Some(owner) => format!("{} ({owner})", calendar.name),
        None => calendar.name.clone(),
    }
}

/// An address book as the editor names it.
pub fn book_name(book: &AddressBook) -> String {
    match &book.shared {
        Some(owner) => format!("{} ({owner})", book.name),
        None => book.name.clone(),
    }
}

/// When an event is, in local time.
pub fn event_when(event: &Event) -> String {
    let Some(start) = event.starts() else { return String::new() };
    if event.show_without_time {
        return format!("{} (all day)", start.date_naive().format("%a %d %b %Y"));
    }
    let start = start.with_timezone(&Local);
    match event.ends().map(|end| end.with_timezone(&Local)) {
        Some(end) if end.date_naive() == start.date_naive() => {
            format!("{} {}–{}", start.format("%a %d %b %Y"), start.format("%H:%M"), end.format("%H:%M"))
        }
        Some(end) => format!("{} – {}", start.format("%a %d %b %Y %H:%M"), end.format("%a %d %b %Y %H:%M")),
        None => start.format("%a %d %b %Y %H:%M").to_string(),
    }
}

/// A date typed for a link's expiry: the end of that day here, as a UTCDate; nothing for none.
fn link_expiry(text: &str) -> Result<Option<String>, String> {
    if text.is_empty() {
        return Ok(None);
    }
    let day = NaiveDate::parse_from_str(text, "%Y-%m-%d").map_err(|_| format!("not a date: {text} (YYYY-MM-DD)"))?;
    let end = day.and_hms_opt(23, 59, 59).and_then(|end| Local.from_local_datetime(&end).earliest());
    let end = end.ok_or_else(|| format!("not a time here: {text}"))?;
    if end <= Local::now() {
        return Err("the day has passed".into());
    }
    Ok(Some(end.with_timezone(&Utc).format("%Y-%m-%dT%H:%M:%SZ").to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_expires_at_the_end_of_the_day_typed() {
        assert_eq!(link_expiry(""), Ok(None));
        let expires = link_expiry("2099-12-31").unwrap().unwrap();
        assert!(expires.starts_with("2099-12-31T") || expires.starts_with("2100-01-01T"), "{expires}");
        assert!(expires.ends_with('Z'));
        assert!(link_expiry("2001-01-01").is_err());
        assert!(link_expiry("tomorrow").is_err());
    }

    #[test]
    fn names_and_sizes() {
        assert_eq!(sanitize("../etc/passwd"), ".._etc_passwd");
        assert_eq!(sanitize(".."), "download");
        assert_eq!(size_text(999), "999 B");
        assert_eq!(size_text(1_500_000), "1.5 MB");
        let dir = std::env::temp_dir().join(format!("kernoid-tui-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(free_path(&dir, "a.txt"), dir.join("a.txt"));
        std::fs::write(dir.join("a.txt"), "x").unwrap();
        assert_eq!(free_path(&dir, "a.txt"), dir.join("a (1).txt"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
