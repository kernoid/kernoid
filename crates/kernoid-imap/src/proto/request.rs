// SPDX-License-Identifier: AGPL-3.0-or-later
//! The requests kernoid understands, as the parser (`parse`) gives them to the session: one variant per command
//! (RFC 9051, 6, and the extensions of RFC 0002, 11.2), mailbox names already in UTF-8.

use super::sequence::SequenceSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Request {
    pub tag: String,
    pub command: Command,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Command {
    Capability,
    Noop,
    Logout,
    StartTls,
    /// The mechanism in upper case; the initial response as sent (base64, or `=` for an empty one).
    Authenticate {
        mechanism: String,
        initial: Option<Vec<u8>>,
    },
    Login {
        user: String,
        password: String,
    },
    /// `ID` (RFC 2971); what the client says about itself is not used.
    Id,
    /// `ENABLE` (RFC 5161) with the capabilities in upper case.
    Enable(Vec<String>),
    Select {
        mailbox: String,
        read_only: bool,
        condstore: bool,
        qresync: Option<QResync>,
    },
    Create(String),
    Delete(String),
    Rename {
        from: String,
        to: String,
    },
    Subscribe {
        mailbox: String,
        subscribe: bool,
    },
    List(List),
    Lsub {
        reference: String,
        pattern: String,
    },
    Namespace,
    Status {
        mailbox: String,
        items: Vec<StatusItem>,
    },
    Append {
        mailbox: String,
        messages: Vec<AppendMessage>,
    },
    Idle,
    Check,
    Close,
    Unselect,
    /// `EXPUNGE`, or `UID EXPUNGE` with its UIDs (RFC 4315).
    Expunge(Option<SequenceSet>),
    Search {
        uid: bool,
        search: Search,
    },
    Sort {
        uid: bool,
        criteria: Vec<SortCriterion>,
        search: Search,
    },
    Thread {
        uid: bool,
        algorithm: ThreadAlgorithm,
        search: Search,
    },
    Fetch {
        uid: bool,
        fetch: Fetch,
    },
    Store {
        uid: bool,
        store: Store,
    },
    /// `COPY` and `MOVE` (RFC 6851).
    Copy {
        uid: bool,
        is_move: bool,
        set: SequenceSet,
        mailbox: String,
    },
    GetAcl(String),
    SetAcl {
        mailbox: String,
        identifier: String,
        change: RightsChange,
    },
    DeleteAcl {
        mailbox: String,
        identifier: String,
    },
    ListRights {
        mailbox: String,
        identifier: String,
    },
    MyRights(String),
    GetQuota(String),
    GetQuotaRoot(String),
    /// `SETQUOTA`: quotas are the administrators', so its arguments do not matter.
    SetQuota,
}

impl Command {
    /// The name of the command, as the tagged `OK` repeats it.
    pub fn name(&self) -> &'static str {
        match self {
            Command::Capability => "CAPABILITY",
            Command::Noop => "NOOP",
            Command::Logout => "LOGOUT",
            Command::StartTls => "STARTTLS",
            Command::Authenticate { .. } => "AUTHENTICATE",
            Command::Login { .. } => "LOGIN",
            Command::Id => "ID",
            Command::Enable(_) => "ENABLE",
            Command::Select { read_only: false, .. } => "SELECT",
            Command::Select { read_only: true, .. } => "EXAMINE",
            Command::Create(_) => "CREATE",
            Command::Delete(_) => "DELETE",
            Command::Rename { .. } => "RENAME",
            Command::Subscribe { subscribe: true, .. } => "SUBSCRIBE",
            Command::Subscribe { subscribe: false, .. } => "UNSUBSCRIBE",
            Command::List(_) => "LIST",
            Command::Lsub { .. } => "LSUB",
            Command::Namespace => "NAMESPACE",
            Command::Status { .. } => "STATUS",
            Command::Append { .. } => "APPEND",
            Command::Idle => "IDLE",
            Command::Check => "CHECK",
            Command::Close => "CLOSE",
            Command::Unselect => "UNSELECT",
            Command::Expunge(None) => "EXPUNGE",
            Command::Expunge(Some(_)) => "UID EXPUNGE",
            Command::Search { uid: false, .. } => "SEARCH",
            Command::Search { uid: true, .. } => "UID SEARCH",
            Command::Sort { uid: false, .. } => "SORT",
            Command::Sort { uid: true, .. } => "UID SORT",
            Command::Thread { uid: false, .. } => "THREAD",
            Command::Thread { uid: true, .. } => "UID THREAD",
            Command::Fetch { uid: false, .. } => "FETCH",
            Command::Fetch { uid: true, .. } => "UID FETCH",
            Command::Store { uid: false, .. } => "STORE",
            Command::Store { uid: true, .. } => "UID STORE",
            Command::Copy { uid: false, is_move: false, .. } => "COPY",
            Command::Copy { uid: true, is_move: false, .. } => "UID COPY",
            Command::Copy { uid: false, is_move: true, .. } => "MOVE",
            Command::Copy { uid: true, is_move: true, .. } => "UID MOVE",
            Command::GetAcl(_) => "GETACL",
            Command::SetAcl { .. } => "SETACL",
            Command::DeleteAcl { .. } => "DELETEACL",
            Command::ListRights { .. } => "LISTRIGHTS",
            Command::MyRights(_) => "MYRIGHTS",
            Command::GetQuota(_) => "GETQUOTA",
            Command::GetQuotaRoot(_) => "GETQUOTAROOT",
            Command::SetQuota => "SETQUOTA",
        }
    }
}

/// QRESYNC's parameter of `SELECT` (RFC 7162, 3.2.5); the sequence match data is read and not used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QResync {
    pub uid_validity: u32,
    pub modseq: u64,
    pub known_uids: Option<SequenceSet>,
}

/// `LIST` with LIST-EXTENDED (RFC 5258), SPECIAL-USE (RFC 6154) and LIST-STATUS (RFC 5819).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct List {
    pub reference: String,
    pub patterns: Vec<String>,
    pub subscribed_only: bool,
    pub special_use_only: bool,
    pub return_subscribed: bool,
    pub return_children: bool,
    pub return_special_use: bool,
    pub return_status: Option<Vec<StatusItem>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatusItem {
    Messages,
    Recent,
    UidNext,
    UidValidity,
    Unseen,
    Deleted,
    Size,
    HighestModSeq,
    /// `DELETED-STORAGE` (RFC 9208): understood, not answered.
    DeletedStorage,
}

impl StatusItem {
    pub fn name(self) -> &'static str {
        match self {
            StatusItem::Messages => "MESSAGES",
            StatusItem::Recent => "RECENT",
            StatusItem::UidNext => "UIDNEXT",
            StatusItem::UidValidity => "UIDVALIDITY",
            StatusItem::Unseen => "UNSEEN",
            StatusItem::Deleted => "DELETED",
            StatusItem::Size => "SIZE",
            StatusItem::HighestModSeq => "HIGHESTMODSEQ",
            StatusItem::DeletedStorage => "DELETED-STORAGE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppendMessage {
    /// The flags as written (`\Seen`, `$Work`).
    pub flags: Vec<String>,
    /// The internal date, in seconds since the epoch.
    pub date: Option<i64>,
    pub data: Vec<u8>,
}

/// What `SEARCH`, `SORT` and `THREAD` share: the result options (ESEARCH, RFC 4731; SEARCHRES, RFC 5182) and the
/// criteria, all of which must match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Search {
    /// `RETURN (…)`: `Some` when given, even empty.
    pub options: Option<Vec<ResultOption>>,
    pub key: SearchKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResultOption {
    Min,
    Max,
    All,
    Count,
    Save,
}

/// A search key (RFC 9051, 6.4.4); dates are midnight UTC of the day, in seconds since the epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SearchKey {
    All,
    And(Vec<SearchKey>),
    Or(Box<SearchKey>, Box<SearchKey>),
    Not(Box<SearchKey>),
    Sequence(SequenceSet),
    Uid(SequenceSet),
    Answered,
    Deleted,
    Draft,
    Flagged,
    Seen,
    Unanswered,
    Undeleted,
    Undraft,
    Unflagged,
    Unseen,
    Recent,
    New,
    Old,
    Keyword(String),
    Unkeyword(String),
    Bcc(String),
    Cc(String),
    From(String),
    To(String),
    Subject(String),
    Body(String),
    Text(String),
    Header(String, String),
    Before(i64),
    On(i64),
    Since(i64),
    SentBefore(i64),
    SentOn(i64),
    SentSince(i64),
    Larger(u64),
    Smaller(u64),
    /// WITHIN (RFC 5032), in seconds.
    Older(u64),
    Younger(u64),
    /// CONDSTORE's `MODSEQ` (RFC 7162); the entry name and type are read and not used.
    ModSeq(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SortCriterion {
    pub key: SortKey,
    pub reverse: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SortKey {
    Arrival,
    Cc,
    Date,
    From,
    Size,
    Subject,
    To,
    /// SORT=DISPLAY (RFC 5957).
    DisplayFrom,
    DisplayTo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreadAlgorithm {
    OrderedSubject,
    References,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fetch {
    pub set: SequenceSet,
    pub items: Vec<FetchItem>,
    /// CONDSTORE's `CHANGEDSINCE` (RFC 7162).
    pub changed_since: Option<u64>,
    /// QRESYNC's `VANISHED`.
    pub vanished: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FetchItem {
    Envelope,
    Flags,
    InternalDate,
    Rfc822,
    Rfc822Header,
    Rfc822Size,
    Rfc822Text,
    /// `BODY`: the structure without extension data.
    Body,
    BodyStructure,
    Uid,
    ModSeq,
    /// `BODY[…]` or `BODY.PEEK[…]`, with `<start.length>`.
    Section {
        peek: bool,
        section: Section,
        partial: Option<(u32, u32)>,
    },
    /// `BINARY[…]` (RFC 3516).
    Binary {
        peek: bool,
        part: Vec<u32>,
        partial: Option<(u32, u32)>,
    },
    BinarySize {
        part: Vec<u32>,
    },
}

/// A section: part numbers, and what of the part.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Section {
    pub part: Vec<u32>,
    pub text: Option<SectionText>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SectionText {
    Header,
    /// `HEADER.FIELDS` and `HEADER.FIELDS.NOT`, with the names as the client wrote them.
    Fields {
        not: bool,
        names: Vec<String>,
    },
    Text,
    Mime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Store {
    pub set: SequenceSet,
    /// CONDSTORE's `UNCHANGEDSINCE`.
    pub unchanged_since: Option<u64>,
    pub mode: StoreMode,
    pub silent: bool,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreMode {
    Replace,
    Add,
    Remove,
}

/// `SETACL`'s rights (RFC 4314, 3.1): replace, add (`+`) or remove (`-`); `c` and `d` stand for `k` and `xte`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RightsChange {
    pub mode: StoreMode,
    pub letters: String,
}
