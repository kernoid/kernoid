// SPDX-License-Identifier: AGPL-3.0-or-later
//! The parser of commands (RFC 9051, 9, with the grammar of the extensions kernoid offers): a cursor over a
//! [`Frame`]'s lines and literals, and a function per command. It never panics and goes no deeper than
//! [`MAX_DEPTH`] in nested search keys; what it does not understand is a `BAD` for the session to send.

use std::borrow::Cow;

use super::{frame::Frame, request::*, sequence::SequenceSet, utf7};

/// How deep search keys may nest (parentheses, `NOT`, `OR`).
const MAX_DEPTH: usize = 32;

/// A command the parser could not read: the tag, if there was one, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Bad {
    pub tag: Option<String>,
    pub text: String,
}

type Result<T> = std::result::Result<T, String>;

/// Reads a command; `utf8` says whether mailbox names are UTF-8 (UTF8=ACCEPT or IMAP4rev2) or modified UTF-7.
pub(crate) fn parse(frame: &Frame, utf8: bool) -> std::result::Result<Request, Bad> {
    let mut cursor = Cursor { frame, line: 0, position: 0, utf8 };
    let tag = cursor.take_while(|b| b.is_ascii_graphic() && !b"+(){%*\"\\".contains(&b));
    if tag.is_empty() || cursor.peek() != Some(b' ') {
        return Err(Bad { tag: None, text: "A command starts with a tag and a space".into() });
    }
    let tag = String::from_utf8_lossy(tag).into_owned();
    let command = cursor.command().map_err(|text| Bad { tag: Some(tag.clone()), text })?;
    Ok(Request { tag, command })
}

struct Cursor<'a> {
    frame: &'a Frame,
    line: usize,
    position: usize,
    utf8: bool,
}

fn is_atom_char(byte: u8) -> bool {
    byte > 0x20 && byte < 0x7f && !b"(){%*\"\\]".contains(&byte)
}

fn is_astring_char(byte: u8) -> bool {
    is_atom_char(byte) || byte == b']'
}

fn text(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| "Not valid UTF-8".to_owned())
}

const MONTHS: [&str; 12] = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];

/// `d-Mon-yyyy` as midnight UTC, in seconds.
fn date(value: &str) -> Option<i64> {
    let mut parts = value.split('-');
    let day: i8 = parts.next()?.trim_start().parse().ok()?;
    let month = parts.next()?.to_ascii_uppercase();
    let month = MONTHS.iter().position(|name| *name == month)? as i8 + 1;
    let year: i16 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let date = jiff::civil::Date::new(year, month, day).ok()?;
    Some(jiff::tz::Offset::UTC.to_timestamp(date.to_datetime(jiff::civil::Time::midnight())).ok()?.as_second())
}

/// `dd-Mon-yyyy hh:mm:ss +zzzz` (`date-time`), in seconds.
fn date_time(value: &str) -> Option<i64> {
    let (day, rest) = value.split_once(' ').filter(|(day, _)| !day.is_empty()).or_else(|| {
        // The day may be a space and a digit.
        value.strip_prefix(' ').and_then(|rest| rest.split_once(' '))
    })?;
    let (time, zone) = rest.split_once(' ')?;
    let midnight = date(day)?;
    let mut hms = time.split(':').map(|part| part.parse::<i64>().ok().filter(|_| part.len() == 2));
    let (hours, minutes, seconds) = (hms.next()??, hms.next()??, hms.next()??);
    if hms.next().is_some() || hours > 23 || minutes > 59 || seconds > 60 {
        return None;
    }
    let (sign, digits) = match zone.as_bytes().first()? {
        b'+' => (1, &zone[1..]),
        b'-' => (-1, &zone[1..]),
        _ => return None,
    };
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let offset = digits[..2].parse::<i64>().ok()? * 3600 + digits[2..].parse::<i64>().ok()? * 60;
    Some(midnight + hours * 3600 + minutes * 60 + seconds - sign * offset)
}

impl<'a> Cursor<'a> {
    fn rest(&self) -> &'a [u8] {
        self.frame.lines.get(self.line).map_or(&[], |line| line.get(self.position..).unwrap_or_default())
    }

    fn peek(&self) -> Option<u8> {
        self.rest().first().copied()
    }

    /// Whether a literal comes next.
    fn at_literal(&self) -> bool {
        self.rest().is_empty() && self.line < self.frame.literals.len()
    }

    fn literal(&mut self) -> &'a [u8] {
        let literal = &self.frame.literals[self.line];
        self.line += 1;
        self.position = 0;
        literal
    }

    fn take_while(&mut self, accept: impl Fn(u8) -> bool) -> &'a [u8] {
        let rest = self.rest();
        let length = rest.iter().position(|&b| !accept(b)).unwrap_or(rest.len());
        self.position += length;
        &rest[..length]
    }

    fn eat(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, byte: u8) -> Result<()> {
        if self.eat(byte) { Ok(()) } else { Err(format!("Expected '{}'", byte as char)) }
    }

    /// One space (more are taken too).
    fn space(&mut self) -> Result<()> {
        if self.take_while(|b| b == b' ').is_empty() { Err("Expected a space".into()) } else { Ok(()) }
    }

    /// A space, if more follows; `false` at the end or before `)`.
    fn more(&mut self) -> bool {
        if self.peek() == Some(b' ') {
            self.take_while(|b| b == b' ');
            !(self.at_end() || self.peek() == Some(b')'))
        } else {
            false
        }
    }

    fn at_end(&self) -> bool {
        self.line + 1 >= self.frame.lines.len() && self.rest().is_empty()
    }

    fn end(&mut self) -> Result<()> {
        self.take_while(|b| b == b' ');
        if self.at_end() { Ok(()) } else { Err("Unexpected arguments".into()) }
    }

    fn atom(&mut self) -> Result<&'a [u8]> {
        let atom = self.take_while(is_atom_char);
        if atom.is_empty() { Err("Expected an atom".into()) } else { Ok(atom) }
    }

    /// An atom in upper case.
    fn word(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(self.atom()?).to_ascii_uppercase())
    }

    /// A keyword, case-insensitively, if it comes next and ends there.
    fn keyword(&mut self, keyword: &str) -> bool {
        let rest = self.rest();
        let matched = rest.len() >= keyword.len()
            && rest[..keyword.len()].eq_ignore_ascii_case(keyword.as_bytes())
            && rest.get(keyword.len()).is_none_or(|&b| !is_atom_char(b));
        if matched {
            self.position += keyword.len();
        }
        matched
    }

    fn number(&mut self) -> Result<u32> {
        let digits = self.take_while(|b| b.is_ascii_digit());
        std::str::from_utf8(digits).ok().and_then(|d| d.parse().ok()).ok_or_else(|| "Expected a number".into())
    }

    fn number64(&mut self) -> Result<u64> {
        let digits = self.take_while(|b| b.is_ascii_digit());
        std::str::from_utf8(digits)
            .ok()
            .and_then(|d| d.parse::<u64>().ok())
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or_else(|| "Expected a number".into())
    }

    fn quoted(&mut self) -> Result<Vec<u8>> {
        self.expect(b'"')?;
        let mut out = Vec::new();
        loop {
            match self.peek() {
                None => return Err("Unterminated quoted string".into()),
                Some(b'"') => {
                    self.position += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.position += 1;
                    match self.peek() {
                        Some(byte @ (b'"' | b'\\')) => out.push(byte),
                        _ => return Err("Invalid escape in a quoted string".into()),
                    }
                    self.position += 1;
                }
                Some(b'\0' | b'\r' | b'\n') => return Err("Invalid character in a quoted string".into()),
                Some(byte) => {
                    out.push(byte);
                    self.position += 1;
                }
            }
        }
    }

    /// A quoted string or a literal.
    fn string(&mut self) -> Result<Cow<'a, [u8]>> {
        if self.at_literal() {
            Ok(Cow::Borrowed(self.literal()))
        } else if self.peek() == Some(b'"') {
            Ok(Cow::Owned(self.quoted()?))
        } else {
            Err("Expected a string".into())
        }
    }

    fn astring(&mut self) -> Result<Cow<'a, [u8]>> {
        if self.at_literal() || self.peek() == Some(b'"') {
            return self.string();
        }
        let atom = self.take_while(is_astring_char);
        if atom.is_empty() { Err("Expected a string".into()) } else { Ok(Cow::Borrowed(atom)) }
    }

    fn astring_text(&mut self) -> Result<String> {
        text(&self.astring()?)
    }

    fn nstring(&mut self) -> Result<Option<Cow<'a, [u8]>>> {
        if self.keyword("NIL") { Ok(None) } else { self.string().map(Some) }
    }

    /// A mailbox name in UTF-8: `INBOX` in any case is `INBOX`; without UTF-8, modified UTF-7 is decoded.
    fn mailbox(&mut self) -> Result<String> {
        let name = self.astring_text()?;
        Ok(self.mailbox_name(name))
    }

    fn mailbox_name(&self, name: String) -> String {
        if name.eq_ignore_ascii_case("INBOX") {
            return "INBOX".into();
        }
        if self.utf8 { name } else { utf7::decode(&name).unwrap_or(name) }
    }

    /// A pattern of `LIST`: like a mailbox name, with `%` and `*`.
    fn list_mailbox(&mut self) -> Result<String> {
        let name = if self.at_literal() || self.peek() == Some(b'"') {
            text(&self.string()?)?
        } else {
            let atom = self.take_while(|b| is_astring_char(b) || b == b'%' || b == b'*');
            if atom.is_empty() {
                return Err("Expected a mailbox pattern".into());
            }
            text(atom)?
        };
        Ok(if self.utf8 { name } else { utf7::decode(&name).unwrap_or(name) })
    }

    fn sequence_set(&mut self) -> Result<SequenceSet> {
        let text = self.take_while(|b| b.is_ascii_digit() || b":,*$".contains(&b));
        SequenceSet::parse(text).ok_or_else(|| "Invalid sequence set".into())
    }

    /// `(a b c)`, each read by `item`; empty lists if `empty`.
    fn list<T>(&mut self, empty: bool, mut item: impl FnMut(&mut Self) -> Result<T>) -> Result<Vec<T>> {
        self.expect(b'(')?;
        let mut items = Vec::new();
        if self.eat(b')') {
            return if empty { Ok(items) } else { Err("Expected items in the list".into()) };
        }
        loop {
            items.push(item(self)?);
            if self.eat(b')') {
                return Ok(items);
            }
            self.space()?;
        }
    }

    /// A flag: `\Seen`, `$Work`, `Keyword`.
    fn flag(&mut self) -> Result<String> {
        let backslash = self.eat(b'\\');
        let atom = self.atom()?;
        let mut flag = if backslash { "\\".to_owned() } else { String::new() };
        flag.push_str(&text(atom)?);
        Ok(flag)
    }

    fn command(&mut self) -> Result<Command> {
        self.space()?;
        let name = self.word().map_err(|_| "Expected a command".to_owned())?;
        let simple = |command: Command, cursor: &mut Self| -> Result<Command> {
            cursor.end()?;
            Ok(command)
        };
        match name.as_str() {
            "CAPABILITY" => simple(Command::Capability, self),
            "NOOP" => simple(Command::Noop, self),
            "LOGOUT" => simple(Command::Logout, self),
            "STARTTLS" => simple(Command::StartTls, self),
            "NAMESPACE" => simple(Command::Namespace, self),
            "IDLE" => simple(Command::Idle, self),
            "CHECK" => simple(Command::Check, self),
            "CLOSE" => simple(Command::Close, self),
            "UNSELECT" => simple(Command::Unselect, self),
            "EXPUNGE" => simple(Command::Expunge(None), self),
            "AUTHENTICATE" => {
                self.space()?;
                let mechanism = self.word()?;
                let initial = if self.more() {
                    let initial = self.take_while(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b));
                    if initial.is_empty() {
                        return Err("Invalid initial response".into());
                    }
                    Some(initial.to_vec())
                } else {
                    None
                };
                self.end()?;
                Ok(Command::Authenticate { mechanism, initial })
            }
            "LOGIN" => {
                self.space()?;
                let user = self.astring_text()?;
                self.space()?;
                let password = self.astring_text()?;
                self.end()?;
                Ok(Command::Login { user, password })
            }
            "ID" => {
                self.space()?;
                if !self.keyword("NIL") {
                    self.list(true, |cursor| {
                        cursor.string()?;
                        cursor.space()?;
                        cursor.nstring()
                    })?;
                }
                self.end()?;
                Ok(Command::Id)
            }
            "ENABLE" => {
                let mut capabilities = Vec::new();
                while self.more() {
                    capabilities.push(self.word()?);
                }
                if capabilities.is_empty() {
                    return Err("ENABLE needs a capability".into());
                }
                self.end()?;
                Ok(Command::Enable(capabilities))
            }
            "SELECT" | "EXAMINE" => self.select(name == "EXAMINE"),
            "CREATE" => {
                self.space()?;
                let mailbox = self.mailbox()?;
                // Parameters (RFC 4466) are read and not used.
                if self.more() {
                    self.parameters()?;
                }
                self.end()?;
                Ok(Command::Create(mailbox))
            }
            "DELETE" => self.one_mailbox(Command::Delete),
            "MYRIGHTS" => self.one_mailbox(Command::MyRights),
            "GETACL" => self.one_mailbox(Command::GetAcl),
            "GETQUOTAROOT" => self.one_mailbox(Command::GetQuotaRoot),
            "GETQUOTA" => {
                self.space()?;
                let root = self.astring_text()?;
                self.end()?;
                Ok(Command::GetQuota(root))
            }
            "SETQUOTA" => Ok(Command::SetQuota),
            "SUBSCRIBE" | "UNSUBSCRIBE" => {
                let subscribe = name == "SUBSCRIBE";
                self.one_mailbox(|mailbox| Command::Subscribe { mailbox, subscribe })
            }
            "RENAME" => {
                self.space()?;
                let from = self.mailbox()?;
                self.space()?;
                let to = self.mailbox()?;
                if self.more() {
                    self.parameters()?;
                }
                self.end()?;
                Ok(Command::Rename { from, to })
            }
            "LIST" => self.list_command(),
            "LSUB" => {
                self.space()?;
                let reference = self.mailbox()?;
                self.space()?;
                let pattern = self.list_mailbox()?;
                self.end()?;
                Ok(Command::Lsub { reference, pattern })
            }
            "STATUS" => {
                self.space()?;
                let mailbox = self.mailbox()?;
                self.space()?;
                let items = self.status_items()?;
                self.end()?;
                Ok(Command::Status { mailbox, items })
            }
            "APPEND" => self.append(),
            "DELETEACL" | "LISTRIGHTS" => {
                self.space()?;
                let mailbox = self.mailbox()?;
                self.space()?;
                let identifier = self.astring_text()?;
                self.end()?;
                Ok(if name == "DELETEACL" {
                    Command::DeleteAcl { mailbox, identifier }
                } else {
                    Command::ListRights { mailbox, identifier }
                })
            }
            "SETACL" => {
                self.space()?;
                let mailbox = self.mailbox()?;
                self.space()?;
                let identifier = self.astring_text()?;
                self.space()?;
                let rights = self.astring_text()?;
                self.end()?;
                let (mode, letters) = match rights.as_bytes().first() {
                    Some(b'+') => (StoreMode::Add, &rights[1..]),
                    Some(b'-') => (StoreMode::Remove, &rights[1..]),
                    _ => (StoreMode::Replace, rights.as_str()),
                };
                let mut expanded = String::new();
                for letter in letters.chars() {
                    match letter {
                        'c' => expanded.push('k'),
                        'd' => expanded.push_str("xte"),
                        'l' | 'r' | 's' | 'w' | 'i' | 'p' | 'k' | 'x' | 't' | 'e' | 'a' => expanded.push(letter),
                        '0'..='9' => {}
                        _ => return Err(format!("Unknown right '{letter}'")),
                    }
                }
                Ok(Command::SetAcl { mailbox, identifier, change: RightsChange { mode, letters: expanded } })
            }
            "UID" => {
                self.space()?;
                let name = self.word()?;
                self.selected_command(&name, true)
            }
            _ => self.selected_command(&name, false),
        }
    }

    fn one_mailbox(&mut self, make: impl FnOnce(String) -> Command) -> Result<Command> {
        self.space()?;
        let mailbox = self.mailbox()?;
        self.end()?;
        Ok(make(mailbox))
    }

    /// The commands of the selected state that have a `UID` form.
    fn selected_command(&mut self, name: &str, uid: bool) -> Result<Command> {
        match name {
            "FETCH" => {
                self.space()?;
                Ok(Command::Fetch { uid, fetch: self.fetch()? })
            }
            "STORE" => {
                self.space()?;
                Ok(Command::Store { uid, store: self.store()? })
            }
            "COPY" | "MOVE" => {
                self.space()?;
                let set = self.sequence_set()?;
                self.space()?;
                let mailbox = self.mailbox()?;
                self.end()?;
                Ok(Command::Copy { uid, is_move: name == "MOVE", set, mailbox })
            }
            "SEARCH" => {
                let search = self.search(true)?;
                Ok(Command::Search { uid, search })
            }
            "SORT" => {
                let options = self.result_options()?;
                self.space()?;
                let criteria = self.list(false, |cursor| {
                    let reverse = cursor.keyword("REVERSE");
                    if reverse {
                        cursor.space()?;
                    }
                    let key = match cursor.word()?.as_str() {
                        "ARRIVAL" => SortKey::Arrival,
                        "CC" => SortKey::Cc,
                        "DATE" => SortKey::Date,
                        "FROM" => SortKey::From,
                        "SIZE" => SortKey::Size,
                        "SUBJECT" => SortKey::Subject,
                        "TO" => SortKey::To,
                        "DISPLAYFROM" => SortKey::DisplayFrom,
                        "DISPLAYTO" => SortKey::DisplayTo,
                        other => return Err(format!("Unknown sort criterion {other}")),
                    };
                    Ok(SortCriterion { key, reverse })
                })?;
                let mut search = self.search_after_charset()?;
                search.options = options;
                Ok(Command::Sort { uid, criteria, search })
            }
            "THREAD" => {
                self.space()?;
                let algorithm = match self.word()?.as_str() {
                    "ORDEREDSUBJECT" => ThreadAlgorithm::OrderedSubject,
                    "REFERENCES" => ThreadAlgorithm::References,
                    other => return Err(format!("Unknown threading algorithm {other}")),
                };
                let search = self.search_after_charset()?;
                Ok(Command::Thread { uid, algorithm, search })
            }
            "EXPUNGE" if uid => {
                self.space()?;
                let set = self.sequence_set()?;
                self.end()?;
                Ok(Command::Expunge(Some(set)))
            }
            other => Err(format!("Unknown command {}", other.chars().take(32).collect::<String>())),
        }
    }

    /// Parameters of `CREATE` and `RENAME` (RFC 4466): a list of anything, read over.
    fn parameters(&mut self) -> Result<()> {
        self.skip_list(0)
    }

    fn skip_list(&mut self, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err("Nested too deeply".into());
        }
        self.list(true, |cursor| {
            if cursor.peek() == Some(b'(') {
                cursor.skip_list(depth + 1)
            } else if cursor.at_literal() || cursor.peek() == Some(b'"') {
                cursor.string().map(|_| ())
            } else {
                let item = cursor.take_while(|b| is_astring_char(b) || b == b'\\');
                if item.is_empty() { Err("Expected a parameter".into()) } else { Ok(()) }
            }
        })
        .map(|_| ())
    }

    fn select(&mut self, read_only: bool) -> Result<Command> {
        self.space()?;
        let mailbox = self.mailbox()?;
        let (mut condstore, mut qresync) = (false, None);
        if self.more() {
            self.list(false, |cursor| {
                match cursor.word()?.as_str() {
                    "CONDSTORE" => condstore = true,
                    "QRESYNC" => {
                        cursor.space()?;
                        cursor.expect(b'(')?;
                        let uid_validity = cursor.number()?;
                        cursor.space()?;
                        let modseq = cursor.number64()?;
                        let mut known_uids = None;
                        if cursor.more() && cursor.peek() != Some(b'(') {
                            known_uids = Some(cursor.sequence_set()?);
                            cursor.more();
                        }
                        if cursor.peek() == Some(b'(') {
                            cursor.expect(b'(')?;
                            cursor.sequence_set()?;
                            cursor.space()?;
                            cursor.sequence_set()?;
                            cursor.expect(b')')?;
                        }
                        cursor.expect(b')')?;
                        qresync = Some(QResync { uid_validity, modseq, known_uids });
                    }
                    other => return Err(format!("Unknown SELECT parameter {other}")),
                }
                Ok(())
            })?;
        }
        self.end()?;
        Ok(Command::Select { mailbox, read_only, condstore, qresync })
    }

    fn status_item(&mut self) -> Result<StatusItem> {
        Ok(match self.word()?.as_str() {
            "MESSAGES" => StatusItem::Messages,
            "RECENT" => StatusItem::Recent,
            "UIDNEXT" => StatusItem::UidNext,
            "UIDVALIDITY" => StatusItem::UidValidity,
            "UNSEEN" => StatusItem::Unseen,
            "DELETED" => StatusItem::Deleted,
            "SIZE" => StatusItem::Size,
            "HIGHESTMODSEQ" => StatusItem::HighestModSeq,
            "DELETED-STORAGE" => StatusItem::DeletedStorage,
            other => return Err(format!("Unknown status item {other}")),
        })
    }

    fn status_items(&mut self) -> Result<Vec<StatusItem>> {
        self.list(false, Self::status_item)
    }

    fn list_command(&mut self) -> Result<Command> {
        let mut list = List::default();
        self.space()?;
        if self.peek() == Some(b'(') {
            self.list(true, |cursor| {
                match cursor.word()?.as_str() {
                    "SUBSCRIBED" => list.subscribed_only = true,
                    "SPECIAL-USE" => list.special_use_only = true,
                    // Every match is listed anyway; there are no remote mailboxes.
                    "RECURSIVEMATCH" | "REMOTE" => {}
                    other => return Err(format!("Unknown selection option {other}")),
                }
                Ok(())
            })?;
            self.space()?;
        }
        list.reference = self.mailbox()?;
        self.space()?;
        list.patterns =
            if self.peek() == Some(b'(') { self.list(false, Self::list_mailbox)? } else { vec![self.list_mailbox()?] };
        if self.more() {
            if !self.keyword("RETURN") {
                return Err("Expected RETURN".into());
            }
            self.space()?;
            self.list(true, |cursor| {
                match cursor.word()?.as_str() {
                    "SUBSCRIBED" => list.return_subscribed = true,
                    "CHILDREN" => list.return_children = true,
                    "SPECIAL-USE" => list.return_special_use = true,
                    "STATUS" => {
                        cursor.space()?;
                        list.return_status = Some(cursor.status_items()?);
                    }
                    other => return Err(format!("Unknown return option {other}")),
                }
                Ok(())
            })?;
        }
        self.end()?;
        Ok(Command::List(list))
    }

    fn append(&mut self) -> Result<Command> {
        self.space()?;
        let mailbox = self.mailbox()?;
        let mut messages = Vec::new();
        while self.more() {
            let mut message = AppendMessage { flags: Vec::new(), date: None, data: Vec::new() };
            if self.peek() == Some(b'(') {
                message.flags = self.list(true, Self::flag)?;
                self.space()?;
            }
            if self.peek() == Some(b'"') {
                let value = text(&self.quoted()?)?;
                match date_time(&value) {
                    Some(date) => {
                        message.date = Some(date);
                        self.space()?;
                    }
                    // Not a date: the message itself, in a quoted string.
                    None => {
                        message.data = value.into_bytes();
                        messages.push(message);
                        continue;
                    }
                }
            }
            if self.keyword("UTF8") {
                // RFC 6855, 4: `UTF8 (~{n}…)`.
                self.space()?;
                self.expect(b'(')?;
                message.data = self.string()?.into_owned();
                self.expect(b')')?;
            } else {
                message.data = self.string()?.into_owned();
            }
            messages.push(message);
        }
        if messages.is_empty() {
            return Err("APPEND needs a message".into());
        }
        self.end()?;
        Ok(Command::Append { mailbox, messages })
    }

    fn result_options(&mut self) -> Result<Option<Vec<ResultOption>>> {
        let start = (self.line, self.position);
        if !(self.more() && self.keyword("RETURN")) {
            (self.line, self.position) = start;
            return Ok(None);
        }
        self.space()?;
        let options = self.list(true, |cursor| {
            Ok(match cursor.word()?.as_str() {
                "MIN" => ResultOption::Min,
                "MAX" => ResultOption::Max,
                "ALL" => ResultOption::All,
                "COUNT" => ResultOption::Count,
                "SAVE" => ResultOption::Save,
                other => return Err(format!("Unknown result option {other}")),
            })
        })?;
        Ok(Some(options))
    }

    /// `SEARCH`'s arguments: `[RETURN (…)] [CHARSET x] key…`.
    fn search(&mut self, charset_optional: bool) -> Result<Search> {
        let options = self.result_options()?;
        self.space()?;
        if charset_optional && self.keyword("CHARSET") {
            self.space()?;
            self.charset()?;
            self.space()?;
        }
        let key = self.keys()?;
        Ok(Search { options, key })
    }

    /// `SORT` and `THREAD`: the charset is required.
    fn search_after_charset(&mut self) -> Result<Search> {
        self.space()?;
        self.charset()?;
        self.space()?;
        Ok(Search { options: None, key: self.keys()? })
    }

    fn charset(&mut self) -> Result<()> {
        let charset = self.astring_text()?;
        if charset.eq_ignore_ascii_case("UTF-8") || charset.eq_ignore_ascii_case("US-ASCII") {
            Ok(())
        } else {
            Err(format!("BADCHARSET {}", charset.chars().take(32).collect::<String>()))
        }
    }

    /// Keys up to the end, all of which must match.
    fn keys(&mut self) -> Result<SearchKey> {
        let mut keys = vec![self.key(0)?];
        while self.more() {
            keys.push(self.key(0)?);
        }
        self.end()?;
        Ok(if keys.len() == 1 { keys.remove(0) } else { SearchKey::And(keys) })
    }

    fn search_string(&mut self) -> Result<String> {
        self.space()?;
        Ok(String::from_utf8_lossy(&self.astring()?).into_owned())
    }

    fn search_date(&mut self) -> Result<i64> {
        self.space()?;
        let value = if self.peek() == Some(b'"') { text(&self.quoted()?)? } else { text(self.atom()?)? };
        date(&value).ok_or_else(|| "Invalid date".into())
    }

    fn key(&mut self, depth: usize) -> Result<SearchKey> {
        if depth > MAX_DEPTH {
            return Err("Search keys nested too deeply".into());
        }
        if self.peek() == Some(b'(') {
            let keys = self.list(false, |cursor| cursor.key(depth + 1))?;
            return Ok(SearchKey::And(keys));
        }
        if self.peek().is_some_and(|b| b.is_ascii_digit() || b == b'*' || b == b'$') {
            return Ok(SearchKey::Sequence(self.sequence_set()?));
        }
        let word = self.word()?;
        Ok(match word.as_str() {
            "ALL" => SearchKey::All,
            "ANSWERED" => SearchKey::Answered,
            "DELETED" => SearchKey::Deleted,
            "DRAFT" => SearchKey::Draft,
            "FLAGGED" => SearchKey::Flagged,
            "SEEN" => SearchKey::Seen,
            "UNANSWERED" => SearchKey::Unanswered,
            "UNDELETED" => SearchKey::Undeleted,
            "UNDRAFT" => SearchKey::Undraft,
            "UNFLAGGED" => SearchKey::Unflagged,
            "UNSEEN" => SearchKey::Unseen,
            "RECENT" => SearchKey::Recent,
            "NEW" => SearchKey::New,
            "OLD" => SearchKey::Old,
            "KEYWORD" | "UNKEYWORD" => {
                self.space()?;
                let flag = self.flag()?;
                if word == "KEYWORD" { SearchKey::Keyword(flag) } else { SearchKey::Unkeyword(flag) }
            }
            "BCC" => SearchKey::Bcc(self.search_string()?),
            "CC" => SearchKey::Cc(self.search_string()?),
            "FROM" => SearchKey::From(self.search_string()?),
            "TO" => SearchKey::To(self.search_string()?),
            "SUBJECT" => SearchKey::Subject(self.search_string()?),
            "BODY" => SearchKey::Body(self.search_string()?),
            "TEXT" => SearchKey::Text(self.search_string()?),
            "HEADER" => {
                let name = self.search_string()?;
                SearchKey::Header(name, self.search_string()?)
            }
            "BEFORE" => SearchKey::Before(self.search_date()?),
            "ON" => SearchKey::On(self.search_date()?),
            "SINCE" => SearchKey::Since(self.search_date()?),
            "SENTBEFORE" => SearchKey::SentBefore(self.search_date()?),
            "SENTON" => SearchKey::SentOn(self.search_date()?),
            "SENTSINCE" => SearchKey::SentSince(self.search_date()?),
            "LARGER" | "SMALLER" | "OLDER" | "YOUNGER" => {
                self.space()?;
                let number = self.number64()?;
                match word.as_str() {
                    "LARGER" => SearchKey::Larger(number),
                    "SMALLER" => SearchKey::Smaller(number),
                    "OLDER" => SearchKey::Older(number),
                    _ => SearchKey::Younger(number),
                }
            }
            "MODSEQ" => {
                self.space()?;
                if self.peek() == Some(b'"') {
                    // An entry name and its type.
                    self.quoted()?;
                    self.space()?;
                    self.atom()?;
                    self.space()?;
                }
                SearchKey::ModSeq(self.number64()?)
            }
            "UID" => {
                self.space()?;
                SearchKey::Uid(self.sequence_set()?)
            }
            "NOT" => {
                self.space()?;
                SearchKey::Not(Box::new(self.key(depth + 1)?))
            }
            "OR" => {
                self.space()?;
                let first = self.key(depth + 1)?;
                self.space()?;
                SearchKey::Or(Box::new(first), Box::new(self.key(depth + 1)?))
            }
            other => return Err(format!("Unknown search key {}", other.chars().take(32).collect::<String>())),
        })
    }

    fn fetch(&mut self) -> Result<Fetch> {
        let set = self.sequence_set()?;
        self.space()?;
        let items = if self.peek() == Some(b'(') {
            self.list(false, Self::fetch_item)?
        } else if self.keyword("ALL") {
            vec![FetchItem::Flags, FetchItem::InternalDate, FetchItem::Rfc822Size, FetchItem::Envelope]
        } else if self.keyword("FULL") {
            vec![FetchItem::Flags, FetchItem::InternalDate, FetchItem::Rfc822Size, FetchItem::Envelope, FetchItem::Body]
        } else if self.keyword("FAST") {
            vec![FetchItem::Flags, FetchItem::InternalDate, FetchItem::Rfc822Size]
        } else {
            vec![self.fetch_item()?]
        };
        let (mut changed_since, mut vanished) = (None, false);
        if self.more() {
            self.list(false, |cursor| {
                match cursor.word()?.as_str() {
                    "CHANGEDSINCE" => {
                        cursor.space()?;
                        changed_since = Some(cursor.number64()?);
                    }
                    "VANISHED" => vanished = true,
                    other => return Err(format!("Unknown FETCH modifier {other}")),
                }
                Ok(())
            })?;
        }
        self.end()?;
        if vanished && changed_since.is_none() {
            return Err("VANISHED needs CHANGEDSINCE".into());
        }
        Ok(Fetch { set, items, changed_since, vanished })
    }

    fn fetch_item(&mut self) -> Result<FetchItem> {
        let name = self.take_while(|b| b.is_ascii_alphanumeric() || b == b'.');
        let name = String::from_utf8_lossy(name).to_ascii_uppercase();
        Ok(match name.as_str() {
            "ENVELOPE" => FetchItem::Envelope,
            "FLAGS" => FetchItem::Flags,
            "INTERNALDATE" => FetchItem::InternalDate,
            "RFC822" => FetchItem::Rfc822,
            "RFC822.HEADER" => FetchItem::Rfc822Header,
            "RFC822.SIZE" => FetchItem::Rfc822Size,
            "RFC822.TEXT" => FetchItem::Rfc822Text,
            "BODYSTRUCTURE" => FetchItem::BodyStructure,
            "UID" => FetchItem::Uid,
            "MODSEQ" => FetchItem::ModSeq,
            "BODY" if self.peek() != Some(b'[') => FetchItem::Body,
            "BODY" | "BODY.PEEK" => {
                let section = self.section()?;
                let partial = self.partial()?;
                FetchItem::Section { peek: name == "BODY.PEEK", section, partial }
            }
            "BINARY" | "BINARY.PEEK" | "BINARY.SIZE" => {
                self.expect(b'[')?;
                let part = self.part_numbers()?;
                self.expect(b']')?;
                if name == "BINARY.SIZE" {
                    FetchItem::BinarySize { part }
                } else {
                    let partial = self.partial()?;
                    FetchItem::Binary { peek: name == "BINARY.PEEK", part, partial }
                }
            }
            other => return Err(format!("Unknown FETCH item {}", other.chars().take(32).collect::<String>())),
        })
    }

    /// `1.2.3`, possibly empty; a trailing `.` is left for the caller.
    fn part_numbers(&mut self) -> Result<Vec<u32>> {
        let mut part = Vec::new();
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            let number = self.number()?;
            if number == 0 || part.len() >= 64 {
                return Err("Invalid part number".into());
            }
            part.push(number);
            let rest = self.rest();
            if rest.first() == Some(&b'.') && rest.get(1).is_some_and(u8::is_ascii_digit) {
                self.position += 1;
            } else {
                break;
            }
        }
        Ok(part)
    }

    fn section(&mut self) -> Result<Section> {
        self.expect(b'[')?;
        let part = self.part_numbers()?;
        if !part.is_empty() && self.peek() != Some(b']') {
            self.expect(b'.')?;
        }
        let text = if self.peek() == Some(b']') {
            None
        } else {
            let name = self.take_while(|b| b.is_ascii_alphabetic() || b == b'.');
            Some(match name.to_ascii_uppercase().as_slice() {
                b"HEADER" => SectionText::Header,
                b"TEXT" => SectionText::Text,
                b"MIME" if !part.is_empty() => SectionText::Mime,
                upper @ (b"HEADER.FIELDS" | b"HEADER.FIELDS.NOT") => {
                    self.space()?;
                    let names = self.list(false, |cursor| cursor.astring_text())?;
                    SectionText::Fields { not: upper.len() > b"HEADER.FIELDS".len(), names }
                }
                _ => return Err("Invalid section".into()),
            })
        };
        self.expect(b']')?;
        Ok(Section { part, text })
    }

    fn partial(&mut self) -> Result<Option<(u32, u32)>> {
        if !self.eat(b'<') {
            return Ok(None);
        }
        let start = self.number()?;
        self.expect(b'.')?;
        let length = self.number()?;
        if length == 0 {
            return Err("A partial needs a length".into());
        }
        self.expect(b'>')?;
        Ok(Some((start, length)))
    }

    fn store(&mut self) -> Result<Store> {
        let set = self.sequence_set()?;
        self.space()?;
        let mut unchanged_since = None;
        if self.peek() == Some(b'(') {
            self.list(false, |cursor| {
                if cursor.word()? != "UNCHANGEDSINCE" {
                    return Err("Unknown STORE modifier".into());
                }
                cursor.space()?;
                unchanged_since = Some(cursor.number64()?);
                Ok(())
            })?;
            self.space()?;
        }
        let mode = if self.eat(b'+') {
            StoreMode::Add
        } else if self.eat(b'-') {
            StoreMode::Remove
        } else {
            StoreMode::Replace
        };
        let silent = match self.word()?.as_str() {
            "FLAGS" => false,
            "FLAGS.SILENT" => true,
            _ => return Err("Expected FLAGS".into()),
        };
        self.space()?;
        let flags = if self.peek() == Some(b'(') {
            self.list(true, Self::flag)?
        } else {
            let mut flags = vec![self.flag()?];
            while self.more() {
                flags.push(self.flag()?);
            }
            flags
        };
        self.end()?;
        Ok(Store { set, unchanged_since, mode, silent, flags })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::sequence::{Bound, Item};

    fn frame(line: &str, literals: &[&str]) -> Frame {
        let lines: Vec<Vec<u8>> = line.split("{}").map(|line| line.as_bytes().to_vec()).collect();
        assert_eq!(lines.len(), literals.len() + 1);
        Frame { lines, literals: literals.iter().map(|literal| literal.as_bytes().to_vec()).collect() }
    }

    fn command(line: &str) -> Command {
        parse(&frame(line, &[]), false).unwrap_or_else(|bad| panic!("{line}: {bad:?}")).command
    }

    fn bad(line: &str) -> Bad {
        parse(&frame(line, &[]), false).expect_err(line)
    }

    fn set(text: &str) -> SequenceSet {
        SequenceSet::parse(text.as_bytes()).unwrap()
    }

    #[test]
    fn simple_commands() {
        assert_eq!(command("a capability"), Command::Capability);
        assert_eq!(command("a1.x NOOP"), Command::Noop);
        assert_eq!(
            command("A LOGIN alice@firma.example \"pass \\\"word\\\\\""),
            Command::Login { user: "alice@firma.example".into(), password: "pass \"word\\".into() }
        );
        assert_eq!(
            parse(&frame("a LOGIN {} {}", &["alice", "p w"]), false).unwrap().command,
            Command::Login { user: "alice".into(), password: "p w".into() }
        );
        assert_eq!(
            command("a AUTHENTICATE plain AGFsaWNlAHB3"),
            Command::Authenticate { mechanism: "PLAIN".into(), initial: Some(b"AGFsaWNlAHB3".to_vec()) }
        );
        assert_eq!(command("a AUTHENTICATE PLAIN"), Command::Authenticate { mechanism: "PLAIN".into(), initial: None });
        assert_eq!(
            command("a ENABLE qresync UTF8=ACCEPT"),
            Command::Enable(vec!["QRESYNC".into(), "UTF8=ACCEPT".into()])
        );
        assert_eq!(command("a ID (\"name\" \"Thunderbird\" \"version\" NIL)"), Command::Id);
        assert_eq!(command("a ID NIL"), Command::Id);
        assert_eq!(command("a UID EXPUNGE 4:7"), Command::Expunge(Some(set("4:7"))));
        assert_eq!(command("a SETQUOTA \"\" (STORAGE 10)"), Command::SetQuota);
    }

    #[test]
    fn mailboxes_in_utf7_or_utf8() {
        assert_eq!(
            command("a SELECT inbox"),
            Command::Select { mailbox: "INBOX".into(), read_only: false, condstore: false, qresync: None }
        );
        assert_eq!(command("a CREATE &AMQ-sterreich"), Command::Create("Ästerreich".into()));
        assert_eq!(command("a CREATE \"A &- B\""), Command::Create("A & B".into()));
        assert_eq!(command("a DELETE &AMQ"), Command::Delete("&AMQ".into()));
        assert_eq!(
            parse(&frame("a CREATE \"&AMQ-sterreich/Ünï\"", &[]), true).unwrap().command,
            Command::Create("&AMQ-sterreich/Ünï".into())
        );
        assert_eq!(command("a RENAME Old \"New Name\""), Command::Rename { from: "Old".into(), to: "New Name".into() });
        assert_eq!(
            command("a EXAMINE Sent (CONDSTORE)"),
            Command::Select { mailbox: "Sent".into(), read_only: true, condstore: true, qresync: None }
        );
        assert_eq!(command("a SELECT INBOX (QRESYNC (67890007 20050715194045000 41,43:211,214:541 (1:5 1:5)))"), {
            Command::Select {
                mailbox: "INBOX".into(),
                read_only: false,
                condstore: false,
                qresync: Some(QResync {
                    uid_validity: 67890007,
                    modseq: 20050715194045000,
                    known_uids: Some(set("41,43:211,214:541")),
                }),
            }
        });
        assert!(matches!(command("a SELECT INBOX (QRESYNC (1 2))"), Command::Select { qresync: Some(_), .. }));
    }

    #[test]
    fn lists_and_status() {
        assert_eq!(command("a LIST \"\" *"), Command::List(List { patterns: vec!["*".into()], ..List::default() }));
        let Command::List(list) = command(
            "a LIST (SUBSCRIBED RECURSIVEMATCH) \"\" (INBOX \"Sent\" %) RETURN (CHILDREN STATUS (MESSAGES SIZE))",
        ) else {
            panic!()
        };
        assert!(list.subscribed_only && list.return_children && !list.return_subscribed);
        assert_eq!(list.patterns, ["INBOX", "Sent", "%"]);
        assert_eq!(list.return_status, Some(vec![StatusItem::Messages, StatusItem::Size]));
        assert_eq!(command("a LSUB \"\" Work/%"), Command::Lsub { reference: "".into(), pattern: "Work/%".into() });
        assert_eq!(
            command("a STATUS INBOX (MESSAGES UIDNEXT highestmodseq)"),
            Command::Status {
                mailbox: "INBOX".into(),
                items: vec![StatusItem::Messages, StatusItem::UidNext, StatusItem::HighestModSeq]
            }
        );
        assert!(bad("a STATUS INBOX ()").text.contains("items"));
    }

    #[test]
    fn appends() {
        let Command::Append { mailbox, messages } = parse(
            &frame(
                "a APPEND Drafts (\\Draft $Work) \" 4-Jul-2026 10:00:00 +0200\" {} () {} UTF8 ({})",
                &["one", "two", "three"],
            ),
            false,
        )
        .unwrap()
        .command
        else {
            panic!()
        };
        assert_eq!(mailbox, "Drafts");
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].flags, ["\\Draft", "$Work"]);
        assert_eq!(messages[0].date, Some(1_783_152_000));
        assert_eq!((messages[1].data.as_slice(), messages[2].data.as_slice()), (&b"two"[..], &b"three"[..]));
        assert!(parse(&frame("a APPEND INBOX", &[]), false).is_err());
    }

    #[test]
    fn fetches() {
        let Command::Fetch { uid: true, fetch } = command(
            "a UID FETCH 1:* (UID FLAGS BODY.PEEK[HEADER.FIELDS (Subject From)] BODY[1.2.MIME] BODY[]<0.20> \
             BINARY.PEEK[1]<2.5> BINARY.SIZE[2] BODY BODYSTRUCTURE) (CHANGEDSINCE 12 VANISHED)",
        ) else {
            panic!()
        };
        assert_eq!(fetch.set.0, vec![Item::Range(Bound::Number(1), Bound::Last)]);
        assert_eq!((fetch.changed_since, fetch.vanished), (Some(12), true));
        assert_eq!(
            fetch.items,
            vec![
                FetchItem::Uid,
                FetchItem::Flags,
                FetchItem::Section {
                    peek: true,
                    section: Section {
                        part: vec![],
                        text: Some(SectionText::Fields { not: false, names: vec!["Subject".into(), "From".into()] })
                    },
                    partial: None
                },
                FetchItem::Section {
                    peek: false,
                    section: Section { part: vec![1, 2], text: Some(SectionText::Mime) },
                    partial: None
                },
                FetchItem::Section { peek: false, section: Section::default(), partial: Some((0, 20)) },
                FetchItem::Binary { peek: true, part: vec![1], partial: Some((2, 5)) },
                FetchItem::BinarySize { part: vec![2] },
                FetchItem::Body,
                FetchItem::BodyStructure,
            ]
        );
        assert!(matches!(command("a FETCH 2 FULL"), Command::Fetch { fetch, .. } if fetch.items.len() == 5));
        assert!(matches!(command("a FETCH 2 body[3.header]"), Command::Fetch { .. }));
        assert!(matches!(command("a FETCH $ uid"), Command::Fetch { .. }));
        for line in [
            "a FETCH 2 BINARY.PEEK[1.2.MIME]",
            "a FETCH 2 BODY[MIME]",
            "a FETCH 2 BODY[0]",
            "a FETCH 2 BODY[1]<5.0>",
            "a FETCH 2 (FLAGS",
            "a FETCH 2 PREVIEW",
            "a FETCH",
            "a FETCH 1 FLAGS (VANISHED)",
        ] {
            bad(line);
        }
    }

    #[test]
    fn stores_and_copies() {
        assert_eq!(
            command("a UID STORE 1:3 (UNCHANGEDSINCE 7) -FLAGS.SILENT (\\Seen $Work)"),
            Command::Store {
                uid: true,
                store: Store {
                    set: set("1:3"),
                    unchanged_since: Some(7),
                    mode: StoreMode::Remove,
                    silent: true,
                    flags: vec!["\\Seen".into(), "$Work".into()],
                }
            }
        );
        assert!(
            matches!(command("a STORE 1 FLAGS \\Seen \\Flagged"), Command::Store { store, .. } if store.flags.len() == 2)
        );
        assert!(matches!(command("a STORE 1 FLAGS ()"), Command::Store { store, .. } if store.flags.is_empty()));
        assert_eq!(
            command("a UID MOVE 2 Archive"),
            Command::Copy { uid: true, is_move: true, set: set("2"), mailbox: "Archive".into() }
        );
        assert_eq!(
            command("a SETACL INBOX bob@firma.example +cd"),
            Command::SetAcl {
                mailbox: "INBOX".into(),
                identifier: "bob@firma.example".into(),
                change: RightsChange { mode: StoreMode::Add, letters: "kxte".into() }
            }
        );
    }

    #[test]
    fn searches() {
        let Command::Search { uid: true, search } =
            command("a UID SEARCH RETURN (COUNT ALL) CHARSET UTF-8 OR SUBJECT second BODY hello (SEEN UNDELETED) 1:5")
        else {
            panic!()
        };
        assert_eq!(search.options, Some(vec![ResultOption::Count, ResultOption::All]));
        assert_eq!(
            search.key,
            SearchKey::And(vec![
                SearchKey::Or(Box::new(SearchKey::Subject("second".into())), Box::new(SearchKey::Body("hello".into()))),
                SearchKey::And(vec![SearchKey::Seen, SearchKey::Undeleted]),
                SearchKey::Sequence(set("1:5")),
            ])
        );
        let Command::Search { search, .. } =
            command("a SEARCH SINCE 1-Feb-2026 SENTBEFORE \"02-Feb-2026\" MODSEQ \"/flags/\\\\draft\" all 620162338")
        else {
            panic!()
        };
        assert_eq!(
            search.key,
            SearchKey::And(vec![
                SearchKey::Since(1_769_904_000),
                SearchKey::SentBefore(1_769_990_400),
                SearchKey::ModSeq(620162338)
            ])
        );
        assert!(matches!(
            parse(&frame("a SEARCH SUBJECT {}", &["Grüße"]), false).unwrap().command,
            Command::Search { search: Search { key: SearchKey::Subject(subject), .. }, .. } if subject == "Grüße"
        ));
        assert!(bad("a SEARCH CHARSET ISO-8859-1 ALL").text.starts_with("BADCHARSET"));
        let Command::Sort { criteria, .. } = command("a SORT (REVERSE ARRIVAL displayfrom) UTF-8 ALL") else {
            panic!()
        };
        assert_eq!(
            criteria,
            [
                SortCriterion { key: SortKey::Arrival, reverse: true },
                SortCriterion { key: SortKey::DisplayFrom, reverse: false }
            ]
        );
        assert!(matches!(
            command("a UID THREAD REFERENCES US-ASCII ALL"),
            Command::Thread { uid: true, algorithm: ThreadAlgorithm::References, .. }
        ));
        bad("a SEARCH BOGUS");
        bad("a SEARCH");
        bad("a SORT () UTF-8 ALL");
        let deep = format!("a SEARCH {}ALL{}", "NOT ".repeat(100), "");
        assert!(bad(&deep).text.contains("deeply"));
        let deep = format!("a SEARCH {}ALL{}", "(".repeat(100), ")".repeat(100));
        assert!(bad(&deep).text.contains("deeply"));
    }

    #[test]
    fn bad_commands() {
        assert_eq!(bad(""), Bad { tag: None, text: "A command starts with a tag and a space".into() });
        assert_eq!(bad("a").tag, None);
        assert_eq!(bad("+ NOOP").tag, None);
        assert_eq!(bad("a FOO").tag.as_deref(), Some("a"));
        bad("a NOOP extra");
        bad("a LOGIN \"unterminated");
        bad("a LOGIN \"bad\\x\" b");
        bad("a SELECT");
    }

    #[test]
    fn dates() {
        assert_eq!(date_time("17-Jul-1996 02:44:25 -0700"), Some(837_596_665));
        assert_eq!(date_time(" 7-Jul-1996 02:44:25 +0000"), Some(836_707_465));
        for bad in ["17-Jul-1996 02:44:25", "32-Jul-1996 02:44:25 +0000", "17-Jux-1996 02:44:25 +0000", "x"] {
            assert_eq!(date_time(bad), None, "{bad}");
        }
    }

    /// Random input – and random changes to valid commands – never panic.
    #[test]
    fn arbitrary_input_never_panics() {
        let samples = [
            "a UID FETCH 1:* (UID FLAGS BODY.PEEK[HEADER.FIELDS (Subject)]<0.5> BINARY[1.2] BODY[3.MIME])",
            "a SEARCH RETURN (MIN) CHARSET UTF-8 OR (NOT SEEN) HEADER Message-ID x UID 1:*,$",
            "a SELECT INBOX (QRESYNC (1 2 1:5 (1 1)))",
            "a LIST (SUBSCRIBED) \"\" (\"a\" %) RETURN (STATUS (MESSAGES))",
            "a APPEND INBOX (\\Seen) \"17-Jul-1996 02:44:25 -0700\" {}",
            "a STORE 1 (UNCHANGEDSINCE 3) +FLAGS.SILENT (\\Seen)",
            "a SORT (REVERSE DATE) UTF-8 SUBJECT {}",
            "a SETACL INBOX \"bob\" -lrs",
        ];
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut random = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..20_000 {
            let mut line: Vec<u8> = samples[round % samples.len()].as_bytes().to_vec();
            for _ in 0..(random() % 6) {
                let position = (random() as usize) % (line.len() + 1);
                match random() % 3 {
                    0 if position < line.len() => {
                        line.remove(position);
                    }
                    1 => line.insert(position, (random() % 256) as u8),
                    _ if position < line.len() => {
                        line[position] = b"(){}[]<>\" \\*%$:.,+-~0123456789"[(random() % 30) as usize]
                    }
                    _ => {}
                }
            }
            if round % 7 == 0 {
                line = (0..(random() % 64)).map(|_| (random() % 256) as u8).collect();
            }
            let mut lines: Vec<Vec<u8>> = Vec::new();
            let mut literals = Vec::new();
            for (index, piece) in String::from_utf8_lossy(&line).split("{}").enumerate() {
                if index > 0 {
                    literals.push(vec![(random() % 256) as u8; (random() % 4) as usize]);
                }
                lines.push(piece.as_bytes().to_vec());
            }
            let _ = parse(&Frame { lines, literals }, round % 2 == 0);
        }
    }
}
