// SPDX-License-Identifier: AGPL-3.0-or-later
//! The selected state: the mailbox as the client knows it – its emails in sequence-number order – brought up to
//! date with untagged `EXPUNGE`/`VANISHED`, `EXISTS` and `FETCH` responses; `SELECT` with CONDSTORE and QRESYNC
//! (RFC 7162), `FETCH`, `STORE`, `COPY`, `MOVE` and `EXPUNGE`.

use std::collections::{BTreeSet, HashMap};

use kernoid_mail::{Keyword, MailError, MailboxEntry, NewEmail, Rights};
use kernoid_mime::Message;
use uuid::Uuid;

use crate::{
    flags,
    mailboxes::{list_line, no_permission},
    message,
    proto::{
        request::{Fetch, FetchItem, QResync, Section, Store, StoreMode},
        response::{self, Code, FetchResponse, Status},
        sequence::{self, SequenceSet},
    },
    session::{Session, mail_error},
};

/// The flags kernoid keeps, for `FLAGS` and `PERMANENTFLAGS`.
const SYSTEM_FLAGS: &str = "\\Answered \\Flagged \\Deleted \\Seen \\Draft";

#[derive(Debug, Clone)]
pub(crate) struct Selected {
    pub id: Uuid,
    /// The account whose mailbox it is: the user's own, or one shared with them.
    pub owner: Uuid,
    /// The user's rights on it (RFC 0002, 12.2).
    pub rights: Rights,
    /// `EXAMINE`, or no right to change anything.
    pub read_only: bool,
    /// The emails as the client knows them; sequence number = position + 1.
    pub entries: Vec<MailboxEntry>,
    /// The UIDs of the last `SEARCH … SAVE` (`$`, RFC 5182).
    pub saved: Vec<u32>,
}

impl Selected {
    /// The positions of the emails a set names, by UID or sequence number.
    pub fn resolve(&self, sequence: &SequenceSet, is_uid: bool) -> Vec<usize> {
        let max = if is_uid { self.entries.last().map_or(0, |entry| entry.uid) } else { self.entries.len() as u32 };
        self.entries
            .iter()
            .enumerate()
            .filter(|(position, entry)| {
                let value = if is_uid { entry.uid } else { *position as u32 + 1 };
                sequence.contains(value, max, self.saved.contains(&entry.uid))
            })
            .map(|(position, _)| position)
            .collect()
    }
}

/// `* n FETCH (UID … FLAGS (…) [MODSEQ (…)])`: an email's flags, unasked.
fn flag_update(out: &mut Vec<u8>, sequence: usize, entry: &MailboxEntry, uid: bool, modseq: bool) {
    let mut fetch = FetchResponse::new(sequence as u32);
    if uid {
        fetch.item().extend_from_slice(format!("UID {}", entry.uid).as_bytes());
    }
    let item = fetch.item();
    item.extend_from_slice(b"FLAGS ");
    response::flag_list(item, &flags::flags(&entry.keywords));
    if modseq {
        fetch.item().extend_from_slice(format!("MODSEQ ({})", entry.modseq).as_bytes());
    }
    out.extend_from_slice(&fetch.finish());
}

/// `1.2.3`.
fn part_name(part: &[u32]) -> String {
    part.iter().map(u32::to_string).collect::<Vec<_>>().join(".")
}

/// `[1.2.HEADER.FIELDS (Subject)]` as the client asked for it.
fn section_name(out: &mut Vec<u8>, section: &Section) {
    use crate::proto::request::SectionText;
    out.push(b'[');
    out.extend_from_slice(part_name(&section.part).as_bytes());
    if let Some(text) = &section.text {
        if !section.part.is_empty() {
            out.push(b'.');
        }
        match text {
            SectionText::Header => out.extend_from_slice(b"HEADER"),
            SectionText::Text => out.extend_from_slice(b"TEXT"),
            SectionText::Mime => out.extend_from_slice(b"MIME"),
            SectionText::Fields { not, names } => {
                out.extend_from_slice(if *not { b"HEADER.FIELDS.NOT (" } else { b"HEADER.FIELDS (" });
                for (index, name) in names.iter().enumerate() {
                    if index > 0 {
                        out.push(b' ');
                    }
                    if !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
                        out.extend_from_slice(name.as_bytes());
                    } else {
                        response::string(out, name.as_bytes(), false);
                    }
                }
                out.push(b')');
            }
        }
    }
    out.push(b']');
}

/// `* VANISHED [(EARLIER)] uids` (RFC 7162, 3.2.10).
fn vanished(out: &mut Vec<u8>, earlier: bool, uids: &[u32]) {
    let earlier = if earlier { "(EARLIER) " } else { "" };
    out.extend_from_slice(format!("* VANISHED {earlier}{}\r\n", sequence::compact(uids)).as_bytes());
}

impl Session {
    pub(crate) async fn select(
        &mut self,
        mailbox: &str,
        read_only: bool,
        condstore: bool,
        qresync: Option<QResync>,
    ) -> Status {
        let closed_previous = self.selected.take().is_some();
        if qresync.is_some() && !self.qresync {
            return Status::bad("Enable QRESYNC first");
        }
        if condstore {
            self.condstore = true;
        }
        let folders = match self.folders().await {
            Ok(folders) => folders,
            Err(response) => return response,
        };
        let Some(folder) = folders.find(mailbox) else {
            return Status::no("No such mailbox").with_code(Code::NonExistent);
        };
        if !folder.rights.contains(Rights::READ) {
            return no_permission("read this mailbox");
        }
        let (id, uid_validity, uid_next) = (folder.info.id, folder.info.uid_validity, folder.info.uid_next);
        let (account, rights) = (folder.owner, folder.rights);
        let changing = [Rights::SEEN, Rights::WRITE, Rights::INSERT, Rights::DELETE, Rights::EXPUNGE];
        let read_only = read_only || !changing.iter().any(|right| rights.contains(*right));
        let name = folder.name.clone();
        let special_use = self.special_use(folder);
        let modseq = match self.inner.mail.state(account).await {
            Ok(modseq) => modseq,
            Err(error) => return mail_error(error),
        };
        let entries = match self.inner.mail.mailbox_entries(account, id).await {
            Ok(entries) => entries,
            Err(error) => return mail_error(error),
        };
        let unseen = entries.iter().position(|entry| !entry.keywords.iter().any(|k| k == "$seen"));
        // RFC 9051, 6.3.2 (and RFC 3501, 6.3.1 for IMAP4rev1).
        let mut out = if closed_previous {
            Status::ok("Closed previous mailbox").with_code(Code::Closed).line(None)
        } else {
            Vec::new()
        };
        out.extend_from_slice(format!("* {} EXISTS\r\n* FLAGS ({SYSTEM_FLAGS})\r\n", entries.len()).as_bytes());
        if self.rev2 {
            list_line(&mut out, "LIST", &special_use.into_iter().collect::<Vec<_>>(), &name, self.utf8);
        } else {
            out.extend_from_slice(b"* 0 RECENT\r\n");
            if let Some(unseen) = unseen {
                out.extend_from_slice(
                    &Status::ok("Unseen messages").with_code(Code::Unseen(unseen as u32 + 1)).line(None),
                );
            }
        }
        let permanent = if read_only { "" } else { "\\Deleted \\Seen \\Answered \\Flagged \\Draft \\*" };
        out.extend_from_slice(&Status::ok("Flags that stay").with_code(Code::PermanentFlags(permanent)).line(None));
        out.extend_from_slice(&Status::ok("UIDs valid").with_code(Code::UidValidity(uid_validity)).line(None));
        out.extend_from_slice(&Status::ok("Next predicted UID").with_code(Code::UidNext(uid_next)).line(None));
        if self.condstore {
            out.extend_from_slice(&Status::ok("Highest modseq").with_code(Code::HighestModSeq(modseq)).line(None));
        }
        self.write(out);
        // QRESYNC (RFC 7162, 3.2.5): what left the mailbox and what changed since the client's last state.
        if let Some(qresync) = qresync
            && qresync.uid_validity == uid_validity
        {
            let gone = match self.inner.mail.expunged_since(id, qresync.modseq).await {
                Ok(gone) => gone,
                Err(error) => return mail_error(error),
            };
            let max = uid_next.saturating_sub(1);
            let gone: Vec<u32> = gone
                .into_iter()
                .filter(|uid| qresync.known_uids.as_ref().is_none_or(|known| known.contains(*uid, max, false)))
                .collect();
            let mut out = Vec::new();
            if !gone.is_empty() {
                vanished(&mut out, true, &gone);
            }
            for (position, entry) in entries.iter().enumerate() {
                if entry.modseq > qresync.modseq {
                    flag_update(&mut out, position + 1, entry, true, true);
                }
            }
            self.write(out);
        }
        self.selected = Some(Selected { id, owner: account, rights, read_only, entries, saved: Vec::new() });
        Status::done().with_code(if read_only { Code::ReadOnly } else { Code::ReadWrite })
    }

    /// Tells the client what changed in the selected mailbox since it last heard.
    pub(crate) async fn sync(&mut self) {
        let Some(selected) = &self.selected else { return };
        let account = selected.owner;
        let fresh = match self.inner.mail.mailbox_entries(account, selected.id).await {
            Ok(fresh) => fresh,
            Err(MailError::NotFound(_)) => Vec::new(),
            Err(error) => {
                tracing::warn!(%error, "reading the selected mailbox");
                return;
            }
        };
        let by_uid: HashMap<u32, &MailboxEntry> = fresh.iter().map(|entry| (entry.uid, entry)).collect();
        let mut out = Vec::new();
        let gone: Vec<u32> = selected
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| !by_uid.contains_key(&entry.uid))
            .map(|(position, entry)| if self.qresync { entry.uid } else { position as u32 + 1 })
            .collect();
        if self.qresync {
            if !gone.is_empty() {
                vanished(&mut out, false, &gone);
            }
        } else {
            // Each EXPUNGE moves the numbers after it down by one.
            for (removed, number) in gone.iter().enumerate() {
                out.extend_from_slice(format!("* {} EXPUNGE\r\n", number - removed as u32).as_bytes());
            }
        }
        let known: Vec<&MailboxEntry> =
            selected.entries.iter().filter(|entry| by_uid.contains_key(&entry.uid)).collect();
        for (position, entry) in known.iter().enumerate() {
            let now = by_uid[&entry.uid];
            if now.keywords != entry.keywords || (self.condstore && now.modseq != entry.modseq) {
                flag_update(&mut out, position + 1, now, true, self.condstore);
            }
        }
        if fresh.len() != known.len() {
            out.extend_from_slice(format!("* {} EXISTS\r\n", fresh.len()).as_bytes());
        }
        self.write(out);
        if let Some(selected) = &mut self.selected {
            selected.entries = fresh;
        }
    }

    pub(crate) async fn fetch(&mut self, fetch: Fetch, is_uid: bool) -> Status {
        let Some(selected) = self.selected.clone() else { return Status::bad("No mailbox selected") };
        let account = selected.owner;
        let mut positions = selected.resolve(&fetch.set, is_uid);
        let mut items = fetch.items;
        if let Some(changed_since) = fetch.changed_since {
            self.condstore = true;
            positions.retain(|&position| selected.entries[position].modseq > changed_since);
            if fetch.vanished {
                if !is_uid || !self.qresync {
                    return Status::bad("VANISHED needs UID FETCH and QRESYNC");
                }
                let gone = match self.inner.mail.expunged_since(selected.id, changed_since).await {
                    Ok(gone) => gone,
                    Err(error) => return mail_error(error),
                };
                let max = selected.entries.last().map_or(0, |entry| entry.uid);
                let gone: Vec<u32> = gone.into_iter().filter(|uid| fetch.set.contains(*uid, max, false)).collect();
                if !gone.is_empty() {
                    let mut out = Vec::new();
                    vanished(&mut out, true, &gone);
                    self.write(out);
                }
            }
        }
        if is_uid && !items.contains(&FetchItem::Uid) {
            items.insert(0, FetchItem::Uid);
        }
        if self.condstore && !items.contains(&FetchItem::ModSeq) {
            items.push(FetchItem::ModSeq);
        }
        let needs_message = items.iter().any(|item| {
            !matches!(
                item,
                FetchItem::Flags | FetchItem::InternalDate | FetchItem::Rfc822Size | FetchItem::Uid | FetchItem::ModSeq
            )
        });
        let marks_seen = !selected.read_only
            && selected.rights.contains(Rights::SEEN)
            && items.iter().any(|item| {
                matches!(
                    item,
                    FetchItem::Section { peek: false, .. }
                        | FetchItem::Binary { peek: false, .. }
                        | FetchItem::Rfc822
                        | FetchItem::Rfc822Text
                )
            });
        let seen = Keyword::parse("$seen").expect("a keyword");
        let utf8 = self.utf8;
        for position in positions {
            let mut entry = selected.entries[position].clone();
            let mut flags_changed = false;
            if marks_seen && !entry.keywords.iter().any(|k| k == "$seen") {
                match self.inner.mail.update_keywords(account, entry.email, std::slice::from_ref(&seen), &[]).await {
                    Ok(()) => {
                        entry.keywords.push("$seen".to_owned());
                        flags_changed = true;
                        if let Some(selected) = &mut self.selected {
                            selected.entries[position].keywords = entry.keywords.clone();
                        }
                    }
                    Err(MailError::NotFound(_)) => continue,
                    Err(error) => return mail_error(error),
                }
            }
            let raw = if needs_message {
                match self.inner.mail.raw_email(account, entry.email).await {
                    Ok(raw) => Some(raw),
                    // Expunged meanwhile: the client hears of it later.
                    Err(MailError::NotFound(_)) => continue,
                    Err(error) => return mail_error(error),
                }
            } else {
                None
            };
            let parsed = raw.as_deref().and_then(Message::parse);
            let mut response = FetchResponse::new(position as u32 + 1);
            for item in &items {
                let message = parsed.as_ref();
                let raw = raw.as_deref().unwrap_or_default();
                match item {
                    FetchItem::Uid => response.item().extend_from_slice(format!("UID {}", entry.uid).as_bytes()),
                    FetchItem::Flags => {
                        let out = response.item();
                        out.extend_from_slice(b"FLAGS ");
                        response::flag_list(out, &flags::flags(&entry.keywords));
                    }
                    FetchItem::InternalDate => {
                        let out = response.item();
                        out.extend_from_slice(b"INTERNALDATE ");
                        response::internal_date(out, entry.received_at);
                    }
                    FetchItem::Rfc822Size => {
                        response.item().extend_from_slice(format!("RFC822.SIZE {}", entry.size).as_bytes());
                    }
                    FetchItem::ModSeq => {
                        response.item().extend_from_slice(format!("MODSEQ ({})", entry.modseq).as_bytes());
                    }
                    FetchItem::Rfc822 => {
                        let out = response.item();
                        out.extend_from_slice(b"RFC822 ");
                        response::literal(out, raw);
                    }
                    FetchItem::Rfc822Header | FetchItem::Rfc822Text => {
                        let Some(message) = message else { continue };
                        let body = message.root().root_part().offset_body().min(raw.len());
                        let (name, content) = if *item == FetchItem::Rfc822Header {
                            ("RFC822.HEADER ", &raw[..body])
                        } else {
                            ("RFC822.TEXT ", &raw[body..])
                        };
                        let out = response.item();
                        out.extend_from_slice(name.as_bytes());
                        response::literal(out, content);
                    }
                    FetchItem::Envelope => {
                        let Some(message) = message else { continue };
                        let out = response.item();
                        out.extend_from_slice(b"ENVELOPE ");
                        message::envelope(out, message.root(), utf8);
                    }
                    FetchItem::Body | FetchItem::BodyStructure => {
                        let Some(message) = message else { continue };
                        let extended = *item == FetchItem::BodyStructure;
                        let out = response.item();
                        out.extend_from_slice(if extended { b"BODYSTRUCTURE " } else { b"BODY " });
                        message::body_structure(out, message, extended, utf8);
                    }
                    FetchItem::Section { section, partial, .. } => {
                        let Some(message) = message else { continue };
                        let content = message::section(message, section).unwrap_or_default();
                        let out = response.item();
                        out.extend_from_slice(b"BODY");
                        section_name(out, section);
                        if let Some((start, _)) = partial {
                            out.extend_from_slice(format!("<{start}>").as_bytes());
                        }
                        out.push(b' ');
                        response::literal(out, message::partial(&content, *partial));
                    }
                    FetchItem::Binary { part, partial, .. } => {
                        let Some(message) = message else { continue };
                        let Ok(content) = message::binary(message, part) else {
                            return Status::no("The part cannot be decoded").with_code(Code::UnknownCte);
                        };
                        let content = content.unwrap_or_default();
                        let out = response.item();
                        out.extend_from_slice(format!("BINARY[{}]", part_name(part)).as_bytes());
                        if let Some((start, _)) = partial {
                            out.extend_from_slice(format!("<{start}>").as_bytes());
                        }
                        out.push(b' ');
                        response::literal8(out, message::partial(&content, *partial));
                    }
                    FetchItem::BinarySize { part } => {
                        let Some(message) = message else { continue };
                        let Ok(content) = message::binary(message, part) else {
                            return Status::no("The part cannot be decoded").with_code(Code::UnknownCte);
                        };
                        let size = content.map_or(0, |content| content.len());
                        response
                            .item()
                            .extend_from_slice(format!("BINARY.SIZE[{}] {size}", part_name(part)).as_bytes());
                    }
                }
            }
            if flags_changed && !items.contains(&FetchItem::Flags) {
                let out = response.item();
                out.extend_from_slice(b"FLAGS ");
                response::flag_list(out, &flags::flags(&entry.keywords));
            }
            self.write(response.finish());
            // A broken connection shows at the next flush.
            let _ = self.flush_if_large().await;
        }
        Status::done()
    }

    pub(crate) async fn store(&mut self, arguments: Store, is_uid: bool) -> Status {
        let Some(selected) = self.selected.clone() else { return Status::bad("No mailbox selected") };
        let account = selected.owner;
        if selected.read_only {
            return Status::no("The mailbox is read-only").with_code(Code::ReadOnly);
        }
        if arguments.unchanged_since.is_some() {
            self.condstore = true;
        }
        // Flags the user may not change are left as they are (RFC 4314, 4).
        let may = |keyword: &str| selected.rights.contains(flags::right(keyword));
        let keywords: Vec<Keyword> = arguments
            .flags
            .iter()
            .filter_map(|flag| flags::keyword(flag))
            .filter(|keyword| may(keyword.as_str()))
            .collect();
        let mut modified = Vec::new();
        let mut touched = BTreeSet::new();
        for position in selected.resolve(&arguments.set, is_uid) {
            let entry = &selected.entries[position];
            if arguments.unchanged_since.is_some_and(|since| entry.modseq > since) {
                modified.push(if is_uid { entry.uid } else { position as u32 + 1 });
                continue;
            }
            let (add, remove): (Vec<Keyword>, Vec<Keyword>) = match arguments.mode {
                StoreMode::Replace => {
                    let removed = entry
                        .keywords
                        .iter()
                        .filter(|current| may(current) && !keywords.iter().any(|k| k.as_str() == current.as_str()))
                        .filter_map(|current| Keyword::parse(current).ok())
                        .collect();
                    (keywords.clone(), removed)
                }
                StoreMode::Add => (keywords.clone(), Vec::new()),
                StoreMode::Remove => (Vec::new(), keywords.clone()),
            };
            match self.inner.mail.update_keywords(account, entry.email, &add, &remove).await {
                Ok(()) => {
                    touched.insert(entry.uid);
                }
                Err(MailError::NotFound(_)) => {}
                Err(error) => return mail_error(error),
            }
        }
        let fresh = match self.inner.mail.mailbox_entries(account, selected.id).await {
            Ok(fresh) => fresh,
            Err(error) => return mail_error(error),
        };
        let by_uid: HashMap<u32, MailboxEntry> = fresh.into_iter().map(|entry| (entry.uid, entry)).collect();
        let mut out = Vec::new();
        if let Some(selected) = &mut self.selected {
            for (position, entry) in selected.entries.iter_mut().enumerate() {
                if !touched.contains(&entry.uid) {
                    continue;
                }
                if let Some(now) = by_uid.get(&entry.uid) {
                    *entry = now.clone();
                    if !arguments.silent || self.condstore {
                        flag_update(&mut out, position + 1, entry, is_uid, self.condstore);
                    }
                }
            }
        }
        self.write(out);
        if modified.is_empty() {
            Status::done()
        } else {
            Status::ok("Conditional STORE failed").with_code(Code::Modified(modified))
        }
    }

    pub(crate) async fn copy_move(&mut self, set: &SequenceSet, mailbox: &str, is_uid: bool, is_move: bool) -> Status {
        let Some(selected) = self.selected.clone() else { return Status::bad("No mailbox selected") };
        if is_move && (selected.read_only || !selected.rights.contains(Rights::DELETE | Rights::EXPUNGE)) {
            return Status::no("No right to remove messages here").with_code(Code::NoPerm);
        }
        let folders = match self.folders().await {
            Ok(folders) => folders,
            Err(response) => return response,
        };
        let Some(target) = folders.find(mailbox) else {
            return Status::no("No such mailbox").with_code(Code::TryCreate);
        };
        if !target.rights.contains(Rights::INSERT) {
            return no_permission("add messages to that mailbox");
        }
        if is_move && target.info.id == selected.id {
            return Status::no("The message is in this mailbox already").with_code(Code::Cannot);
        }
        let positions = selected.resolve(set, is_uid);
        if positions.is_empty() {
            return Status::done();
        }
        let emails: Vec<Uuid> = positions.iter().map(|&position| selected.entries[position].email).collect();
        let src_uids: Vec<u32> = positions.iter().map(|&position| selected.entries[position].uid).collect();
        let mail = &self.inner.mail;
        let placed = if target.owner != selected.owner {
            copy_between_stores(mail, &selected, &positions, target).await
        } else if is_move {
            mail.move_to_mailbox(selected.owner, &emails, selected.id, target.info.id).await
        } else {
            mail.copy_to_mailbox(selected.owner, &emails, target.info.id).await
        };
        let dest_uids = match placed {
            Ok(uids) => uids,
            Err(MailError::NotFound("the email")) => {
                return Status::no("Some of the messages were expunged").with_code(Code::ExpungeIssued);
            }
            Err(error) => return mail_error(error),
        };
        if is_move && target.owner != selected.owner {
            let uids: BTreeSet<u32> = src_uids.iter().copied().collect();
            if let Err(error) = mail.remove_from_mailbox(selected.owner, selected.id, &uids).await {
                return mail_error(error);
            }
        }
        let code = Code::CopyUid { uid_validity: target.info.uid_validity, source: src_uids, target: dest_uids };
        if is_move {
            // RFC 6851, 4.3: COPYUID in an untagged OK before the EXPUNGEs the sync sends.
            self.write(Status::ok("Moved").with_code(code).line(None));
            Status::done()
        } else {
            Status::done().with_code(code)
        }
    }

    /// `EXPUNGE`, `UID EXPUNGE` (UIDPLUS) and the silent one of `CLOSE`: the sync reports what went.
    pub(crate) async fn expunge(&mut self, uids: Option<SequenceSet>, report: bool) -> Status {
        let Some(selected) = &self.selected else { return Status::bad("No mailbox selected") };
        let account = selected.owner;
        if selected.read_only || !selected.rights.contains(Rights::EXPUNGE) {
            return match report {
                false => Status::done(),
                true if selected.read_only => Status::no("The mailbox is read-only").with_code(Code::ReadOnly),
                true => no_permission("expunge messages here"),
            };
        }
        let only: Option<BTreeSet<u32>> = uids.map(|uids| {
            selected.resolve(&uids, true).into_iter().map(|position| selected.entries[position].uid).collect()
        });
        match self.inner.mail.expunge(account, selected.id, only.as_ref()).await {
            Ok(_) => Status::done(),
            Err(error) => mail_error(error),
        }
    }
}

/// Copies emails into a mailbox of another store (between the user's own and a shared one): each is stored there anew,
/// with the flags the user may set there.
async fn copy_between_stores(
    mail: &kernoid_mail::Mail,
    selected: &Selected,
    positions: &[usize],
    target: &crate::folders::Folder,
) -> Result<Vec<u32>, MailError> {
    {
        let mut uids = Vec::with_capacity(positions.len());
        for &position in positions {
            let entry = &selected.entries[position];
            let raw = mail.raw_email(selected.owner, entry.email).await?;
            let keywords = entry
                .keywords
                .iter()
                .filter(|keyword| target.rights.contains(flags::right(keyword)))
                .filter_map(|keyword| Keyword::parse(keyword).ok())
                .collect();
            let new = NewEmail { mailbox_ids: vec![target.info.id], keywords, received_at: Some(entry.received_at) };
            let imported = mail.import_email(target.owner, raw, new).await?;
            let email = mail.email(target.owner, imported.id).await?;
            uids.extend(email.mailboxes.iter().find(|(id, _)| *id == target.info.id).map(|(_, uid)| *uid));
        }
        Ok(uids)
    }
}
