// SPDX-License-Identifier: AGPL-3.0-or-later
//! The selected state: the mailbox as the client knows it – its emails in sequence-number order – brought up to
//! date with untagged `EXPUNGE`/`VANISHED`, `EXISTS` and `FETCH` responses; `SELECT` with CONDSTORE and QRESYNC
//! (RFC 7162), `FETCH`, `STORE`, `COPY`, `MOVE` and `EXPUNGE`.

use std::collections::{BTreeSet, HashMap};

use kernoid_mail::{Keyword, MailError, MailboxEntry, NewEmail, Rights};
use mail_parser::MessageParser;
use uuid::Uuid;

use crate::{
    flags,
    mailboxes::no_permission,
    message,
    proto::{
        Command, ResponseCode, StatusResponse,
        protocol::{
            ImapResponse, Sequence, copy_move, expunge,
            fetch::{self, Attribute, DataItem, FetchItem},
            list::ListItem,
            select::{self, HighestModSeq},
            store::{self, Operation},
        },
        types::SliceRange,
    },
    session::{Session, mail_error},
};

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

pub(crate) fn in_set(sequence: &Sequence, value: u32, max: u32, saved: bool) -> bool {
    match sequence {
        Sequence::SavedSearch => saved,
        Sequence::List { items } => items.iter().any(|item| in_set(item, value, max, saved)),
        sequence => sequence.contains(value, max),
    }
}

impl Selected {
    /// The positions of the emails a set names, by UID or sequence number.
    pub fn resolve(&self, sequence: &Sequence, is_uid: bool) -> Vec<usize> {
        let max = if is_uid { self.entries.last().map_or(0, |entry| entry.uid) } else { self.entries.len() as u32 };
        self.entries
            .iter()
            .enumerate()
            .filter(|(position, entry)| {
                let value = if is_uid { entry.uid } else { *position as u32 + 1 };
                in_set(sequence, value, max, self.saved.contains(&entry.uid))
            })
            .map(|(position, _)| position)
            .collect()
    }
}

/// `* n FETCH (UID … FLAGS (…) [MODSEQ (…)])`: an email's flags, unasked.
fn flag_update(out: &mut Vec<u8>, sequence: usize, entry: &MailboxEntry, uid: bool, modseq: bool) {
    let mut items = Vec::new();
    if uid {
        items.push(DataItem::Uid { uid: entry.uid });
    }
    items.push(DataItem::Flags { flags: flags::flags(&entry.keywords) });
    if modseq {
        items.push(DataItem::ModSeq { modseq: entry.modseq });
    }
    FetchItem { id: sequence as u32, is_uidonly: false, items }.serialize(out, false);
}

impl Session {
    pub(crate) async fn select(&mut self, arguments: select::Arguments, read_only: bool) -> StatusResponse {
        let command = if read_only { Command::Examine } else { Command::Select };
        let closed_previous = self.selected.take().is_some();
        if arguments.qresync.is_some() && !self.qresync {
            return StatusResponse::bad("Enable QRESYNC first");
        }
        if arguments.condstore {
            self.condstore = true;
        }
        let folders = match self.folders().await {
            Ok(folders) => folders,
            Err(response) => return response,
        };
        let Some(folder) = folders.find(&arguments.mailbox_name) else {
            return StatusResponse::no("No such mailbox").with_code(ResponseCode::NonExistent);
        };
        if !folder.rights.contains(Rights::READ) {
            return no_permission("read this mailbox");
        }
        let (id, uid_validity, uid_next) = (folder.info.id, folder.info.uid_validity, folder.info.uid_next);
        let (account, rights) = (folder.owner, folder.rights);
        let changing = [Rights::SEEN, Rights::WRITE, Rights::INSERT, Rights::DELETE, Rights::EXPUNGE];
        let read_only = read_only || !changing.iter().any(|right| rights.contains(*right));
        let mut item = ListItem::new(folder.name.clone());
        item.attributes.extend(self.special_use(folder));
        let modseq = match self.inner.mail.state(account).await {
            Ok(modseq) => modseq,
            Err(error) => return mail_error(error),
        };
        let entries = match self.inner.mail.mailbox_entries(account, id).await {
            Ok(entries) => entries,
            Err(error) => return mail_error(error),
        };
        let unseen = entries.iter().position(|entry| !entry.keywords.iter().any(|k| k == "$seen"));
        let response = select::Response {
            mailbox: item,
            total_messages: entries.len(),
            recent_messages: 0,
            unseen_seq: unseen.map_or(0, |position| position as u32 + 1),
            uid_validity,
            uid_next,
            is_rev2: self.version.is_rev2(),
            is_utf8: self.is_utf8,
            closed_previous,
            highest_modseq: self.condstore.then(|| HighestModSeq::new(modseq)),
            objectid: None,
        };
        self.write(response.serialize());
        // QRESYNC (RFC 7162, 3.2.5): what left the mailbox and what changed since the client's last state.
        if let Some(qresync) = arguments.qresync
            && qresync.uid_validity == uid_validity
        {
            let vanished = match self.inner.mail.expunged_since(id, qresync.modseq).await {
                Ok(vanished) => vanished,
                Err(error) => return mail_error(error),
            };
            let max = uid_next.saturating_sub(1);
            let vanished: Vec<u32> = vanished
                .into_iter()
                .filter(|uid| qresync.known_uids.as_ref().is_none_or(|known| known.contains(*uid, max)))
                .collect();
            let mut out = Vec::new();
            if !vanished.is_empty() {
                expunge::Vanished { earlier: true, ids: vanished }.serialize(&mut out);
            }
            for (position, entry) in entries.iter().enumerate() {
                if entry.modseq > qresync.modseq {
                    flag_update(&mut out, position + 1, entry, true, true);
                }
            }
            self.write(out);
        }
        self.selected = Some(Selected { id, owner: account, rights, read_only, entries, saved: Vec::new() });
        let code = if read_only { ResponseCode::ReadOnly } else { ResponseCode::ReadWrite };
        StatusResponse::completed(command).with_code(code)
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
        if !gone.is_empty() {
            expunge::Response { use_vanished: self.qresync, ids: gone }.serialize_to(&mut out);
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

    pub(crate) async fn fetch(&mut self, arguments: fetch::Arguments, is_uid: bool) -> StatusResponse {
        let command = Command::Fetch(is_uid);
        let Some(selected) = self.selected.clone() else { return StatusResponse::bad("No mailbox selected") };
        let account = selected.owner;
        let mut positions = selected.resolve(&arguments.sequence_set, is_uid);
        let mut attributes = arguments.attributes;
        if let Some(changed_since) = arguments.changed_since {
            self.condstore = true;
            positions.retain(|&position| selected.entries[position].modseq > changed_since);
            if arguments.include_vanished && is_uid {
                let vanished = match self.inner.mail.expunged_since(selected.id, changed_since).await {
                    Ok(vanished) => vanished,
                    Err(error) => return mail_error(error),
                };
                let max = selected.entries.last().map_or(0, |entry| entry.uid);
                let vanished: Vec<u32> =
                    vanished.into_iter().filter(|uid| in_set(&arguments.sequence_set, *uid, max, false)).collect();
                if !vanished.is_empty() {
                    let mut out = Vec::new();
                    expunge::Vanished { earlier: true, ids: vanished }.serialize(&mut out);
                    self.write(out);
                }
            }
        }
        if is_uid && !attributes.contains(&Attribute::Uid) {
            attributes.insert(0, Attribute::Uid);
        }
        if self.condstore && !attributes.contains(&Attribute::ModSeq) {
            attributes.push(Attribute::ModSeq);
        }
        let needs_message = attributes.iter().any(|attribute| {
            !matches!(
                attribute,
                Attribute::Flags
                    | Attribute::InternalDate
                    | Attribute::Rfc822Size
                    | Attribute::Uid
                    | Attribute::ModSeq
                    | Attribute::Preview { .. }
                    | Attribute::ObjectId
            )
        });
        let marks_seen = !selected.read_only
            && selected.rights.contains(Rights::SEEN)
            && attributes.iter().any(|attribute| {
                matches!(
                    attribute,
                    Attribute::BodySection { peek: false, .. }
                        | Attribute::Binary { peek: false, .. }
                        | Attribute::Rfc822
                        | Attribute::Rfc822Text
                )
            });
        let seen = kernoid_mail::Keyword::parse("$seen").expect("a keyword");
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
            let parsed = raw.as_deref().and_then(|raw| MessageParser::new().parse(raw));
            let mut items = Vec::with_capacity(attributes.len() + 1);
            for attribute in &attributes {
                let item = match (attribute, &parsed, &raw) {
                    (Attribute::Uid, _, _) => DataItem::Uid { uid: entry.uid },
                    (Attribute::Flags, _, _) => DataItem::Flags { flags: flags::flags(&entry.keywords) },
                    (Attribute::InternalDate, _, _) => DataItem::InternalDate { date: entry.received_at.timestamp() },
                    (Attribute::Rfc822Size, _, _) => DataItem::Rfc822Size { size: entry.size as usize },
                    (Attribute::ModSeq, _, _) => DataItem::ModSeq { modseq: entry.modseq },
                    (Attribute::Rfc822, _, Some(raw)) => DataItem::Rfc822 { contents: SliceRange::Single(raw) },
                    (Attribute::Rfc822Header, Some(message), Some(raw)) => DataItem::Rfc822Header {
                        contents: SliceRange::Single(&raw[..(message.parts[0].offset_body as usize).min(raw.len())]),
                    },
                    (Attribute::Rfc822Text, Some(message), Some(raw)) => DataItem::Rfc822Text {
                        contents: SliceRange::Single(
                            raw.get(message.parts[0].offset_body as usize..).unwrap_or_default(),
                        ),
                    },
                    (Attribute::Envelope, Some(message), _) => {
                        DataItem::Envelope { envelope: message::envelope(message) }
                    }
                    (Attribute::Body, Some(message), _) => {
                        DataItem::Body { part: message::body_structure(message, false) }
                    }
                    (Attribute::BodyStructure, Some(message), _) => {
                        DataItem::BodyStructure { part: message::body_structure(message, true) }
                    }
                    (Attribute::BodySection { sections, partial, .. }, Some(message), _) => DataItem::BodySection {
                        sections: sections.clone(),
                        origin_octet: partial.map(|(start, _)| start),
                        contents: message::body_section(message, sections, *partial).unwrap_or_default(),
                    },
                    (Attribute::Binary { sections, partial, .. }, Some(message), _) => {
                        match message::binary(message, sections, *partial) {
                            Ok(contents) => DataItem::Binary {
                                sections: sections.clone(),
                                offset: partial.map(|(start, _)| start),
                                contents: contents.unwrap_or(fetch::BodyContents::Bytes(Default::default())),
                            },
                            Err(()) => {
                                return StatusResponse::no("The part cannot be decoded")
                                    .with_code(ResponseCode::UnknownCte);
                            }
                        }
                    }
                    (Attribute::BinarySize { sections }, Some(message), _) => DataItem::BinarySize {
                        sections: sections.clone(),
                        size: message::binary_size(message, sections).unwrap_or(0),
                    },
                    // Not offered, or the message could not be read.
                    _ => continue,
                };
                items.push(item);
            }
            if flags_changed && !attributes.contains(&Attribute::Flags) {
                items.push(DataItem::Flags { flags: flags::flags(&entry.keywords) });
            }
            let mut out = Vec::new();
            FetchItem { id: position as u32 + 1, is_uidonly: false, items }.serialize(&mut out, self.is_utf8);
            self.write(out);
        }
        StatusResponse::completed(command)
    }

    pub(crate) async fn store(&mut self, arguments: store::Arguments, is_uid: bool) -> StatusResponse {
        let command = Command::Store(is_uid);
        let Some(selected) = self.selected.clone() else { return StatusResponse::bad("No mailbox selected") };
        let account = selected.owner;
        if selected.read_only {
            return StatusResponse::no("The mailbox is read-only").with_code(ResponseCode::ReadOnly);
        }
        if arguments.unchanged_since.is_some() {
            self.condstore = true;
        }
        // Flags the user may not change are left as they are (RFC 4314, 4).
        let may = |keyword: &str| selected.rights.contains(flags::right(keyword));
        let keywords: Vec<Keyword> =
            arguments.keywords.iter().filter_map(flags::keyword).filter(|keyword| may(keyword.as_str())).collect();
        let mut modified = Vec::new();
        let mut touched = BTreeSet::new();
        for position in selected.resolve(&arguments.sequence_set, is_uid) {
            let entry = &selected.entries[position];
            if arguments.unchanged_since.is_some_and(|since| entry.modseq > since) {
                modified.push(if is_uid { entry.uid } else { position as u32 + 1 });
                continue;
            }
            let (add, remove): (Vec<Keyword>, Vec<Keyword>) = match arguments.operation {
                Operation::Set => {
                    let removed = entry
                        .keywords
                        .iter()
                        .filter(|current| may(current) && !keywords.iter().any(|k| k.as_str() == current.as_str()))
                        .filter_map(|current| Keyword::parse(current).ok())
                        .collect();
                    (keywords.clone(), removed)
                }
                Operation::Add => (keywords.clone(), Vec::new()),
                Operation::Clear => (Vec::new(), keywords.clone()),
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
                    if !arguments.is_silent || self.condstore {
                        flag_update(&mut out, position + 1, entry, is_uid, self.condstore);
                    }
                }
            }
        }
        self.write(out);
        if modified.is_empty() {
            StatusResponse::completed(command)
        } else {
            modified.sort_unstable();
            StatusResponse::ok("Conditional STORE failed").with_code(ResponseCode::Modified { ids: modified })
        }
    }

    pub(crate) async fn copy_move(
        &mut self,
        arguments: copy_move::Arguments,
        is_uid: bool,
        is_move: bool,
    ) -> StatusResponse {
        let command = if is_move { Command::Move(is_uid) } else { Command::Copy(is_uid) };
        let Some(selected) = self.selected.clone() else { return StatusResponse::bad("No mailbox selected") };
        if is_move && (selected.read_only || !selected.rights.contains(Rights::DELETE | Rights::EXPUNGE)) {
            return StatusResponse::no("No right to remove messages here").with_code(ResponseCode::NoPerm);
        }
        let folders = match self.folders().await {
            Ok(folders) => folders,
            Err(response) => return response,
        };
        let Some(target) = folders.find(&arguments.mailbox_name) else {
            return StatusResponse::no("No such mailbox").with_code(ResponseCode::TryCreate);
        };
        if !target.rights.contains(Rights::INSERT) {
            return no_permission("add messages to that mailbox");
        }
        if is_move && target.info.id == selected.id {
            return StatusResponse::no("The message is in this mailbox already").with_code(ResponseCode::Cannot);
        }
        let positions = selected.resolve(&arguments.sequence_set, is_uid);
        if positions.is_empty() {
            return StatusResponse::completed(command);
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
                return StatusResponse::no("Some of the messages were expunged").with_code(ResponseCode::ExpungeIssued);
            }
            Err(error) => return mail_error(error),
        };
        if is_move && target.owner != selected.owner {
            let uids: BTreeSet<u32> = src_uids.iter().copied().collect();
            if let Err(error) = mail.remove_from_mailbox(selected.owner, selected.id, &uids).await {
                return mail_error(error);
            }
        }
        let code = ResponseCode::CopyUid { uid_validity: target.info.uid_validity, src_uids, dest_uids };
        if is_move {
            // RFC 6851, 4.3: COPYUID in an untagged OK before the EXPUNGEs the sync sends.
            self.write(StatusResponse::ok("Moved").with_code(code).into_bytes());
            StatusResponse::completed(command)
        } else {
            StatusResponse::completed(command).with_code(code)
        }
    }

    /// `EXPUNGE`, `UID EXPUNGE` (UIDPLUS) and the silent one of `CLOSE`: the sync reports what went.
    pub(crate) async fn expunge(&mut self, uids: Option<Sequence>, report: bool) -> StatusResponse {
        let command = Command::Expunge(uids.is_some());
        let Some(selected) = &self.selected else { return StatusResponse::bad("No mailbox selected") };
        let account = selected.owner;
        if selected.read_only || !selected.rights.contains(Rights::EXPUNGE) {
            return match report {
                false => StatusResponse::completed(command),
                true if selected.read_only => {
                    StatusResponse::no("The mailbox is read-only").with_code(ResponseCode::ReadOnly)
                }
                true => no_permission("expunge messages here"),
            };
        }
        let only: Option<BTreeSet<u32>> = uids.map(|uids| {
            selected.resolve(&uids, true).into_iter().map(|position| selected.entries[position].uid).collect()
        });
        match self.inner.mail.expunge(account, selected.id, only.as_ref()).await {
            Ok(_) => StatusResponse::completed(command),
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
