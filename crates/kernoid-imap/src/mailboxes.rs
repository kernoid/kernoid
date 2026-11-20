// SPDX-License-Identifier: AGPL-3.0-or-later
//! The commands of the authenticated state that work on mailboxes by name: `LIST` (with LIST-EXTENDED, LIST-STATUS
//! and SPECIAL-USE), `LSUB`, `STATUS`, `CREATE`, `DELETE`, `RENAME`, `SUBSCRIBE`, `UNSUBSCRIBE` and `APPEND` – in the
//! user's own store and in those shared with them, with the rights of RFC 0002, 12.2.

use bytes::Bytes;
use kernoid_mail::{Access, MailboxUpdate, NewEmail, NewMailbox, Rights, Role};
use uuid::Uuid;

use crate::{
    flags,
    folders::{self, Folder, Folders, SEPARATOR, Store},
    proto::{
        request::{AppendMessage, List, StatusItem},
        response::{self, Code, Status},
    },
    session::{Session, mail_error},
};

pub(crate) fn no_permission(what: &str) -> Status {
    Status::no(format!("No right to {what}")).with_code(Code::NoPerm)
}

/// `* LIST (attributes) "/" name`, or `* LSUB …`.
pub(crate) fn list_line(out: &mut Vec<u8>, verb: &str, attributes: &[&str], name: &str, utf8: bool) {
    out.extend_from_slice(format!("* {verb} ({}) \"{SEPARATOR}\" ", attributes.join(" ")).as_bytes());
    response::mailbox(out, name, utf8);
    out.extend_from_slice(b"\r\n");
}

impl Session {
    pub(crate) fn account(&self) -> Uuid {
        self.account.expect("only after logging in")
    }

    /// The user's mailboxes and those shared with them.
    #[allow(clippy::result_large_err, reason = "the error is the response, sent once")]
    pub(crate) async fn folders(&mut self) -> Result<Folders, Status> {
        let account = self.account();
        let mail = &self.inner.mail;
        let own = Store {
            access: Access::own(account),
            address: String::new(),
            mailboxes: mail.mailboxes(account).await.map_err(mail_error)?,
        };
        let mut shared = Vec::new();
        for store in mail.shared_with(account).await.map_err(mail_error)? {
            let access = mail.access(account, store.owner).await.map_err(mail_error)?;
            if !access.any() {
                continue;
            }
            mail.ensure_account(store.owner).await.map_err(mail_error)?;
            let mailboxes = mail.mailboxes(store.owner).await.map_err(mail_error)?;
            shared.push(Store { access, address: store.address, mailboxes });
        }
        Ok(Folders::new(own, shared))
    }

    /// Whether the user subscribed to a folder: their own choice for their own mailboxes; others' are always listed.
    fn subscribed(&self, folder: &Folder) -> bool {
        folder.owner != self.account() || folder.info.is_subscribed
    }

    /// The special use of a folder (RFC 6154) – for the user's own only: a client must not take a shared `Sent`
    /// for its own.
    pub(crate) fn special_use(&self, folder: &Folder) -> Option<&'static str> {
        if folder.owner == self.account() { folders::special_use(folder.info.role) } else { None }
    }

    pub(crate) async fn list(&mut self, list: List) -> Status {
        // `LIST "" ""` asks for the separator.
        if list.patterns.iter().all(String::is_empty) {
            self.write(b"* LIST (\\Noselect) \"/\" \"\"\r\n");
            return Status::done();
        }
        self.list_folders(list, false).await
    }

    pub(crate) async fn lsub(&mut self, reference: &str, pattern: &str) -> Status {
        let list = List { reference: reference.to_owned(), patterns: vec![pattern.to_owned()], ..List::default() };
        self.list_folders(list, true).await
    }

    async fn list_folders(&mut self, list: List, is_lsub: bool) -> Status {
        let folders = match self.folders().await {
            Ok(folders) => folders,
            Err(response) => return response,
        };
        let subscribed_only = is_lsub || list.subscribed_only;
        let show_subscribed = subscribed_only || list.return_subscribed;
        let reference = &list.reference;
        let patterns: Vec<String> = list.patterns.iter().map(|pattern| format!("{reference}{pattern}")).collect();
        let mut out = Vec::new();
        for folder in folders.iter() {
            if !patterns.iter().any(|pattern| folders::matches(pattern, &folder.name))
                || (subscribed_only && !self.subscribed(folder))
                || (list.special_use_only && self.special_use(folder).is_none())
            {
                continue;
            }
            let mut attributes = Vec::new();
            if !folder.selectable {
                attributes.push("\\NoSelect");
            }
            attributes.push(if folder.has_children { "\\HasChildren" } else { "\\HasNoChildren" });
            attributes.extend(self.special_use(folder));
            if show_subscribed && self.subscribed(folder) {
                attributes.push("\\Subscribed");
            }
            list_line(&mut out, if is_lsub { "LSUB" } else { "LIST" }, &attributes, &folder.name, self.utf8);
            if let Some(items) = &list.return_status
                && folder.selectable
                && folder.rights.contains(Rights::READ)
            {
                match self.status_line(folder, items).await {
                    Ok(line) => out.extend_from_slice(&line),
                    Err(response) => return response,
                }
            }
        }
        self.write(out);
        Status::done()
    }

    /// `* STATUS name (…)` of a folder.
    #[allow(clippy::result_large_err, reason = "the error is the response, sent once")]
    async fn status_line(&mut self, folder: &Folder, items: &[StatusItem]) -> Result<Vec<u8>, Status> {
        let owner = folder.owner;
        let entries =
            if items.iter().any(|item| matches!(item, StatusItem::Unseen | StatusItem::Deleted | StatusItem::Size)) {
                self.inner.mail.mailbox_entries(owner, folder.info.id).await.map_err(mail_error)?
            } else {
                Vec::new()
            };
        let has = |entry: &kernoid_mail::MailboxEntry, keyword: &str| entry.keywords.iter().any(|k| k == keyword);
        let mut values = Vec::new();
        for item in items {
            let value = match item {
                StatusItem::Messages => folder.info.total_emails,
                StatusItem::UidNext => u64::from(folder.info.uid_next),
                StatusItem::UidValidity => u64::from(folder.info.uid_validity),
                StatusItem::Unseen => entries.iter().filter(|entry| !has(entry, "$seen")).count() as u64,
                StatusItem::Deleted => entries.iter().filter(|entry| has(entry, "$deleted")).count() as u64,
                StatusItem::Size => entries.iter().map(|entry| entry.size).sum(),
                StatusItem::Recent => 0,
                StatusItem::HighestModSeq => self.inner.mail.state(owner).await.map_err(mail_error)?,
                // Not offered.
                StatusItem::DeletedStorage => continue,
            };
            values.push(format!("{} {value}", item.name()));
        }
        let mut out = b"* STATUS ".to_vec();
        response::mailbox(&mut out, &folder.name, self.utf8);
        out.extend_from_slice(format!(" ({})\r\n", values.join(" ")).as_bytes());
        Ok(out)
    }

    pub(crate) async fn status(&mut self, mailbox: &str, items: &[StatusItem]) -> Status {
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
        match self.status_line(folder, items).await {
            Ok(line) => {
                self.write(line);
                Status::done()
            }
            Err(response) => response,
        }
    }

    /// Creates a mailbox and the parents it lacks (RFC 9051, 6.3.4), in the store the name leads to.
    pub(crate) async fn create(&mut self, name: &str) -> Status {
        let name = folders::normalize(name);
        if name.is_empty() {
            return Status::no("A mailbox needs a name").with_code(Code::Cannot);
        }
        let folders = match self.folders().await {
            Ok(folders) => folders,
            Err(response) => return response,
        };
        if folders.find_any(&name).is_some() {
            return Status::no("The mailbox exists already").with_code(Code::AlreadyExists);
        }
        let account = self.account();
        // Where the next mailbox goes: the store, the parent in it, and the rights there.
        let (mut owner, mut parent, mut rights) = (account, None, Rights::ALL);
        let mut path = String::new();
        for segment in name.split(SEPARATOR) {
            if !path.is_empty() {
                path.push(SEPARATOR);
            }
            path.push_str(segment);
            if let Some(folder) = folders.find_any(&path) {
                owner = folder.owner;
                parent = folder.selectable.then_some(folder.info.id);
                rights = folder.rights;
                continue;
            }
            if owner.is_nil() || !rights.contains(Rights::CREATE) {
                return no_permission("create mailboxes here");
            }
            let new = NewMailbox {
                parent_id: parent,
                name: segment.to_owned(),
                is_subscribed: owner == account,
                ..NewMailbox::default()
            };
            match self.inner.mail.create_mailbox(owner, new).await {
                Ok(id) => parent = Some(id),
                Err(error) => return mail_error(error),
            }
        }
        Status::done()
    }

    /// Deletes a mailbox and its emails; one with children or the inbox stays (RFC 9051, 6.3.5).
    pub(crate) async fn delete(&mut self, name: &str) -> Status {
        let folders = match self.folders().await {
            Ok(folders) => folders,
            Err(response) => return response,
        };
        let Some(folder) = folders.find(name) else {
            return Status::no("No such mailbox").with_code(Code::NonExistent);
        };
        if folder.info.role == Some(Role::Inbox) {
            return Status::no("The inbox cannot be deleted").with_code(Code::Cannot);
        }
        if !folder.rights.contains(Rights::DELETE_MAILBOX) {
            return no_permission("delete this mailbox");
        }
        let id = folder.info.id;
        if let Err(error) = self.inner.mail.destroy_mailbox(folder.owner, id, true).await {
            return mail_error(error);
        }
        if self.selected.as_ref().is_some_and(|selected| selected.id == id) {
            self.selected = None;
        }
        Status::done()
    }

    /// Renames a mailbox, moving it in the tree of its store; its children go with it (RFC 9051, 6.3.6).
    pub(crate) async fn rename(&mut self, from: &str, to: &str) -> Status {
        let to = folders::normalize(to);
        let folders = match self.folders().await {
            Ok(folders) => folders,
            Err(response) => return response,
        };
        let Some(folder) = folders.find(from) else {
            return Status::no("No such mailbox").with_code(Code::NonExistent);
        };
        if folder.info.role == Some(Role::Inbox) {
            // OPEN (RFC 0002, 11.2): renaming INBOX moves its messages into a new mailbox.
            return Status::no("Renaming INBOX is not supported").with_code(Code::Cannot);
        }
        if !folder.rights.contains(Rights::DELETE_MAILBOX) {
            return no_permission("rename this mailbox");
        }
        if folders.find_any(&to).is_some() {
            return Status::no("The new name exists already").with_code(Code::AlreadyExists);
        }
        let (id, owner, name) = (folder.info.id, folder.owner, folder.name.clone());
        let (parent_name, leaf) = match to.rsplit_once(SEPARATOR) {
            Some((parent, leaf)) => (Some(parent.to_owned()), leaf.to_owned()),
            None => (None, to.clone()),
        };
        let parent = match parent_name {
            Some(parent_name) => {
                if parent_name == name || parent_name.starts_with(&format!("{name}{SEPARATOR}")) {
                    return Status::no("A mailbox cannot move below itself").with_code(Code::Cannot);
                }
                if folders.find_any(&parent_name).is_none() {
                    let created = self.create(&parent_name).await;
                    if !created.is_ok() {
                        return created;
                    }
                }
                let folders = match self.folders().await {
                    Ok(folders) => folders,
                    Err(response) => return response,
                };
                match folders.find_any(&parent_name) {
                    Some(parent) if parent.owner == owner && parent.rights.contains(Rights::CREATE) => {
                        parent.selectable.then_some(parent.info.id)
                    }
                    _ => return no_permission("move the mailbox there"),
                }
            }
            // The top of the user's own store.
            None if owner == self.account() => None,
            None => return no_permission("move the mailbox into another store"),
        };
        let update = MailboxUpdate { name: Some(leaf), parent_id: Some(parent), ..MailboxUpdate::default() };
        match self.inner.mail.update_mailbox(owner, id, update).await {
            Ok(()) => Status::done(),
            Err(error) => mail_error(error),
        }
    }

    pub(crate) async fn subscribe(&mut self, name: &str, subscribe: bool) -> Status {
        let folders = match self.folders().await {
            Ok(folders) => folders,
            Err(response) => return response,
        };
        let Some(folder) = folders.find(name) else {
            return Status::no("No such mailbox").with_code(Code::NonExistent);
        };
        // A subscription is the owner's; others' mailboxes are always listed (OPEN: per-user subscriptions).
        if folder.owner != self.account() {
            return Status::done();
        }
        let update = MailboxUpdate { is_subscribed: Some(subscribe), ..MailboxUpdate::default() };
        match self.inner.mail.update_mailbox(folder.owner, folder.info.id, update).await {
            Ok(()) => Status::done(),
            Err(error) => mail_error(error),
        }
    }

    /// Stores messages in a mailbox (RFC 9051, 6.3.12; MULTIAPPEND, RFC 3502); answers with their UIDs (UIDPLUS).
    pub(crate) async fn append(&mut self, mailbox: &str, messages: Vec<AppendMessage>) -> Status {
        let folders = match self.folders().await {
            Ok(folders) => folders,
            Err(response) => return response,
        };
        let Some(folder) = folders.find(mailbox) else {
            return Status::no("No such mailbox").with_code(Code::TryCreate);
        };
        if !folder.rights.contains(Rights::INSERT) {
            return no_permission("add messages to this mailbox");
        }
        let (mailbox, uid_validity, owner, rights) =
            (folder.info.id, folder.info.uid_validity, folder.owner, folder.rights);
        let mut uids = Vec::with_capacity(messages.len());
        for message in messages {
            let new = NewEmail {
                mailbox_ids: vec![mailbox],
                // Flags the user may not set are dropped (RFC 4314, 4).
                keywords: message
                    .flags
                    .iter()
                    .filter_map(|flag| flags::keyword(flag))
                    .filter(|keyword| rights.contains(flags::right(keyword.as_str())))
                    .collect(),
                received_at: message.date.and_then(|at| jiff::Timestamp::from_second(at).ok()),
            };
            let raw = Bytes::from(message.data);
            if let Err(error) = self.inner.mail.scan_message(&[owner], &[], &raw).await {
                return mail_error(error);
            }
            let imported = match self.inner.mail.import_email(owner, raw, new).await {
                Ok(imported) => imported,
                Err(error) => return mail_error(error),
            };
            match self.inner.mail.email(owner, imported.id).await {
                Ok(email) => uids.extend(email.mailboxes.iter().find(|(id, _)| *id == mailbox).map(|(_, uid)| *uid)),
                Err(error) => return mail_error(error),
            }
        }
        Status::done().with_code(Code::AppendUid { uid_validity, uids })
    }
}
