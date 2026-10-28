// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mailbox names: a mailbox's IMAP name is its path in the tree, `/`-separated; the inbox is `INBOX`, at the top
//! wherever JMAP put it, and its children are below it. Stores shared with the user are in the shared namespace
//! `Shared/<address of the owner>/…` (RFC 0002, 12.2), with the mailboxes the user may see.

use std::collections::HashMap;

use kernoid_mail::{Access, MailboxInfo, Rights, Role};
use uuid::Uuid;

use crate::proto::protocol::list::Attribute;

pub(crate) const SEPARATOR: char = '/';

/// The prefix of the shared namespace.
pub(crate) const SHARED: &str = "Shared";

#[derive(Debug, Clone)]
pub(crate) struct Folder {
    /// The full IMAP name.
    pub name: String,
    pub info: MailboxInfo,
    pub has_children: bool,
    /// The account whose mailbox it is.
    pub owner: Uuid,
    /// The user's rights on it.
    pub rights: Rights,
    /// `false` for a level of the shared namespace (`Shared`, `Shared/<address>`), which holds no emails.
    pub selectable: bool,
}

/// One store's mailboxes as the user sees them.
#[derive(Debug, Clone)]
pub(crate) struct Store {
    pub access: Access,
    /// The owner's primary address.
    pub address: String,
    pub mailboxes: Vec<MailboxInfo>,
}

/// The user's mailboxes and those shared with them, by name.
#[derive(Debug, Clone)]
pub(crate) struct Folders(Vec<Folder>);

/// `INBOX` in any case is the inbox; a trailing separator is ignored.
pub(crate) fn normalize(name: &str) -> String {
    let name = name.trim_end_matches(SEPARATOR);
    match name.split_once(SEPARATOR) {
        Some((first, rest)) if first.eq_ignore_ascii_case("INBOX") => format!("INBOX{SEPARATOR}{rest}"),
        None if name.eq_ignore_ascii_case("INBOX") => "INBOX".to_owned(),
        _ => name.to_owned(),
    }
}

/// The paths of a store's mailboxes, below `prefix`.
fn paths(mailboxes: &[MailboxInfo], prefix: Option<&str>) -> Vec<String> {
    let by_id: HashMap<Uuid, &MailboxInfo> = mailboxes.iter().map(|mailbox| (mailbox.id, mailbox)).collect();
    mailboxes
        .iter()
        .map(|mailbox| {
            let mut segments = Vec::new();
            let mut current = Some(mailbox);
            // A tree is at most this deep; the bound keeps a broken one from looping.
            while let Some(mailbox) = current.take()
                && segments.len() < 64
            {
                if mailbox.role == Some(Role::Inbox) {
                    segments.push("INBOX");
                    break;
                }
                segments.push(mailbox.name.as_str());
                current = mailbox.parent_id.and_then(|parent| by_id.get(&parent).copied());
            }
            segments.extend(prefix);
            segments.reverse();
            segments.join(&SEPARATOR.to_string())
        })
        .collect()
}

/// A level of the shared namespace; `rights` are those on the store as a whole (`k` creates mailboxes in it).
fn level(name: String, owner: Uuid, rights: Rights) -> Folder {
    Folder {
        name,
        info: MailboxInfo {
            id: Uuid::nil(),
            parent_id: None,
            name: String::new(),
            role: None,
            sort_order: 0,
            is_subscribed: true,
            uid_validity: 0,
            uid_next: 0,
            total_emails: 0,
            unread_emails: 0,
            total_threads: 0,
            unread_threads: 0,
        },
        has_children: true,
        owner,
        rights: rights | Rights::LOOKUP,
        selectable: false,
    }
}

impl Folders {
    pub fn new(own: Store, shared: Vec<Store>) -> Self {
        fn add(folders: &mut Vec<Folder>, store: &Store, prefix: Option<&str>) {
            let visible: Vec<&MailboxInfo> = store
                .mailboxes
                .iter()
                .filter(|mailbox| store.access.mailbox(mailbox.id).contains(Rights::LOOKUP))
                .collect();
            for (mailbox, name) in store.mailboxes.iter().zip(paths(&store.mailboxes, prefix)) {
                let rights = store.access.mailbox(mailbox.id);
                if !rights.contains(Rights::LOOKUP) {
                    continue;
                }
                folders.push(Folder {
                    name,
                    info: mailbox.clone(),
                    has_children: visible.iter().any(|child| child.parent_id == Some(mailbox.id)),
                    owner: store.access.owner,
                    rights,
                    selectable: true,
                });
            }
        }
        let mut folders = Vec::new();
        add(&mut folders, &own, None);
        if !shared.is_empty() {
            folders.push(level(SHARED.to_owned(), Uuid::nil(), Rights::NONE));
        }
        for store in &shared {
            let prefix = format!("{SHARED}{SEPARATOR}{}", store.address);
            folders.push(level(prefix.clone(), store.access.owner, store.access.store));
            add(&mut folders, store, Some(&prefix));
        }
        folders.sort_by(|a, b| {
            // The own INBOX first, then the own mailboxes, then the shared namespace.
            let rank = |folder: &Folder| {
                let own_store = folder.owner == own.access.owner;
                (!own_store, !(own_store && folder.info.role == Some(Role::Inbox)))
            };
            (rank(a), &a.name).cmp(&(rank(b), &b.name))
        });
        Self(folders)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Folder> {
        self.0.iter()
    }

    /// A mailbox by name.
    pub fn find(&self, name: &str) -> Option<&Folder> {
        self.find_any(name).filter(|folder| folder.selectable)
    }

    /// A mailbox or a level of the shared namespace, by name.
    pub fn find_any(&self, name: &str) -> Option<&Folder> {
        let name = normalize(name);
        self.0.iter().find(|folder| folder.name == name)
    }
}

/// `LIST` patterns (RFC 9051, 6.3.9): `*` matches anything, `%` anything but the separator.
pub(crate) fn matches(pattern: &str, name: &str) -> bool {
    fn go(pattern: &[char], name: &[char]) -> bool {
        match pattern.split_first() {
            None => name.is_empty(),
            Some(('*', rest)) => (0..=name.len()).any(|skip| go(rest, &name[skip..])),
            Some(('%', rest)) => (0..=name.len())
                .take_while(|&skip| !name[..skip].contains(&SEPARATOR))
                .any(|skip| go(rest, &name[skip..])),
            Some((c, rest)) => name.first() == Some(c) && go(rest, &name[1..]),
        }
    }
    let pattern = normalize_pattern(pattern);
    go(&pattern.chars().collect::<Vec<_>>(), &name.chars().collect::<Vec<_>>())
}

/// A pattern that starts with `INBOX` in any case matches the inbox.
fn normalize_pattern(pattern: &str) -> String {
    match pattern.get(..5) {
        Some(first) if first.eq_ignore_ascii_case("INBOX") => format!("INBOX{}", &pattern[5..]),
        _ => pattern.to_owned(),
    }
}

/// The special use of a role (RFC 6154).
pub(crate) fn special_use(role: Option<Role>) -> Option<Attribute> {
    Some(match role? {
        Role::Inbox => return None,
        Role::Drafts => Attribute::Drafts,
        Role::Sent => Attribute::Sent,
        Role::Archive => Attribute::Archive,
        Role::Junk => Attribute::Junk,
        Role::Trash => Attribute::Trash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mailbox(id: u128, parent: Option<u128>, name: &str, role: Option<Role>) -> MailboxInfo {
        MailboxInfo {
            id: Uuid::from_u128(id),
            parent_id: parent.map(Uuid::from_u128),
            name: name.into(),
            role,
            sort_order: 0,
            is_subscribed: true,
            uid_validity: 1,
            uid_next: 1,
            total_emails: 0,
            unread_emails: 0,
            total_threads: 0,
            unread_threads: 0,
        }
    }

    #[test]
    fn names_are_paths() {
        let alice = Uuid::from_u128(100);
        let own = Store {
            access: Access::own(alice),
            address: "alice@firma.example".into(),
            mailboxes: vec![
                mailbox(1, None, "Inbox", Some(Role::Inbox)),
                mailbox(2, Some(1), "Lists", None),
                mailbox(3, None, "Work", None),
                mailbox(4, Some(3), "2026", None),
            ],
        };
        let mut access = Access::own(Uuid::from_u128(200));
        access.owned = false;
        access.user = alice;
        access.store = Rights::NONE;
        access.mailboxes = HashMap::from([(Uuid::from_u128(5), Rights::parse("lr"))]);
        let info = Store {
            access,
            address: "info@firma.example".into(),
            mailboxes: vec![mailbox(5, None, "Inbox", Some(Role::Inbox)), mailbox(6, None, "Hidden", None)],
        };
        let folders = Folders::new(own, vec![info]);
        let names: Vec<_> = folders.iter().map(|folder| folder.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "INBOX",
                "INBOX/Lists",
                "Work",
                "Work/2026",
                "Shared",
                "Shared/info@firma.example",
                "Shared/info@firma.example/INBOX"
            ]
        );
        assert_eq!(folders.find("inbox/Lists/").unwrap().info.id, Uuid::from_u128(2));
        assert!(folders.find("Work").unwrap().has_children);
        assert!(folders.find("work").is_none());
        let shared = folders.find("Shared/info@firma.example/INBOX").unwrap();
        assert_eq!((shared.owner, shared.rights.letters()), (Uuid::from_u128(200), "lr".to_owned()));
        assert!(folders.find("Shared/info@firma.example").is_none());
        assert!(!folders.find_any("Shared/info@firma.example").unwrap().selectable);
    }

    #[test]
    fn patterns() {
        assert!(matches("*", "Work/2026"));
        assert!(!matches("%", "Work/2026"));
        assert!(matches("%", "Work"));
        assert!(matches("Work/%", "Work/2026"));
        assert!(matches("inbox", "INBOX"));
        assert!(matches("W*6", "Work/2026"));
        assert!(!matches("Work", "Work/2026"));
    }
}
