// SPDX-License-Identifier: AGPL-3.0-or-later
//! Who may use whose mail (RFC 0002, 12.2): the grants in `mail_access` – administration, written by
//! `kernoid-identity` – resolved into a user's rights on another account's mailboxes. The protocols check them.

use std::collections::HashMap;

use uuid::Uuid;

use crate::{Mail, Result};

/// IMAP ACL rights (RFC 4314) as a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Rights(u16);

const LETTERS: &str = "lrswipkxtea";

impl Rights {
    pub const NONE: Self = Self(0);
    pub const LOOKUP: Self = Self(1);
    pub const READ: Self = Self(1 << 1);
    pub const SEEN: Self = Self(1 << 2);
    pub const WRITE: Self = Self(1 << 3);
    pub const INSERT: Self = Self(1 << 4);
    pub const POST: Self = Self(1 << 5);
    pub const CREATE: Self = Self(1 << 6);
    pub const DELETE_MAILBOX: Self = Self(1 << 7);
    pub const DELETE: Self = Self(1 << 8);
    pub const EXPUNGE: Self = Self(1 << 9);
    pub const ADMIN: Self = Self(1 << 10);
    pub const ALL: Self = Self((1 << 11) - 1);

    /// From letters; unknown ones are ignored.
    pub fn parse(letters: &str) -> Self {
        Self(
            LETTERS
                .chars()
                .enumerate()
                .filter(|(_, letter)| letters.contains(*letter))
                .fold(0, |bits, (position, _)| bits | 1 << position),
        )
    }

    pub fn letters(self) -> String {
        LETTERS.chars().enumerate().filter(|(position, _)| self.0 & (1 << position) != 0).map(|(_, c)| c).collect()
    }

    /// Whether every right of `other` is in `self`.
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for Rights {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl std::ops::BitOrAssign for Rights {
    fn bitor_assign(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

/// A user's access to one account's mail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    pub user: Uuid,
    pub owner: Uuid,
    /// The user's own store: every right.
    pub owned: bool,
    /// Rights on every mailbox of the store.
    pub store: Rights,
    /// Further rights on single mailboxes.
    pub mailboxes: HashMap<Uuid, Rights>,
    /// May send from the owner's addresses.
    pub send_as: bool,
}

impl Access {
    pub fn own(account: Uuid) -> Self {
        Self {
            user: account,
            owner: account,
            owned: true,
            store: Rights::ALL,
            mailboxes: HashMap::new(),
            send_as: true,
        }
    }

    /// The user's rights on a mailbox of the store.
    pub fn mailbox(&self, mailbox: Uuid) -> Rights {
        if self.owned {
            return Rights::ALL;
        }
        self.store | self.mailboxes.get(&mailbox).copied().unwrap_or_default()
    }

    /// Whether the user may use the store at all.
    pub fn any(&self) -> bool {
        self.owned || self.send_as || !self.store.is_empty() || self.mailboxes.values().any(|rights| !rights.is_empty())
    }

    /// Whether some right allows a change (JMAP `isReadOnly` is the opposite).
    pub fn may_change(&self) -> bool {
        let reading = Rights::LOOKUP | Rights::READ;
        self.owned
            || std::iter::once(self.store)
                .chain(self.mailboxes.values().copied())
                .any(|rights| Rights(rights.0 & !reading.0) != Rights::NONE)
    }
}

/// A store a user may use besides its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedStore {
    pub owner: Uuid,
    pub address: String,
    pub display_name: String,
}

impl Mail {
    /// What `user` may do with `owner`'s mail: everything if it is its own; otherwise what the grants to it and its
    /// groups say, while the owner is active.
    pub async fn access(&self, user: Uuid, owner: Uuid) -> Result<Access> {
        if user == owner {
            return Ok(Access::own(user));
        }
        let rows = sqlx::query!(
            "SELECT m.mailbox_id, m.rights, m.send_as
             FROM mail_access m JOIN accounts a ON a.id = m.owner_id
             WHERE m.owner_id = $2 AND a.active
               AND EXISTS (SELECT 1 FROM account_services s WHERE s.account_id = a.id AND s.service = 'mail' AND s.state = 'on')
               AND (m.grantee_account = $1
                    OR m.grantee_group IN (SELECT group_id FROM group_members WHERE account_id = $1))",
            user,
            owner,
        )
        .fetch_all(&self.pool)
        .await?;
        let mut access =
            Access { user, owner, owned: false, store: Rights::NONE, mailboxes: HashMap::new(), send_as: false };
        for row in rows {
            let rights = Rights::parse(&row.rights);
            match row.mailbox_id {
                Some(mailbox) => *access.mailboxes.entry(mailbox).or_default() |= rights,
                None => {
                    access.store |= rights;
                    access.send_as |= row.send_as;
                }
            }
        }
        Ok(access)
    }

    /// The stores shared with `user`: granted to it or one of its groups, owners active, in the same tenant.
    pub async fn shared_with(&self, user: Uuid) -> Result<Vec<SharedStore>> {
        let rows = sqlx::query!(
            r#"SELECT DISTINCT a.id, a.primary_address AS "primary_address!", a.display_name
               FROM mail_access m JOIN accounts a ON a.id = m.owner_id
               WHERE a.active AND a.id <> $1 AND a.primary_address IS NOT NULL
                 AND EXISTS (SELECT 1 FROM account_services s WHERE s.account_id = a.id AND s.service = 'mail' AND s.state = 'on')
                 AND (m.grantee_account = $1
                      OR m.grantee_group IN (SELECT group_id FROM group_members WHERE account_id = $1))
               ORDER BY a.primary_address"#,
            user,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| SharedStore { owner: row.id, address: row.primary_address, display_name: row.display_name })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_are_letters() {
        let rights = Rights::parse("rl ae");
        assert_eq!(rights.letters(), "lrea");
        assert!(rights.contains(Rights::LOOKUP | Rights::READ));
        assert!(!rights.contains(Rights::INSERT));
        assert_eq!(Rights::ALL.letters(), "lrswipkxtea");
        let owner = Uuid::from_u128(1);
        let mut access = Access {
            user: Uuid::from_u128(2),
            owner,
            owned: false,
            store: Rights::parse("lr"),
            mailboxes: HashMap::from([(Uuid::from_u128(3), Rights::parse("i"))]),
            send_as: false,
        };
        assert_eq!(access.mailbox(Uuid::from_u128(3)).letters(), "lri");
        assert!(access.may_change());
        access.mailboxes.clear();
        assert!(access.any() && !access.may_change());
        assert_eq!(Access::own(owner).mailbox(Uuid::from_u128(9)), Rights::ALL);
    }
}
