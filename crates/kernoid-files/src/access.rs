// SPDX-License-Identifier: AGPL-3.0-or-later
//! Who may do what with whose files (RFC 0005, 11): the rights of the draft's `FilesRights`, granted on directories
//! or on a whole store to accounts and groups of the tenant (`file_access`, a read model of the owner's events) and
//! inherited down the tree. The owner of a store has every right; a drive has no owner, only grants.

use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use crate::{Files, NodeInfo, Result, changes};

/// Rights on a node, as the letters stored in `file_access`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Rights(u8);

impl Rights {
    pub const NONE: Self = Self(0);
    /// `mayRead`: the node's properties and content.
    pub const READ: Self = Self(1);
    /// `mayAddChildren`.
    pub const ADD: Self = Self(2);
    /// `mayRename`: rename or move.
    pub const RENAME: Self = Self(4);
    /// `mayDelete`.
    pub const DELETE: Self = Self(8);
    /// `mayModifyContent`.
    pub const WRITE: Self = Self(16);
    /// `mayShare`.
    pub const SHARE: Self = Self(32);
    pub const ALL: Self = Self(63);

    const LETTERS: [(char, Self); 6] = [
        ('r', Self::READ),
        ('a', Self::ADD),
        ('n', Self::RENAME),
        ('d', Self::DELETE),
        ('w', Self::WRITE),
        ('s', Self::SHARE),
    ];

    /// Reads letters; unknown ones are ignored.
    pub fn parse(letters: &str) -> Self {
        Self(
            Self::LETTERS
                .iter()
                .filter(|(letter, _)| letters.contains(*letter))
                .fold(0, |all, (_, right)| all | right.0),
        )
    }

    /// The letters, in their order.
    pub fn letters(self) -> String {
        Self::LETTERS.iter().filter(|(_, right)| self.contains(*right)).map(|(letter, _)| *letter).collect()
    }

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

/// What one account may do in one store: everything if it owns it, else what the grants to it and its groups say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAccess {
    pub user: Uuid,
    pub owner: Uuid,
    pub owned: bool,
    /// Granted on the whole store.
    pub store: Rights,
    /// Granted on directories, each for what lies below it as well.
    pub nodes: HashMap<Uuid, Rights>,
}

impl FileAccess {
    /// The owner's access to its own store.
    pub fn own(account: Uuid) -> Self {
        Self { user: account, owner: account, owned: true, store: Rights::ALL, nodes: HashMap::new() }
    }

    /// Whether the user reaches anything in the store.
    pub fn any(&self) -> bool {
        self.owned || !self.store.is_empty() || self.nodes.values().any(|rights| !rights.is_empty())
    }

    /// The rights on a node given its ancestors (parent first): those on the store, the node and every ancestor.
    pub fn rights(&self, node: Uuid, ancestors: &[Uuid]) -> Rights {
        if self.owned {
            return Rights::ALL;
        }
        let mut rights = self.store;
        for id in std::iter::once(&node).chain(ancestors) {
            if let Some(granted) = self.nodes.get(id) {
                rights |= *granted;
            }
        }
        rights
    }

    /// May the user create nodes at the top of the store (`mayCreateTopLevelFileNode`)?
    pub fn may_create_top_level(&self) -> bool {
        self.owned || self.store.contains(Rights::ADD)
    }
}

/// The nodes of a store as one user sees them (RFC 0005, 11; the draft's section 5): which are discoverable, which
/// readable, and the rights on each.
#[derive(Debug, Clone)]
pub struct View {
    pub access: FileAccess,
    nodes: HashMap<Uuid, NodeInfo>,
    rights: HashMap<Uuid, Rights>,
    discoverable: HashSet<Uuid>,
}

impl View {
    pub fn new(access: FileAccess, nodes: Vec<NodeInfo>) -> Self {
        let nodes: HashMap<Uuid, NodeInfo> = nodes.into_iter().map(|node| (node.id, node)).collect();
        let ancestors = |id: Uuid| {
            let mut out = Vec::new();
            let mut next = nodes.get(&id).and_then(|node| node.parent);
            while let Some(parent) = next {
                if out.contains(&parent) || out.len() > crate::MAX_DEPTH {
                    break;
                }
                out.push(parent);
                next = nodes.get(&parent).and_then(|node| node.parent);
            }
            out
        };
        let mut rights = HashMap::new();
        let mut discoverable = HashSet::new();
        for id in nodes.keys() {
            let above = ancestors(*id);
            let granted = access.rights(*id, &above);
            rights.insert(*id, granted);
            if granted.contains(Rights::READ) {
                discoverable.insert(*id);
            }
            // A grant of any right makes the node and the way to it discoverable.
            if !access.owned && access.nodes.get(id).is_some_and(|rights| !rights.is_empty()) {
                discoverable.insert(*id);
                discoverable.extend(above);
            }
        }
        Self { access, nodes, rights, discoverable }
    }

    pub fn node(&self, id: Uuid) -> Option<&NodeInfo> {
        self.nodes.get(&id).filter(|_| self.discoverable.contains(&id))
    }

    /// The discoverable nodes.
    pub fn nodes(&self) -> impl Iterator<Item = &NodeInfo> {
        self.nodes.values().filter(|node| self.discoverable.contains(&node.id))
    }

    pub fn rights(&self, id: Uuid) -> Rights {
        self.rights.get(&id).copied().unwrap_or_default()
    }

    pub fn readable(&self, id: Uuid) -> bool {
        self.rights(id).contains(Rights::READ)
    }

    /// The ancestors of a node, its parent first.
    pub fn ancestors(&self, id: Uuid) -> Vec<Uuid> {
        let mut out = Vec::new();
        let mut next = self.nodes.get(&id).and_then(|node| node.parent);
        while let Some(parent) = next {
            if out.contains(&parent) || out.len() > crate::MAX_DEPTH {
                break;
            }
            out.push(parent);
            next = self.nodes.get(&parent).and_then(|node| node.parent);
        }
        out
    }
}

/// A store the user reaches through grants: its owner, the owner's name and whether it is a drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedStore {
    pub owner: Uuid,
    pub name: String,
    pub drive: bool,
}

impl Files {
    /// What `user` may do in `owner`'s store: its own, or the grants to it and its groups on an active account with
    /// files.
    pub async fn access(&self, user: Uuid, owner: Uuid) -> Result<FileAccess> {
        if user == owner {
            return Ok(FileAccess::own(user));
        }
        let rows = sqlx::query!(
            "SELECT f.node_id, f.rights
             FROM file_access f JOIN accounts a ON a.id = f.owner_id
             WHERE f.owner_id = $2 AND a.active
               AND EXISTS (SELECT 1 FROM account_services s WHERE s.account_id = a.id AND s.service = 'files' AND s.state = 'on')
               AND (f.grantee_account = $1
                    OR f.grantee_group IN (SELECT group_id FROM group_members WHERE account_id = $1))",
            user,
            owner,
        )
        .fetch_all(&self.pool)
        .await?;
        let mut access = FileAccess { user, owner, owned: false, store: Rights::NONE, nodes: HashMap::new() };
        for row in rows {
            let rights = Rights::parse(&row.rights);
            match row.node_id {
                Some(node) => *access.nodes.entry(node).or_default() |= rights,
                None => access.store |= rights,
            }
        }
        Ok(access)
    }

    /// The stores shared with `user`: drives and other accounts' files it holds grants on.
    pub async fn shared_with(&self, user: Uuid) -> Result<Vec<SharedStore>> {
        let rows = sqlx::query!(
            r#"SELECT DISTINCT a.id, a.display_name, coalesce(a.primary_address, a.email) AS address, a.kind
               FROM file_access f JOIN accounts a ON a.id = f.owner_id
               WHERE a.active AND a.id <> $1
                 AND EXISTS (SELECT 1 FROM account_services s WHERE s.account_id = a.id AND s.service = 'files' AND s.state = 'on')
                 AND (f.grantee_account = $1
                      OR f.grantee_group IN (SELECT group_id FROM group_members WHERE account_id = $1))
               ORDER BY a.display_name"#,
            user,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| SharedStore {
                owner: row.id,
                drive: row.kind == "drive",
                name: if row.kind == "drive" { row.display_name } else { row.address.unwrap_or(row.display_name) },
            })
            .collect())
    }

    /// The store as `access` sees it.
    pub async fn view(&self, access: FileAccess) -> Result<View> {
        let nodes = self.nodes(access.owner).await?;
        Ok(View::new(access, nodes))
    }

    /// Records a change of sharing as a change of every node it covers – a directory and all below it, or the whole
    /// store – so that `FileNode/changes` tells each user what they now see (draft, section 5).
    pub async fn touch(&self, owner: Uuid, node: Option<Uuid>) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let mut locked = self.lock_store(&mut tx, owner).await?;
        let modseq = locked.next_modseq(&mut tx).await?;
        let ids = sqlx::query_scalar!(
            r#"WITH RECURSIVE tree AS (
                   SELECT id FROM file_nodes WHERE account_id = $1 AND (id = $2 OR ($2::uuid IS NULL AND parent_id IS NULL))
                   UNION ALL
                   SELECT n.id FROM file_nodes n JOIN tree ON n.parent_id = tree.id)
               SELECT id AS "id!" FROM tree"#,
            owner,
            node,
        )
        .fetch_all(&mut *tx)
        .await?;
        for id in ids {
            changes::record(&mut tx, owner, modseq, id, changes::Change::Updated).await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_are_letters() {
        let rights = Rights::parse("wrx");
        assert_eq!(rights.letters(), "rw");
        assert!(rights.contains(Rights::READ) && !rights.contains(Rights::ADD));
        assert_eq!(Rights::ALL.letters(), "randws");
    }

    #[test]
    fn grants_are_inherited_and_make_the_way_discoverable() {
        let (owner, user) = (Uuid::now_v7(), Uuid::now_v7());
        let node = |id: Uuid, parent: Option<Uuid>, name: &str| NodeInfo::directory_for_tests(id, parent, name);
        let (top, shared, below, other) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let access = FileAccess {
            user,
            owner,
            owned: false,
            store: Rights::NONE,
            nodes: HashMap::from([(shared, Rights::READ | Rights::ADD)]),
        };
        let view = View::new(
            access,
            vec![
                node(top, None, "top"),
                node(shared, Some(top), "shared"),
                node(below, Some(shared), "below"),
                node(other, Some(top), "other"),
            ],
        );
        assert!(view.node(top).is_some() && !view.readable(top));
        assert!(view.readable(shared) && view.readable(below));
        assert!(view.rights(below).contains(Rights::ADD));
        assert!(view.node(other).is_none());
    }
}
