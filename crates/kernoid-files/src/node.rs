// SPDX-License-Identifier: AGPL-3.0-or-later
//! Directories and files (RFC 0005, 3–6): creating, changing, moving and destroying them, with names unique among
//! siblings, a limited depth, the content in object storage, its versions, and the rights of whoever acts (11).

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    FileAccess, Files, FilesError, Locked, Result, Rights,
    changes::{Change, record},
    content::{self, Content, ContentInfo, Readable, Released},
};

/// Most levels of the tree (`maxFileNodeDepth`): a top-level node is at depth 0, the deepest at 63.
pub const MAX_DEPTH: usize = 64;
/// Longest name, in bytes of UTF-8 (`maxSizeFileNodeName`).
pub const MAX_NAME: usize = 255;
/// Most nodes one destroy removes (RFC 0005, 7).
pub const MAX_DESTROY: usize = 10_000;
/// Characters no name may hold (`forbiddenNameChars`), besides control characters.
pub const FORBIDDEN_CHARS: &str = "/<>:\"\\|?*";
/// What a file's media type is when nobody said.
const DEFAULT_MEDIA_TYPE: &str = "application/octet-stream";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Directory,
    File,
}

impl NodeType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::File => "file",
        }
    }

    fn parse(value: &str) -> Self {
        if value == "file" { Self::File } else { Self::Directory }
    }
}

/// The role of a directory (the draft's registry); kernoid creates and knows only the trash for now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Trash,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trash => "trash",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        (value == "trash").then_some(Self::Trash)
    }
}

/// A node as it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    pub id: Uuid,
    pub parent: Option<Uuid>,
    pub node_type: NodeType,
    pub name: String,
    pub role: Option<Role>,
    /// Files: the id of the object with the content (the blob `f-<id>` in JMAP), its size and type, the flag.
    pub content: Option<Uuid>,
    pub size: Option<u64>,
    pub media_type: Option<String>,
    pub executable: Option<bool>,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub accessed: DateTime<Utc>,
    pub changed: DateTime<Utc>,
    pub is_subscribed: bool,
}

impl NodeInfo {
    #[cfg(test)]
    pub(crate) fn directory_for_tests(id: Uuid, parent: Option<Uuid>, name: &str) -> Self {
        let now = Utc::now();
        Self {
            id,
            parent,
            node_type: NodeType::Directory,
            name: name.into(),
            role: None,
            content: None,
            size: None,
            media_type: None,
            executable: None,
            created: now,
            modified: now,
            accessed: now,
            changed: now,
            is_subscribed: true,
        }
    }
}

/// A node to create. A file needs its content, stored already (empty for an empty file); times not given are now.
#[derive(Debug, Clone)]
pub struct NewNode {
    pub parent: Option<Uuid>,
    pub node_type: NodeType,
    pub name: String,
    pub content: Option<Content>,
    pub media_type: Option<String>,
    pub executable: bool,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    pub is_subscribed: bool,
}

impl NewNode {
    pub fn directory(parent: Option<Uuid>, name: impl Into<String>) -> Self {
        Self {
            parent,
            node_type: NodeType::Directory,
            name: name.into(),
            content: None,
            media_type: None,
            executable: false,
            created: None,
            modified: None,
            accessed: None,
            is_subscribed: true,
        }
    }

    pub fn file(parent: Option<Uuid>, name: impl Into<String>, content: Content, media_type: Option<String>) -> Self {
        Self { node_type: NodeType::File, content: Some(content), media_type, ..Self::directory(parent, name) }
    }
}

/// What changes in a node; `None` leaves a property as it is. `parent: Some(None)` moves it to the top.
#[derive(Debug, Clone, Default)]
pub struct NodeUpdate {
    pub parent: Option<Option<Uuid>>,
    pub name: Option<String>,
    pub content: Option<Content>,
    pub media_type: Option<String>,
    pub executable: Option<bool>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    pub is_subscribed: Option<bool>,
}

/// What happens when a name is taken among the siblings (JMAP `onExists`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnExists {
    /// Refused (`alreadyExists`).
    #[default]
    Refuse,
    /// The node holding the name is destroyed.
    Replace,
    /// The new name gets a number: `report (2).pdf`.
    Rename,
}

/// How a create, update or destroy treats names and children (the extra arguments of `FileNode/set`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SetOptions {
    pub on_exists: OnExists,
    /// Names that differ only in case count as the same (`compareCaseInsensitively`).
    pub case_insensitive: bool,
    /// Destroying a directory destroys what it holds (`onDestroyRemoveChildren`).
    pub remove_children: bool,
}

/// A node created or changed, and the nodes destroyed on the way (`onExists: replace`).
#[derive(Debug, Clone)]
pub struct Written {
    pub node: NodeInfo,
    pub destroyed: Vec<Uuid>,
}

/// Checks a name (RFC 0005, 3): 1–255 bytes, none of [`FORBIDDEN_CHARS`] or control characters, not `.` or `..`.
pub fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_NAME {
        return Err(FilesError::Invalid(format!("a name has 1 to {MAX_NAME} bytes")));
    }
    if name == "." || name == ".." {
        return Err(FilesError::Invalid(format!("{name} is not a name")));
    }
    if name.chars().any(|c| c.is_control() || FORBIDDEN_CHARS.contains(c)) {
        return Err(FilesError::Invalid(format!("a name holds none of {FORBIDDEN_CHARS} and no control characters")));
    }
    Ok(())
}

/// Checks a media type – `type/subtype` as RFC 6838 (4.2) names them, without parameters – and gives it in lower case.
pub fn check_media_type(value: &str) -> Result<String> {
    let name = |part: &str| {
        let mut chars = part.chars();
        part.len() <= 127
            && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
            && chars.all(|c| c.is_ascii_alphanumeric() || "!#$&-^_.+".contains(c))
    };
    match value.split_once('/') {
        Some((kind, subtype)) if name(kind) && name(subtype) => Ok(value.to_ascii_lowercase()),
        _ => Err(FilesError::Invalid(format!("{value:?} is not a media type"))),
    }
}

/// `name` with a number before its extension: `report.pdf` → `report (2).pdf`, cut to fit [`MAX_NAME`].
fn numbered(name: &str, number: u32) -> String {
    let (stem, extension) = match name.rfind('.') {
        Some(dot) if dot > 0 => name.split_at(dot),
        _ => (name, ""),
    };
    let suffix = format!(" ({number}){extension}");
    let mut stem = stem.to_owned();
    while stem.len() + suffix.len() > MAX_NAME && stem.pop().is_some() {}
    format!("{stem}{suffix}")
}

/// Builds a [`NodeInfo`] from a row of the select list every read of nodes uses.
macro_rules! node_info {
    ($row:expr) => {{
        let row = $row;
        NodeInfo {
            id: row.id,
            parent: row.parent_id,
            node_type: NodeType::parse(&row.node_type),
            name: row.name,
            role: row.role.as_deref().and_then(Role::parse),
            content: row.content_id,
            size: row.size.map(|size| size as u64),
            media_type: row.media_type,
            executable: row.executable,
            created: row.created,
            modified: row.modified,
            accessed: row.accessed,
            changed: row.changed,
            is_subscribed: row.is_subscribed,
        }
    }};
}

/// The nodes of `account` among `ids`.
async fn load(connection: &mut PgConnection, account: Uuid, ids: &[Uuid]) -> Result<Vec<NodeInfo>> {
    let rows = sqlx::query!(
        "SELECT id, parent_id, node_type, name, role, content_id, size, media_type, executable,
                created, modified, accessed, changed, is_subscribed
         FROM file_nodes WHERE account_id = $1 AND id = ANY($2) ORDER BY id",
        account,
        ids,
    )
    .fetch_all(connection)
    .await?;
    Ok(rows.into_iter().map(|row| node_info!(row)).collect())
}

async fn load_one(connection: &mut PgConnection, account: Uuid, id: Uuid) -> Result<NodeInfo> {
    load(connection, account, &[id]).await?.pop().ok_or(FilesError::NotFound("the node"))
}

/// The ancestors of a node, its parent first.
async fn ancestors(connection: &mut PgConnection, id: Uuid) -> Result<Vec<Uuid>> {
    Ok(sqlx::query_scalar!(
        r#"WITH RECURSIVE up AS (
               SELECT parent_id AS id, 1 AS depth FROM file_nodes WHERE id = $1 AND parent_id IS NOT NULL
               UNION ALL
               SELECT n.parent_id, up.depth + 1 FROM file_nodes n JOIN up ON n.id = up.id
               WHERE n.parent_id IS NOT NULL AND up.depth < $2)
           SELECT id AS "id!" FROM up ORDER BY depth"#,
        id,
        MAX_DEPTH as i32,
    )
    .fetch_all(connection)
    .await?)
}

/// What `access` may do with a node of its store.
async fn rights_of(connection: &mut PgConnection, access: &FileAccess, id: Uuid) -> Result<Rights> {
    if access.owned {
        return Ok(Rights::ALL);
    }
    Ok(access.rights(id, &ancestors(connection, id).await?))
}

/// Loads a node `access` may act on, needing `wanted`: a node without any right is unknown (it does not show), one
/// without the right wanted is refused.
async fn acting_on(connection: &mut PgConnection, access: &FileAccess, id: Uuid, wanted: Rights) -> Result<NodeInfo> {
    let node = load_one(connection, access.owner, id).await?;
    let rights = rights_of(connection, access, id).await?;
    if rights.is_empty() && !access.nodes.contains_key(&id) {
        return Err(FilesError::NotFound("the node"));
    }
    if !rights.contains(wanted) {
        return Err(FilesError::Forbidden("not allowed".into()));
    }
    Ok(node)
}

/// How many levels lie below a node: 0 for a file or an empty directory.
async fn height(connection: &mut PgConnection, id: Uuid) -> Result<usize> {
    let height = sqlx::query_scalar!(
        r#"WITH RECURSIVE down AS (
               SELECT id, 0 AS height FROM file_nodes WHERE id = $1
               UNION ALL
               SELECT n.id, down.height + 1 FROM file_nodes n JOIN down ON n.parent_id = down.id
               WHERE down.height < $2)
           SELECT max(height) AS "height!" FROM down"#,
        id,
        MAX_DEPTH as i32,
    )
    .fetch_one(connection)
    .await?;
    Ok(height as usize)
}

/// The sibling under `parent` called `name` (or so in another case), other than `own`.
async fn sibling(
    connection: &mut PgConnection,
    account: Uuid,
    parent: Option<Uuid>,
    name: &str,
    own: Option<Uuid>,
    case_insensitive: bool,
) -> Result<Option<Uuid>> {
    Ok(sqlx::query_scalar!(
        "SELECT id FROM file_nodes
         WHERE account_id = $1 AND parent_id IS NOT DISTINCT FROM $2
           AND (name = $3 OR ($5 AND lower(name) = lower($3)))
           AND id IS DISTINCT FROM $4
         ORDER BY name = $3 DESC LIMIT 1",
        account,
        parent,
        name,
        own,
        case_insensitive,
    )
    .fetch_optional(connection)
    .await?)
}

/// Checks that `access` may put a subtree `height` levels high into `parent` (a directory of the store) or at the
/// top.
async fn check_parent(
    connection: &mut PgConnection,
    access: &FileAccess,
    parent: Option<Uuid>,
    height: usize,
) -> Result<()> {
    let Some(parent) = parent else {
        if !access.may_create_top_level() {
            return Err(FilesError::Forbidden("nothing may be put at the top of this store".into()));
        }
        return if height < MAX_DEPTH { Ok(()) } else { Err(too_deep()) };
    };
    let node = load(connection, access.owner, &[parent]).await?.pop().ok_or(FilesError::NotFound("the parent"))?;
    if node.node_type != NodeType::Directory {
        return Err(FilesError::Invalid("the parent is not a directory".into()));
    }
    let above = ancestors(connection, parent).await?;
    if !access.rights(parent, &above).contains(Rights::ADD) {
        return Err(FilesError::Forbidden("nothing may be added to this directory".into()));
    }
    if above.len() + 1 + height >= MAX_DEPTH {
        return Err(too_deep());
    }
    Ok(())
}

fn too_deep() -> FilesError {
    FilesError::Invalid(format!("the tree is at most {MAX_DEPTH} levels deep"))
}

/// Creates the default directories of a new store (RFC 0005, 4); a drive has none.
pub(crate) async fn create_defaults(tx: &mut Transaction<'static, Postgres>, locked: &mut Locked) -> Result<()> {
    let drive = sqlx::query_scalar!(r#"SELECT kind = 'drive' AS "drive!" FROM accounts WHERE id = $1"#, locked.account)
        .fetch_one(&mut **tx)
        .await?;
    if drive {
        return Ok(());
    }
    let modseq = locked.next_modseq(tx).await?;
    let id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO file_nodes (id, account_id, node_type, name, role, created, modified, accessed)
         VALUES ($1, $2, 'directory', 'Trash', 'trash', now(), now(), now())",
        id,
        locked.account,
    )
    .execute(&mut **tx)
    .await?;
    record(tx, locked.account, modseq, id, Change::Created).await
}

/// Destroys a node – with all it holds, if `remove_children` – in the change in progress; returns the ids gone.
async fn destroy_in(
    tx: &mut Transaction<'static, Postgres>,
    locked: &mut Locked,
    access: &FileAccess,
    modseq: i64,
    id: Uuid,
    remove_children: bool,
) -> Result<Vec<Uuid>> {
    let node = acting_on(tx, access, id, Rights::DELETE).await?;
    if node.role.is_some() {
        return Err(FilesError::Forbidden("a directory with a role stays".into()));
    }
    let tree = sqlx::query!(
        r#"WITH RECURSIVE tree AS (
               SELECT id FROM file_nodes WHERE id = $1 AND account_id = $2
               UNION ALL
               SELECT n.id FROM file_nodes n JOIN tree ON n.parent_id = tree.id)
           SELECT id AS "id!" FROM tree LIMIT $3"#,
        id,
        locked.account,
        (MAX_DESTROY + 1) as i64,
    )
    .fetch_all(&mut **tx)
    .await?;
    if tree.len() > 1 && !remove_children {
        return Err(FilesError::HasChildren);
    }
    if tree.len() > MAX_DESTROY {
        return Err(FilesError::Forbidden(format!("at most {MAX_DESTROY} nodes go at once; destroy it in parts")));
    }
    // Only who can see all of it removes a subtree (draft, section 5).
    if tree.len() > 1 && !rights_of(tx, access, id).await?.contains(Rights::READ) {
        return Err(FilesError::Forbidden("it holds what you cannot see".into()));
    }
    let ids: Vec<Uuid> = tree.iter().map(|row| row.id).collect();
    sqlx::query!("DELETE FROM file_locks WHERE node_id = ANY($1)", &ids).execute(&mut **tx).await?;
    let gone = sqlx::query_as!(
        Released,
        "DELETE FROM file_contents WHERE node_id = ANY($1) RETURNING prefix, parts, size",
        &ids
    )
    .fetch_all(&mut **tx)
    .await?;
    // One statement: the references among the nodes are checked at its end, when all of them are gone.
    sqlx::query!("DELETE FROM file_nodes WHERE id = ANY($1)", &ids).execute(&mut **tx).await?;
    content::released(tx, locked, gone).await?;
    for id in &ids {
        record(tx, locked.account, modseq, *id, Change::Destroyed).await?;
    }
    Ok(ids)
}

/// The name a node gets under `parent` when another may hold it already, following `options`; nodes replaced are
/// destroyed and returned.
#[allow(clippy::too_many_arguments, reason = "one step of a change, with all it needs")]
async fn place(
    tx: &mut Transaction<'static, Postgres>,
    locked: &mut Locked,
    access: &FileAccess,
    modseq: i64,
    parent: Option<Uuid>,
    name: String,
    own: Option<Uuid>,
    options: &SetOptions,
) -> Result<(String, Vec<Uuid>)> {
    let Some(existing) = sibling(tx, locked.account, parent, &name, own, options.case_insensitive).await? else {
        return Ok((name, Vec::new()));
    };
    match options.on_exists {
        OnExists::Refuse => {
            // A sibling the user cannot see is not named (draft, 3.2.3).
            if rights_of(tx, access, existing).await?.is_empty() {
                return Err(FilesError::Forbidden("the name is taken".into()));
            }
            Err(FilesError::AlreadyExists(existing))
        }
        OnExists::Replace => {
            if rights_of(tx, access, existing).await?.is_empty() {
                return Err(FilesError::Forbidden("the name is taken".into()));
            }
            let destroyed = destroy_in(tx, locked, access, modseq, existing, options.remove_children).await?;
            Ok((name, destroyed))
        }
        OnExists::Rename => {
            for number in 2..10_000 {
                let candidate = numbered(&name, number);
                if sibling(tx, locked.account, parent, &candidate, own, options.case_insensitive).await?.is_none() {
                    return Ok((candidate, Vec::new()));
                }
            }
            Err(FilesError::AlreadyExists(existing))
        }
    }
}

impl Files {
    /// All nodes of the account, whoever may see them.
    pub async fn nodes(&self, account: Uuid) -> Result<Vec<NodeInfo>> {
        let mut tx = self.pool.begin().await?;
        self.open(&mut tx, account).await?;
        let rows = sqlx::query!(
            "SELECT id, parent_id, node_type, name, role, content_id, size, media_type, executable,
                    created, modified, accessed, changed, is_subscribed
             FROM file_nodes WHERE account_id = $1 ORDER BY id",
            account,
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows.into_iter().map(|row| node_info!(row)).collect())
    }

    /// The nodes of the account among `ids`, whoever may see them; unknown ids are left out.
    pub async fn get(&self, account: Uuid, ids: &[Uuid]) -> Result<Vec<NodeInfo>> {
        let mut tx = self.pool.begin().await?;
        self.open(&mut tx, account).await?;
        let nodes = load(&mut tx, account, ids).await?;
        tx.commit().await?;
        Ok(nodes)
    }

    /// The rights `access` has on a node.
    pub async fn rights(&self, access: &FileAccess, id: Uuid) -> Result<Rights> {
        let mut connection = self.pool.acquire().await?;
        rights_of(&mut connection, access, id).await
    }

    /// The contents of a file `access` may read: the current one first, then its versions, newest first.
    pub async fn versions(&self, access: &FileAccess, node: Uuid) -> Result<Vec<ContentInfo>> {
        let mut connection = self.pool.acquire().await?;
        let node = acting_on(&mut connection, access, node, Rights::READ).await?;
        if node.node_type != NodeType::File {
            return Err(FilesError::Invalid("not a file".into()));
        }
        content::contents(&mut connection, node.id).await
    }

    /// A content of the store – current or a version – that `access` may read, to read it.
    pub async fn readable(&self, access: &FileAccess, content: Uuid) -> Result<Readable> {
        let mut connection = self.pool.acquire().await?;
        let node = sqlx::query_scalar!(
            "SELECT node_id FROM file_contents WHERE id = $1 AND account_id = $2",
            content,
            access.owner,
        )
        .fetch_optional(&mut *connection)
        .await?
        .ok_or(FilesError::NotFound("the content"))?;
        acting_on(&mut connection, access, node, Rights::READ)
            .await
            .map_err(|_| FilesError::NotFound("the content"))?;
        let info = content::contents(&mut connection, node)
            .await?
            .into_iter()
            .find(|info| info.id == content)
            .ok_or(FilesError::NotFound("the content"))?;
        drop(connection);
        Ok(Readable { info, content: self.existing(content).await? })
    }

    /// Creates a node.
    pub async fn create(&self, access: &FileAccess, new: NewNode, options: &SetOptions) -> Result<Written> {
        check_name(&new.name)?;
        let media_type = match new.node_type {
            NodeType::File => {
                new.media_type.as_deref().map(check_media_type).transpose()?.unwrap_or(DEFAULT_MEDIA_TYPE.into())
            }
            NodeType::Directory if new.content.is_some() || new.media_type.is_some() || new.executable => {
                return Err(FilesError::Invalid("a directory has no content".into()));
            }
            NodeType::Directory => String::new(),
        };
        if new.node_type == NodeType::File && new.content.is_none() {
            return Err(FilesError::Invalid("a file needs its content".into()));
        }
        let account = access.owner;
        let mut tx = self.pool.begin().await?;
        let mut locked = self.lock_store(&mut tx, account).await?;
        check_parent(&mut tx, access, new.parent, 0).await?;
        let modseq = locked.next_modseq(&mut tx).await?;
        let (name, destroyed) =
            place(&mut tx, &mut locked, access, modseq, new.parent, new.name, None, options).await?;
        let id = Uuid::now_v7();
        let now = Utc::now();
        let modified = new.modified.unwrap_or(now);
        let content = match &new.content {
            Some(content) => Some((
                content::attach(&mut tx, &mut locked, self.limits.max_file_size, id, content, &media_type, modified)
                    .await?,
                content.stored.size as i64,
            )),
            None => None,
        };
        let file = new.node_type == NodeType::File;
        sqlx::query!(
            "INSERT INTO file_nodes (id, account_id, parent_id, node_type, name, content_id, size, media_type,
                                     executable, created, modified, accessed, is_subscribed)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
            id,
            account,
            new.parent,
            new.node_type.as_str(),
            name,
            content.map(|(content, _)| content),
            content.map(|(_, size)| size),
            file.then_some(media_type),
            file.then_some(new.executable),
            new.created.unwrap_or(now),
            modified,
            new.accessed.unwrap_or(now),
            new.is_subscribed,
        )
        .execute(&mut *tx)
        .await?;
        record(&mut tx, account, modseq, id, Change::Created).await?;
        let node = load_one(&mut tx, account, id).await?;
        tx.commit().await?;
        Ok(Written { node, destroyed })
    }

    /// Changes a node: moves or renames it, gives a file new content (the old one becomes a version), sets its
    /// properties.
    pub async fn update(
        &self,
        access: &FileAccess,
        id: Uuid,
        update: NodeUpdate,
        options: &SetOptions,
    ) -> Result<Written> {
        if let Some(name) = &update.name {
            check_name(name)?;
        }
        let media_type = update.media_type.as_deref().map(check_media_type).transpose()?;
        let account = access.owner;
        let mut tx = self.pool.begin().await?;
        let mut locked = self.lock_store(&mut tx, account).await?;
        let node = acting_on(&mut tx, access, id, Rights::NONE).await?;
        let rights = rights_of(&mut tx, access, id).await?;
        let parent = update.parent.unwrap_or(node.parent);
        let name = update.name.unwrap_or_else(|| node.name.clone());
        let moved = parent != node.parent;
        let renamed = moved || name != node.name;
        let content_changes = update.content.is_some()
            || media_type.is_some()
            || update.executable.is_some()
            || update.modified.is_some()
            || update.accessed.is_some();
        if node.role.is_some() && renamed {
            return Err(FilesError::Forbidden("a directory with a role stays where it is".into()));
        }
        if renamed && !rights.contains(Rights::RENAME) || content_changes && !rights.contains(Rights::WRITE) {
            return Err(FilesError::Forbidden("not allowed".into()));
        }
        if node.node_type == NodeType::Directory
            && (update.content.is_some() || media_type.is_some() || update.executable.is_some())
        {
            return Err(FilesError::Invalid("a directory has no content".into()));
        }
        if moved {
            if let Some(parent) = parent
                && (parent == id || ancestors(&mut tx, parent).await?.contains(&id))
            {
                return Err(FilesError::Invalid("a node cannot move below itself".into()));
            }
            let height = height(&mut tx, id).await?;
            check_parent(&mut tx, access, parent, height).await?;
        }
        let modseq = locked.next_modseq(&mut tx).await?;
        let (name, destroyed) = if renamed {
            place(&mut tx, &mut locked, access, modseq, parent, name, Some(id), options).await?
        } else {
            (name, Vec::new())
        };
        let modified = update.modified.or(update.content.as_ref().map(|_| Utc::now()));
        let new_content = match &update.content {
            Some(content) => {
                let kind = media_type.clone().or(node.media_type.clone()).unwrap_or(DEFAULT_MEDIA_TYPE.into());
                let at = modified.unwrap_or(node.modified);
                let max = self.limits.max_file_size;
                Some((content::attach(&mut tx, &mut locked, max, id, content, &kind, at).await?, content.stored.size))
            }
            None => None,
        };
        // Only the owner's own display setting is stored (draft: per user); others' are not kept (OPEN).
        let is_subscribed = update.is_subscribed.filter(|_| access.owned);
        sqlx::query!(
            "UPDATE file_nodes SET parent_id = $3, name = $4, content_id = coalesce($5, content_id),
                    size = coalesce($6, size), media_type = coalesce($7, media_type),
                    executable = coalesce($8, executable), modified = coalesce($9, modified),
                    accessed = coalesce($10, accessed), is_subscribed = coalesce($11, is_subscribed), changed = now()
             WHERE id = $1 AND account_id = $2",
            id,
            account,
            parent,
            name,
            new_content.map(|(content, _)| content),
            new_content.map(|(_, size)| size as i64),
            media_type,
            update.executable,
            modified,
            update.accessed,
            is_subscribed,
        )
        .execute(&mut *tx)
        .await?;
        if new_content.is_some() {
            content::prune_versions(&mut tx, &mut locked, id, self.limits.versions_kept).await?;
        }
        record(&mut tx, account, modseq, id, Change::Updated).await?;
        let node = load_one(&mut tx, account, id).await?;
        tx.commit().await?;
        Ok(Written { node, destroyed })
    }

    /// Gives a file new content and media type, and sets its modification time to now (the draft's direct write).
    pub async fn write(
        &self,
        access: &FileAccess,
        id: Uuid,
        content: Content,
        media_type: Option<&str>,
    ) -> Result<NodeInfo> {
        let node = self.get(access.owner, &[id]).await?.pop().ok_or(FilesError::NotFound("the node"))?;
        if node.node_type != NodeType::File {
            return Err(FilesError::Invalid("not a file".into()));
        }
        let update = NodeUpdate {
            content: Some(content),
            media_type: Some(media_type.unwrap_or(DEFAULT_MEDIA_TYPE).to_owned()),
            modified: Some(Utc::now()),
            ..NodeUpdate::default()
        };
        Ok(self.update(access, id, update, &SetOptions::default()).await?.node)
    }

    /// Makes an earlier version a file's content again; the content it had becomes a version.
    pub async fn restore(&self, access: &FileAccess, id: Uuid, version: Uuid) -> Result<NodeInfo> {
        let account = access.owner;
        let mut tx = self.pool.begin().await?;
        let mut locked = self.lock_store(&mut tx, account).await?;
        let node = acting_on(&mut tx, access, id, Rights::WRITE).await?;
        let found = content::contents(&mut tx, id).await?.into_iter().find(|content| content.id == version);
        let version = found.filter(|content| !content.current).ok_or(FilesError::NotFound("the version"))?;
        if node.node_type != NodeType::File {
            return Err(FilesError::Invalid("not a file".into()));
        }
        let modseq = locked.next_modseq(&mut tx).await?;
        // The content it had keeps the time it had; the restored one is the file's content as of now.
        sqlx::query!("UPDATE file_contents SET created_at = now() WHERE id = $1", version.id).execute(&mut *tx).await?;
        sqlx::query!(
            "UPDATE file_nodes SET content_id = $2, size = $3, media_type = $4, modified = now(), changed = now()
             WHERE id = $1",
            id,
            version.id,
            version.size as i64,
            version.media_type,
        )
        .execute(&mut *tx)
        .await?;
        record(&mut tx, account, modseq, id, Change::Updated).await?;
        let node = load_one(&mut tx, account, id).await?;
        tx.commit().await?;
        Ok(node)
    }

    /// Destroys a node – with all it holds, if `remove_children`; returns the ids of the nodes gone.
    pub async fn destroy(&self, access: &FileAccess, id: Uuid, remove_children: bool) -> Result<Vec<Uuid>> {
        let mut tx = self.pool.begin().await?;
        let mut locked = self.lock_store(&mut tx, access.owner).await?;
        let modseq = locked.next_modseq(&mut tx).await?;
        let destroyed = destroy_in(&mut tx, &mut locked, access, modseq, id, remove_children).await?;
        tx.commit().await?;
        Ok(destroyed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_the_rules() {
        for good in ["report.pdf", "Ä ö ü", ".hidden", "a".repeat(255).as_str()] {
            assert!(check_name(good).is_ok(), "{good}");
        }
        for bad in ["", ".", "..", "a/b", "a:b", "tab\there", "a".repeat(256).as_str(), "q?"] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn media_types_are_type_and_subtype() {
        assert_eq!(check_media_type("Application/PDF").unwrap(), "application/pdf");
        assert!(check_media_type("text/plain; charset=utf-8").is_err());
        assert!(check_media_type("text").is_err());
        assert!(check_media_type("/plain").is_err());
    }

    #[test]
    fn numbered_names_keep_the_extension() {
        assert_eq!(numbered("report.pdf", 2), "report (2).pdf");
        assert_eq!(numbered("Folder", 3), "Folder (3)");
        assert_eq!(numbered(".hidden", 2), ".hidden (2)");
        assert!(numbered(&"a".repeat(255), 2).len() <= MAX_NAME);
    }
}
