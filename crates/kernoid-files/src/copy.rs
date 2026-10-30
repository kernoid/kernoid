// SPDX-License-Identifier: AGPL-3.0-or-later
//! Copying a node – a directory with what it holds – into a store, the same or another of the tenant (WebDAV's
//! `COPY` and `MOVE`, JMAP's `FileNode/copy`; RFC 0005, 8 and 9): a file's copy shares its content's parts, and only
//! what the user may read is copied.

use std::{future::Future, pin::Pin};

use uuid::Uuid;

use crate::{FileAccess, Files, FilesError, MAX_DEPTH, NewNode, NodeInfo, NodeType, Result, SetOptions, View};

impl Files {
    /// Copies `node` of `from` below `parent` of the store `to` reaches, as `name`, with `options` for the node
    /// itself; returns the copy.
    pub async fn copy_tree(
        &self,
        to: &FileAccess,
        from: &View,
        node: &NodeInfo,
        parent: Option<Uuid>,
        name: String,
        options: &SetOptions,
    ) -> Result<NodeInfo> {
        copy(self, to, from, node, parent, name, options, 0).await
    }
}

/// The children of a node in a view, by name.
pub fn children(view: &View, parent: Option<Uuid>) -> Vec<&NodeInfo> {
    let mut out: Vec<&NodeInfo> = view.nodes().filter(|node| node.parent == parent).collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[allow(clippy::too_many_arguments, reason = "one step of a recursive copy")]
fn copy<'a>(
    files: &'a Files,
    to: &'a FileAccess,
    from: &'a View,
    node: &'a NodeInfo,
    parent: Option<Uuid>,
    name: String,
    options: &'a SetOptions,
    depth: usize,
) -> Pin<Box<dyn Future<Output = Result<NodeInfo>> + Send + 'a>> {
    Box::pin(async move {
        if depth > MAX_DEPTH {
            return Err(FilesError::Invalid("too deep".into()));
        }
        if !from.readable(node.id) {
            return Err(FilesError::Forbidden("reading what is copied".into()));
        }
        let mut new = match (node.node_type, node.content) {
            (NodeType::File, Some(content)) => {
                NewNode::file(parent, name, files.existing(content).await?, node.media_type.clone())
            }
            _ => NewNode::directory(parent, name),
        };
        // A copy inside the vault keeps its encrypted name; out of it, the creation refuses it (RFC 0006, 6).
        new.encrypted_name = node.encrypted_name.clone();
        let created = files.create(to, new, options).await?.node;
        if node.node_type == NodeType::Directory {
            for child in children(from, Some(node.id)) {
                let fresh = SetOptions::default();
                copy(files, to, from, child, Some(created.id), child.name.clone(), &fresh, depth + 1).await?;
            }
        }
        Ok(created)
    })
}
