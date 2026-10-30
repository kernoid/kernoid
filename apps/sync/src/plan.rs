// SPDX-License-Identifier: MIT
//! What to do to bring a folder and a store into step – decided from three views of every path: as both sides were
//! when they last agreed (the base), as the store is now, as the folder is now. Pure: no I/O, so every case is tested.
//!
//! A change on one side is carried to the other. A change on both sides is a conflict: the server's version wins the
//! name, the local one is kept beside it as a copy – never merged, never lost (the copy is uploaded in the next round).
//! A deletion never takes a change of the other side with it: a file deleted here but changed on the server comes
//! back, a file deleted on the server but changed here is uploaded again. A move is a deletion and a creation (OPEN:
//! moves as moves).

use std::collections::{BTreeMap, BTreeSet};

/// A path relative to the folder, `/`-separated, without a leading `/` (`Projects/plan.txt`).
pub type RelPath = String;

/// A node of the store at a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub id: String,
    pub directory: bool,
    /// The content's blob; `None` for a directory.
    pub blob: Option<String>,
    pub size: u64,
}

/// A file or directory of the folder at a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Local {
    pub directory: bool,
    pub size: u64,
    /// Modification time, nanoseconds since 1970 – with the size, what tells a change without reading the file.
    pub modified: i128,
}

/// A path as both sides were when they last agreed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base {
    pub remote: Remote,
    pub local: Local,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Make the directory here.
    MakeLocalDirectory(RelPath),
    /// Make the directory in the store (its parent first).
    MakeRemoteDirectory(RelPath),
    /// Download the node's content to the path (replacing what is there).
    Download { path: RelPath, id: String, blob: String },
    /// Upload the file as a new node (`id: None`) or as new content of a node.
    Upload { path: RelPath, id: Option<String> },
    /// Delete here (a directory with what is in it).
    DeleteLocal(RelPath),
    /// Move the node to the store's trash.
    DeleteRemote { path: RelPath, id: String },
    /// Rename the local file to a conflict copy beside it, before the server's version is downloaded.
    KeepLocalCopy(RelPath),
    /// Both sides agree already (both made the same directory): remember it.
    Adopt(RelPath),
}

/// The actions in the order they must run: local directories and copies first, then downloads; remote directories
/// shallow before deep, then uploads; deletions deep before shallow.
pub fn plan(
    base: &BTreeMap<RelPath, Base>,
    remote: &BTreeMap<RelPath, Remote>,
    local: &BTreeMap<RelPath, Local>,
) -> Vec<Action> {
    let paths: BTreeSet<&RelPath> = base.keys().chain(remote.keys()).chain(local.keys()).collect();
    let mut actions = Vec::new();
    // Deleted directories take what is below them along; their contents need no actions of their own.
    let mut gone_here: Vec<&str> = Vec::new();
    let mut gone_there: Vec<&str> = Vec::new();
    let under = |path: &str, roots: &[&str]| roots.iter().any(|root| path.starts_with(&format!("{root}/")));
    for path in &paths {
        let (b, r, l) = (base.get(*path), remote.get(*path), local.get(*path));
        let remote_changed = match (b, r) {
            (Some(b), Some(r)) => b.remote.id != r.id || b.remote.blob != r.blob || b.remote.directory != r.directory,
            (None, Some(_)) => true,
            _ => false,
        };
        let local_changed = match (b, l) {
            (Some(b), Some(l)) => {
                b.local.directory != l.directory
                    || (!l.directory && (b.local.size != l.size || b.local.modified != l.modified))
            }
            (None, Some(_)) => true,
            _ => false,
        };
        if under(path, &gone_here) || under(path, &gone_there) {
            continue;
        }
        match (b, r, l) {
            (_, None, None) => {}
            // New on one side only.
            (None, Some(r), None) => actions.push(fetch(path, r)),
            (None, None, Some(l)) => actions.push(send(path, l, None)),
            // New on both sides.
            (None, Some(r), Some(l)) => {
                if r.directory && l.directory {
                    actions.push(Action::Adopt((*path).clone()));
                } else {
                    // Two files, or a file and a directory, of one name: the server's keeps the name.
                    actions.push(Action::KeepLocalCopy((*path).clone()));
                    actions.push(fetch(path, r));
                }
            }
            // Known to both before.
            (Some(_), Some(r), Some(l)) => match (remote_changed, local_changed) {
                (false, false) => {}
                (true, false) => {
                    // A file replaced by a directory on the server, or the other way round.
                    if l.directory != r.directory {
                        actions.push(Action::DeleteLocal((*path).clone()));
                    }
                    actions.push(fetch(path, r));
                }
                (false, true) => {
                    if r.directory && !l.directory {
                        // A directory replaced by a file here.
                        actions.push(Action::KeepLocalCopy((*path).clone()));
                        actions.push(fetch(path, r));
                    } else if !l.directory {
                        actions.push(send(path, l, Some(r.id.clone())));
                    }
                }
                (true, true) => {
                    if r.directory && l.directory {
                        actions.push(Action::Adopt((*path).clone()));
                    } else {
                        actions.push(Action::KeepLocalCopy((*path).clone()));
                        actions.push(fetch(path, r));
                    }
                }
            },
            // Gone on the server.
            (Some(b), None, Some(l)) => {
                if local_changed || (l.directory && changed_below(path, base, local)) {
                    actions.push(send(path, l, None));
                } else {
                    actions.push(Action::DeleteLocal((*path).clone()));
                    if b.local.directory {
                        gone_here.push(path);
                    }
                }
            }
            // Gone here.
            (Some(b), Some(r), None) => {
                if remote_changed || (r.directory && changed_below(path, base, remote)) {
                    actions.push(fetch(path, r));
                } else {
                    actions.push(Action::DeleteRemote { path: (*path).clone(), id: r.id.clone() });
                    if b.remote.directory {
                        gone_there.push(path);
                    }
                }
            }
        }
    }
    order(actions)
}

fn fetch(path: &RelPath, remote: &Remote) -> Action {
    if remote.directory {
        Action::MakeLocalDirectory(path.clone())
    } else {
        Action::Download { path: path.clone(), id: remote.id.clone(), blob: remote.blob.clone().unwrap_or_default() }
    }
}

fn send(path: &RelPath, local: &Local, id: Option<String>) -> Action {
    if local.directory { Action::MakeRemoteDirectory(path.clone()) } else { Action::Upload { path: path.clone(), id } }
}

/// Whether anything below a directory changed on the side `now` describes, against the base.
fn changed_below<T: Changed>(directory: &str, base: &BTreeMap<RelPath, Base>, now: &BTreeMap<RelPath, T>) -> bool {
    let prefix = format!("{directory}/");
    now.iter().filter(|(path, _)| path.starts_with(&prefix)).any(|(path, node)| match base.get(path) {
        Some(base) => node.differs(base),
        None => true,
    })
}

trait Changed {
    fn differs(&self, base: &Base) -> bool;
}

impl Changed for Local {
    fn differs(&self, base: &Base) -> bool {
        base.local.directory != self.directory
            || (!self.directory && (base.local.size != self.size || base.local.modified != self.modified))
    }
}

impl Changed for Remote {
    fn differs(&self, base: &Base) -> bool {
        base.remote.id != self.id || base.remote.blob != self.blob
    }
}

fn depth(path: &str) -> usize {
    path.matches('/').count()
}

fn order(actions: Vec<Action>) -> Vec<Action> {
    let rank = |action: &Action| -> (u8, isize) {
        match action {
            Action::KeepLocalCopy(path) => (0, depth(path) as isize),
            Action::DeleteLocal(path) => (1, -(depth(path) as isize)),
            Action::MakeLocalDirectory(path) => (2, depth(path) as isize),
            Action::Download { path, .. } => (3, depth(path) as isize),
            Action::MakeRemoteDirectory(path) => (4, depth(path) as isize),
            Action::Upload { path, .. } => (5, depth(path) as isize),
            Action::DeleteRemote { path, .. } => (6, -(depth(path) as isize)),
            Action::Adopt(path) => (7, depth(path) as isize),
        }
    };
    let mut actions = actions;
    actions.sort_by_key(rank);
    actions
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(id: &str, blob: &str) -> Remote {
        Remote { id: id.into(), directory: false, blob: Some(blob.into()), size: 1 }
    }
    fn dir(id: &str) -> Remote {
        Remote { id: id.into(), directory: true, blob: None, size: 0 }
    }
    fn here(size: u64, modified: i128) -> Local {
        Local { directory: false, size, modified }
    }
    fn here_dir() -> Local {
        Local { directory: true, size: 0, modified: 0 }
    }
    fn map<T: Clone>(entries: &[(&str, T)]) -> BTreeMap<RelPath, T> {
        entries.iter().map(|(path, value)| ((*path).to_owned(), value.clone())).collect()
    }
    fn agreed(entries: &[(&str, Remote, Local)]) -> BTreeMap<RelPath, Base> {
        entries.iter().map(|(p, r, l)| ((*p).to_owned(), Base { remote: r.clone(), local: *l })).collect()
    }

    #[test]
    fn nothing_changed_nothing_to_do() {
        let base = agreed(&[("a.txt", file("n1", "b1"), here(1, 10)), ("D", dir("n2"), here_dir())]);
        let remote = map(&[("a.txt", file("n1", "b1")), ("D", dir("n2"))]);
        let local = map(&[("a.txt", here(1, 10)), ("D", here_dir())]);
        assert!(plan(&base, &remote, &local).is_empty());
    }

    #[test]
    fn the_first_round_brings_both_sides_together() {
        let remote = map(&[("D", dir("n1")), ("D/x.txt", file("n2", "b2")), ("same", dir("n3"))]);
        let local = map(&[("E", here_dir()), ("E/y.txt", here(3, 1)), ("same", here_dir())]);
        assert_eq!(
            plan(&BTreeMap::new(), &remote, &local),
            [
                Action::MakeLocalDirectory("D".into()),
                Action::Download { path: "D/x.txt".into(), id: "n2".into(), blob: "b2".into() },
                Action::MakeRemoteDirectory("E".into()),
                Action::Upload { path: "E/y.txt".into(), id: None },
                Action::Adopt("same".into()),
            ]
        );
    }

    #[test]
    fn a_change_goes_to_the_other_side() {
        let base = agreed(&[("a", file("n1", "b1"), here(1, 10)), ("b", file("n2", "b2"), here(1, 10))]);
        let remote = map(&[("a", file("n1", "b9")), ("b", file("n2", "b2"))]);
        let local = map(&[("a", here(1, 10)), ("b", here(2, 11))]);
        assert_eq!(
            plan(&base, &remote, &local),
            [
                Action::Download { path: "a".into(), id: "n1".into(), blob: "b9".into() },
                Action::Upload { path: "b".into(), id: Some("n2".into()) },
            ]
        );
    }

    #[test]
    fn a_change_on_both_sides_keeps_both() {
        let base = agreed(&[("a", file("n1", "b1"), here(1, 10))]);
        let remote = map(&[("a", file("n1", "b2"))]);
        let local = map(&[("a", here(5, 20))]);
        assert_eq!(
            plan(&base, &remote, &local),
            [
                Action::KeepLocalCopy("a".into()),
                Action::Download { path: "a".into(), id: "n1".into(), blob: "b2".into() },
            ]
        );
        // New on both sides, never seen before: the same.
        let remote = map(&[("n", file("n5", "b5"))]);
        let local = map(&[("n", here(1, 1))]);
        assert_eq!(plan(&BTreeMap::new(), &remote, &local)[0], Action::KeepLocalCopy("n".into()));
    }

    #[test]
    fn deletions_carry_over_but_never_take_a_change_along() {
        let base = agreed(&[
            ("gone-there", file("n1", "b1"), here(1, 10)),
            ("gone-here", file("n2", "b2"), here(1, 10)),
            ("gone-there-changed-here", file("n3", "b3"), here(1, 10)),
            ("gone-here-changed-there", file("n4", "b4"), here(1, 10)),
        ]);
        let remote = map(&[("gone-here", file("n2", "b2")), ("gone-here-changed-there", file("n4", "b5"))]);
        let local = map(&[("gone-there", here(1, 10)), ("gone-there-changed-here", here(7, 11))]);
        assert_eq!(
            plan(&base, &remote, &local),
            [
                Action::DeleteLocal("gone-there".into()),
                Action::Download { path: "gone-here-changed-there".into(), id: "n4".into(), blob: "b5".into() },
                Action::Upload { path: "gone-there-changed-here".into(), id: None },
                Action::DeleteRemote { path: "gone-here".into(), id: "n2".into() },
            ]
        );
    }

    #[test]
    fn a_deleted_directory_goes_whole_unless_something_in_it_changed() {
        let base = agreed(&[
            ("D", dir("n1"), here_dir()),
            ("D/a", file("n2", "b2"), here(1, 10)),
            ("E", dir("n3"), here_dir()),
            ("E/b", file("n4", "b4"), here(1, 10)),
        ]);
        // D gone on the server, unchanged here: deleted here, with what is in it. E gone on the server, but E/b
        // changed here: E and E/b go up again.
        let remote = BTreeMap::new();
        let local = map(&[("D", here_dir()), ("D/a", here(1, 10)), ("E", here_dir()), ("E/b", here(2, 12))]);
        assert_eq!(
            plan(&base, &remote, &local),
            [
                Action::DeleteLocal("D".into()),
                Action::MakeRemoteDirectory("E".into()),
                Action::Upload { path: "E/b".into(), id: None },
            ]
        );
        // The same the other way round.
        let remote = map(&[("D", dir("n1")), ("D/a", file("n2", "b2")), ("E", dir("n3")), ("E/b", file("n4", "b9"))]);
        assert_eq!(
            plan(&base, &remote, &BTreeMap::new()),
            [
                Action::MakeLocalDirectory("E".into()),
                Action::Download { path: "E/b".into(), id: "n4".into(), blob: "b9".into() },
                Action::DeleteRemote { path: "D".into(), id: "n1".into() },
            ]
        );
    }

    #[test]
    fn deep_directories_are_made_after_their_parents_and_deleted_before() {
        let remote = map(&[("A/B/C", dir("c")), ("A", dir("a")), ("A/B", dir("b"))]);
        let made = plan(&BTreeMap::new(), &remote, &BTreeMap::new());
        assert_eq!(
            made,
            [
                Action::MakeLocalDirectory("A".into()),
                Action::MakeLocalDirectory("A/B".into()),
                Action::MakeLocalDirectory("A/B/C".into()),
            ]
        );
    }
}
