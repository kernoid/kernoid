// SPDX-License-Identifier: MIT
//! The Windows shell (docs/plan.md, 5): kernoid's stores in Explorer as sync roots of the Cloud Files API (cfapi), one
//! per store below a folder of the user's profile, with placeholders whose content is fetched when a program opens
//! them – as OneDrive does. It is a client of the core ([`super::call`]) like the shells of the other systems, with a
//! login of its own.
//!
//! What decides is here and runs on every system (and in the tests): the tree of a store as the shell last placed it
//! ([`Root`]), and how a page of changes from kernoid becomes steps on the disk ([`Root::apply`] through [`Disk`]).
//! What touches Windows – registering and connecting the sync roots, placeholders, the callbacks that fetch content and
//! report deletions and renames, the scan for files made or changed in Explorer, DPAPI for the login – is `system`,
//! only on Windows.
//!
//! The flow: `start` opens the core with the kept login, registers a sync root per store (`CfRegisterSyncRoot`, the
//! whole namespace placed by the shell: `CF_POPULATION_POLICY_ALWAYS_FULL`), connects it (`CfConnectSyncRoot`) and runs
//! a round every minute: `changes` since the store's anchor → placeholders made, renamed, moved, given new content
//! (dehydrated, unless changed here too) or removed; then files and folders new in Explorer are uploaded and turned
//! into placeholders, and changed ones uploaded again. Opening a placeholder calls FETCH_DATA: the core fetches the
//! content into a temporary file, which is handed over in pieces (`CfExecute`, TRANSFER_DATA). Deleting and renaming
//! in Explorer call NOTIFY_DELETE and NOTIFY_RENAME: the item goes into the store's Trash, or is renamed or moved at
//! kernoid, before the platform is told to go on.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

#[cfg(windows)]
pub(crate) mod system;

/// The file in the state directory that holds the shell's login (protected with DPAPI on Windows).
pub(crate) const LOGIN_FILE: &str = "login.dpapi";

/// How the shell is doing, for the app to show.
#[derive(Debug, Clone, Default)]
pub(crate) struct Status {
    pub running: bool,
    /// The sync roots, one folder per store.
    pub folders: Vec<String>,
    /// What failed since the last round began (the newest 20).
    pub problems: Vec<String>,
    /// The shell's login has ended: it is to be set up again.
    pub signed_out: bool,
    /// When the last round ended (RFC 3339).
    pub last_round: Option<String>,
}

pub(crate) static STATUS: Mutex<Status> = Mutex::new(Status {
    running: false,
    folders: Vec::new(),
    problems: Vec::new(),
    signed_out: false,
    last_round: None,
});

pub(crate) fn status() -> Status {
    STATUS.lock().map(|s| s.clone()).unwrap_or_default()
}

/// Whether the shell was set up in `state_dir`: it has a login of its own there.
pub(crate) fn configured(state_dir: &str) -> bool {
    std::path::Path::new(state_dir).join(LOGIN_FILE).is_file()
}

/// An item as the core describes it (`provider::item`), as far as the shell needs it.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Item {
    pub id: String,
    pub parent: Option<String>,
    pub name: String,
    pub directory: bool,
    #[serde(default)]
    pub size: u64,
    pub modified: Option<String>,
    pub version: String,
    #[serde(default)]
    pub rights: Rights,
    #[serde(default)]
    pub locked: bool,
    pub role: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct Rights {
    #[serde(default = "yes")]
    pub write: bool,
}

fn yes() -> bool {
    true
}

impl Item {
    /// Shown in Explorer: not in a vault (**OPEN**: vaults in the shells, plan section 6), not the Trash, and with a
    /// name Windows allows.
    pub fn shown(&self) -> bool {
        !self.locked && self.role.as_deref() != Some("trash") && windows_name(&self.name)
    }

    /// The content's part of the version (`blob|parent|name`): what changed when it differs.
    pub fn content(&self) -> &str {
        content(&self.version)
    }

    /// Windows' time of the last change: 100 ns since 1601 (UTC).
    pub fn filetime(&self) -> i64 {
        self.modified.as_deref().and_then(filetime).unwrap_or_else(|| filetime_of(jiff::Timestamp::now()))
    }
}

fn content(version: &str) -> &str {
    version.split('|').next().unwrap_or_default()
}

/// An RFC 3339 time in Windows' FILETIME.
pub(crate) fn filetime(text: &str) -> Option<i64> {
    text.parse::<jiff::Timestamp>().ok().map(filetime_of)
}

fn filetime_of(time: jiff::Timestamp) -> i64 {
    const SINCE_1601: i64 = 11_644_473_600;
    (time.as_second() + SINCE_1601) * 10_000_000 + i64::from(time.subsec_nanosecond() / 100)
}

/// Whether Windows allows `name` for a file or folder: no reserved characters, no trailing dot or space, not a device
/// name (`CON`, `NUL`, `COM1` …, also with an extension), at most 255 UTF-16 units.
pub(crate) fn windows_name(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." || name.encode_utf16().count() > 255 {
        return false;
    }
    if name.chars().any(reserved) {
        return false;
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return false;
    }
    let stem = name.split('.').next().unwrap_or_default().trim_end().to_ascii_uppercase();
    let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0');
    !device
}

fn reserved(c: char) -> bool {
    (c as u32) < 32 || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
}

/// Files of the system and of programs at work that are not uploaded from Explorer.
pub(crate) fn ignored(name: &str) -> bool {
    let lower = name.to_lowercase();
    matches!(lower.as_str(), "desktop.ini" | "thumbs.db" | ".ds_store")
        || lower.starts_with("~$")
        || lower.ends_with(".tmp")
        || lower.ends_with(".crdownload")
        || lower.ends_with(".partial")
}

/// The folders for the stores below the shell's folder: their names made allowed for Windows, and told apart when two
/// are equal (Windows does not tell case apart).
pub(crate) fn folder_names(stores: &[(String, String)]) -> Vec<String> {
    let mut taken = HashSet::new();
    stores
        .iter()
        .map(|(id, name)| {
            let mut base: String = name.chars().map(|c| if reserved(c) { '_' } else { c }).collect();
            base = base.trim_end_matches(['.', ' ']).trim().to_owned();
            if !windows_name(&base) {
                base = format!("kernoid {id}");
            }
            let mut candidate = base.clone();
            let mut n = 2;
            while !taken.insert(candidate.to_lowercase()) {
                candidate = format!("{base} ({n})");
                n += 1;
            }
            candidate
        })
        .collect()
}

/// Paths are Windows' (`\`) wherever this runs, compared without case.
pub(crate) fn join(dir: &str, name: &str) -> String {
    format!("{}\\{name}", dir.trim_end_matches('\\'))
}

/// A path as compared: without the `\\?\` prefix and a trailing `\`, `/` as `\`, in lower case.
pub(crate) fn normal(path: &str) -> String {
    let path = path.strip_prefix(r"\\?\").unwrap_or(path).replace('/', "\\");
    path.trim_end_matches('\\').to_lowercase()
}

/// Whether `path` is `dir` or lies below it.
pub(crate) fn within(path: &str, dir: &str) -> bool {
    let (path, dir) = (normal(path), normal(dir));
    path == dir || path.strip_prefix(&dir).is_some_and(|rest| rest.starts_with('\\'))
}

/// An item as the shell placed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Entry {
    pub parent: Option<String>,
    pub name: String,
    pub directory: bool,
    pub version: String,
}

/// A store as a sync root: its folder, the anchor of the last changes applied, and its tree as placed – kept in the
/// state directory between starts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct Root {
    pub store: String,
    pub path: String,
    /// The state of `FileNode/changes` applied last; empty: everything is compared again.
    #[serde(default)]
    pub anchor: String,
    #[serde(default)]
    pub items: HashMap<String, Entry>,
}

/// What the shell does on the disk for [`Root::apply`]; an error is a message and leaves the tree as it was.
pub(crate) trait Disk {
    /// A placeholder for `item` in the folder `dir`.
    fn create(&mut self, dir: &str, item: &Item) -> Result<(), String>;
    /// A placeholder renamed or moved.
    fn rename(&mut self, from: &str, to: &str) -> Result<(), String>;
    /// A file's content changed at kernoid: new size and time, the old content dropped – unless it changed here too.
    fn replace(&mut self, path: &str, item: &Item) -> Result<(), String>;
    /// A placeholder removed, a folder with everything in it.
    fn delete(&mut self, path: &str, directory: bool) -> Result<(), String>;
}

impl Root {
    pub fn new(store: &str, path: &str) -> Root {
        Root { store: store.to_owned(), path: path.to_owned(), ..Root::default() }
    }

    /// Where an item lies, or none when it or one above it is not placed.
    pub fn path_of(&self, id: &str) -> Option<String> {
        let mut names = Vec::new();
        let mut current = Some(id.to_owned());
        while let Some(id) = current {
            let entry = self.items.get(&id)?;
            names.push(entry.name.clone());
            current = entry.parent.clone();
            if names.len() > 1024 {
                return None;
            }
        }
        Some(names.iter().rev().fold(self.path.clone(), |dir, name| join(&dir, name)))
    }

    /// The item named `name` in the folder `parent` (none: the top).
    pub fn child(&self, parent: Option<&str>, name: &str) -> Option<String> {
        let name = name.to_lowercase();
        self.items
            .iter()
            .find(|(_, e)| e.parent.as_deref() == parent && e.name.to_lowercase() == name)
            .map(|(id, _)| id.clone())
    }

    /// What lies at `path`: `Some(None)` is the root itself, `Some(Some(id))` an item, `None` nothing placed or a path
    /// outside the root.
    pub fn at(&self, path: &str) -> Option<Option<String>> {
        let (path, root) = (normal(path), normal(&self.path));
        if path == root {
            return Some(None);
        }
        let rest = path.strip_prefix(&root)?.strip_prefix('\\')?;
        let mut current: Option<String> = None;
        for name in rest.split('\\') {
            current = Some(self.child(current.as_deref(), name)?);
        }
        Some(current)
    }

    /// Forgets an item and everything below it.
    pub fn remove(&mut self, id: &str) {
        let mut gone = vec![id.to_owned()];
        while let Some(id) = gone.pop() {
            self.items.remove(&id);
            gone.extend(self.items.iter().filter(|(_, e)| e.parent.as_deref() == Some(&id)).map(|(c, _)| c.clone()));
        }
    }

    pub fn place(&mut self, item: &Item) {
        let entry = Entry {
            parent: item.parent.clone(),
            name: item.name.clone(),
            directory: item.directory,
            version: item.version.clone(),
        };
        self.items.insert(item.id.clone(), entry);
    }

    /// Applies a page of changes: `deleted` ids removed, `items` made, moved or given new content – parents before
    /// what lies in them. With `reset`, `items` is the whole store and what is placed but not in it is removed. Items
    /// not shown, or below one not shown (a vault, the Trash), are removed when placed. Returns what failed; after a
    /// failure the anchor should be dropped, so that the next round compares everything and tries again.
    pub fn apply(&mut self, items: &[Item], deleted: &[String], reset: bool, disk: &mut impl Disk) -> Vec<String> {
        let mut problems = Vec::new();
        let mut gone: Vec<String> = deleted.to_vec();
        if reset {
            let present: HashSet<&str> = items.iter().map(|i| i.id.as_str()).collect();
            gone.extend(self.items.keys().filter(|id| !present.contains(id.as_str())).cloned());
        }
        gone.extend(items.iter().filter(|i| !i.shown()).map(|i| i.id.clone()));
        // Moves first, deletions last: what is moved out of a deleted folder is not lost with it.
        let mut pending: Vec<&Item> = items.iter().filter(|i| i.shown() && !gone.contains(&i.id)).collect();
        loop {
            let before = pending.len();
            pending.retain(|item| {
                let parent_placed = item.parent.as_ref().is_none_or(|p| self.items.contains_key(p));
                if !parent_placed {
                    return true;
                }
                if let Err(problem) = self.update(item, disk) {
                    problems.push(format!("{}: {problem}", item.name));
                }
                false
            });
            if pending.is_empty() || pending.len() == before {
                break;
            }
        }
        // Moved below something not shown: no longer in Explorer.
        gone.extend(pending.iter().map(|i| i.id.clone()));
        for id in gone {
            self.delete(&id, disk, &mut problems);
        }
        problems
    }

    fn delete(&mut self, id: &str, disk: &mut impl Disk, problems: &mut Vec<String>) {
        let (Some(path), Some(entry)) = (self.path_of(id), self.items.get(id)) else { return };
        match disk.delete(&path, entry.directory) {
            Ok(()) => self.remove(id),
            Err(problem) => problems.push(format!("{}: {problem}", entry.name)),
        }
    }

    fn update(&mut self, item: &Item, disk: &mut impl Disk) -> Result<(), String> {
        let dir = match &item.parent {
            Some(parent) => self.path_of(parent).ok_or("the folder above is not placed")?,
            None => self.path.clone(),
        };
        let Some(entry) = self.items.get(&item.id).cloned() else {
            disk.create(&dir, item)?;
            self.place(item);
            return Ok(());
        };
        let from = self.path_of(&item.id).ok_or("not placed")?;
        let to = join(&dir, &item.name);
        if entry.parent != item.parent || entry.name != item.name {
            disk.rename(&from, &to)?;
            let moved = Entry { parent: item.parent.clone(), name: item.name.clone(), ..entry.clone() };
            self.items.insert(item.id.clone(), moved);
        }
        if !item.directory && content(&entry.version) != item.content() {
            disk.replace(&to, item)?;
        }
        self.place(item);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, parent: Option<&str>, name: &str, directory: bool, blob: &str) -> Item {
        Item {
            id: id.into(),
            parent: parent.map(Into::into),
            name: name.into(),
            directory,
            size: 3,
            modified: Some("2026-11-04T12:00:00Z".into()),
            version: format!("{blob}|{}|{name}", parent.unwrap_or("-")),
            rights: Rights { write: true },
            locked: false,
            role: None,
        }
    }

    /// The disk as a list of what was done.
    #[derive(Default)]
    struct Log(Vec<String>);

    impl Disk for Log {
        fn create(&mut self, dir: &str, item: &Item) -> Result<(), String> {
            self.0.push(format!("create {}", join(dir, &item.name)));
            Ok(())
        }
        fn rename(&mut self, from: &str, to: &str) -> Result<(), String> {
            self.0.push(format!("rename {from} -> {to}"));
            Ok(())
        }
        fn replace(&mut self, path: &str, _: &Item) -> Result<(), String> {
            self.0.push(format!("replace {path}"));
            Ok(())
        }
        fn delete(&mut self, path: &str, _: bool) -> Result<(), String> {
            self.0.push(format!("delete {path}"));
            Ok(())
        }
    }

    #[test]
    fn a_store_is_placed_parents_first_and_kept_in_step() {
        let mut root = Root::new("s", r"C:\Users\u\kernoid\Files");
        let mut disk = Log::default();
        let first = [
            item("c", Some("b"), "Plan.txt", false, "x"),
            item("b", Some("a"), "Docs", true, "-"),
            item("a", None, "Work", true, "-"),
            item("t", None, "Trash", true, "-"),
        ];
        let mut first = first.to_vec();
        first[3].role = Some("trash".into());
        assert!(root.apply(&first, &[], true, &mut disk).is_empty());
        assert_eq!(
            disk.0,
            [
                r"create C:\Users\u\kernoid\Files\Work",
                r"create C:\Users\u\kernoid\Files\Work\Docs",
                r"create C:\Users\u\kernoid\Files\Work\Docs\Plan.txt",
            ]
        );
        assert_eq!(root.at(r"c:\users\u\KERNOID\files\work\docs\plan.txt"), Some(Some("c".into())));
        assert_eq!(root.at(r"\\?\C:\Users\u\kernoid\Files\"), Some(None));
        assert_eq!(root.at(r"C:\Users\u\kernoid\Other"), None);

        // Renamed and given new content; a folder moved to the top; one deleted.
        disk.0.clear();
        let changed = [item("c", Some("b"), "Plan v2.txt", false, "y"), item("b", None, "Docs", true, "-")];
        assert!(root.apply(&changed, &["a".into()], false, &mut disk).is_empty());
        assert_eq!(
            disk.0,
            [
                r"rename C:\Users\u\kernoid\Files\Work\Docs\Plan.txt -> C:\Users\u\kernoid\Files\Work\Docs\Plan v2.txt",
                r"replace C:\Users\u\kernoid\Files\Work\Docs\Plan v2.txt",
                r"rename C:\Users\u\kernoid\Files\Work\Docs -> C:\Users\u\kernoid\Files\Docs",
                r"delete C:\Users\u\kernoid\Files\Work",
            ],
            "what is moved out of a deleted folder is moved before the folder goes"
        );

        disk.0.clear();
        let moved = [item("c", None, "Plan v2.txt", false, "y")];
        root.apply(&moved, &[], false, &mut disk);
        assert_eq!(
            disk.0,
            [r"rename C:\Users\u\kernoid\Files\Docs\Plan v2.txt -> C:\Users\u\kernoid\Files\Plan v2.txt"]
        );

        disk.0.clear();
        let mut locked = item("c", None, "Plan v2.txt", false, "z");
        locked.locked = true;
        root.apply(&[locked, item("b", None, "Docs", true, "-")], &[], true, &mut disk);
        assert_eq!(disk.0, [r"delete C:\Users\u\kernoid\Files\Plan v2.txt"]);
        assert_eq!(root.items.len(), 1);
    }

    #[test]
    fn content_changes_only_when_the_blob_does() {
        let mut root = Root::new("s", r"C:\k");
        let mut disk = Log::default();
        root.apply(&[item("f", None, "a.txt", false, "x")], &[], false, &mut disk);
        disk.0.clear();
        root.apply(&[item("f", None, "b.txt", false, "x")], &[], false, &mut disk);
        assert_eq!(disk.0, [r"rename C:\k\a.txt -> C:\k\b.txt"]);
        disk.0.clear();
        root.apply(&[item("f", None, "b.txt", false, "w")], &[], false, &mut disk);
        assert_eq!(disk.0, [r"replace C:\k\b.txt"]);
    }

    #[test]
    fn names_windows_refuses_are_left_out() {
        for bad in ["a:b", "x?", "trailing.", "space ", "CON", "con.txt", "Lpt1", "COM9.log", "", "a\u{1}"] {
            assert!(!windows_name(bad), "{bad:?}");
        }
        for good in ["Plan.txt", "COM0", "Console", "LPT", ".hidden", "Über"] {
            assert!(windows_name(good), "{good:?}");
        }
        let names = folder_names(&[
            ("1".into(), "Files".into()),
            ("2".into(), "files".into()),
            ("3".into(), "A/B: team".into()),
            ("4".into(), "CON".into()),
        ]);
        assert_eq!(names, ["Files", "files (2)", "A_B_ team", "kernoid 4"]);
    }

    #[test]
    fn times_are_windows_filetimes() {
        // 1970-01-01 is 11644473600 seconds after 1601-01-01.
        assert_eq!(filetime("1970-01-01T00:00:00Z"), Some(116_444_736_000_000_000));
        assert_eq!(filetime("1970-01-01T00:00:01.5+00:00"), Some(116_444_736_015_000_000));
        assert_eq!(filetime("yesterday"), None);
    }

    #[test]
    fn paths_compare_without_case_and_prefix() {
        assert!(within(r"\\?\C:\Users\U\kernoid\Files\a", r"c:\users\u\kernoid\files"));
        assert!(within(r"C:\k", r"C:\k\"));
        assert!(!within(r"C:\kernoid2\a", r"C:\kernoid"));
        assert!(ignored("~$Report.docx") && ignored("Thumbs.db") && !ignored("Report.docx"));
    }
}
