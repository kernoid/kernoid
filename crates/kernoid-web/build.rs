// SPDX-License-Identifier: AGPL-3.0-or-later
//! Writes the tables of `lib.rs`: one per build, each file taken with `include_bytes!`. In the repository a build
//! comes from `web/<name>/dist` (`pnpm build`); in the package on crates.io, which has no `web/`, from the copy in
//! `dist/<name>`. Without either the table is empty.

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

/// The tables and the builds they hold.
const BUILDS: [(&str, &str); 2] = [("LOGIN_UI", "login"), ("WEB_APP", "app")];

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("set by Cargo"));
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("set by Cargo"));
    let mut code = String::from("// Written by build.rs.\n");
    for (table, name) in BUILDS {
        // The repository: crates/kernoid-web next to web/<name>, the sources of the build.
        let sources = manifest.join("../../web").join(name);
        let directory = if sources.join("package.json").is_file() {
            sources.join("dist")
        } else {
            manifest.join("dist").join(name)
        };
        // A directory is watched with everything in it; one that does not exist yet, through its parent (in the
        // repository the build's sources, not its dependencies: pnpm keeps those in web/node_modules).
        if directory.is_dir() {
            println!("cargo::rerun-if-changed={}", directory.display());
        } else if let Some(parent) = directory.parent().filter(|parent| parent.is_dir()) {
            println!("cargo::rerun-if-changed={}", parent.display());
        }
        let mut files = Vec::new();
        if directory.is_dir() {
            collect(&directory, &directory, &mut files);
        }
        files.sort();
        let _ = writeln!(code, "pub(crate) static {table}: &[(&str, &[u8])] = &[");
        for (path, file) in files {
            let _ = writeln!(code, "    ({path:?}, include_bytes!({:?})),", file.display().to_string());
        }
        code.push_str("];\n");
    }
    let target = out.join("builds.rs");
    if std::fs::read_to_string(&target).ok().as_deref() != Some(code.as_str()) {
        std::fs::write(&target, code).expect("writing builds.rs");
    }
}

/// Every file below `directory`, with its path relative to `root` (with `/`, as in URLs); hidden files are left out.
fn collect(root: &Path, directory: &Path, files: &mut Vec<(String, PathBuf)>) {
    let entries = std::fs::read_dir(directory).unwrap_or_else(|e| panic!("reading {}: {e}", directory.display()));
    for entry in entries {
        let entry = entry.expect("a directory entry");
        let path = entry.path();
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect(root, &path, files);
        } else if path.is_file() {
            let relative = path.strip_prefix(root).expect("below the root");
            let parts: Vec<String> =
                relative.components().map(|part| part.as_os_str().to_string_lossy().into_owned()).collect();
            files.push((parts.join("/"), path));
        }
    }
}
