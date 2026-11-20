// SPDX-License-Identifier: AGPL-3.0-or-later
//! Builds the login UI and the web app (`web/login/dist`, `web/app/dist`, from `pnpm build`) into the binary: one
//! table of paths and their content per build, each file taken with `include_bytes!`, so that it is built in again
//! when it changes. A build of kernoid without them gets empty tables (and answers 404 at `/login` and `/app`).

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

/// The tables `login_ui.rs` includes: their names and the directories they hold, from this crate's directory.
const BUILDS: [(&str, &str); 3] =
    [("LOGIN_UI", "../../web/login/dist"), ("WEB_APP", "../../web/app/dist"), ("FIXTURE", "src/testdata/login-ui")];

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("set by Cargo"));
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("set by Cargo"));
    let mut code = String::from("// Written by build.rs.\n");
    for (name, directory) in BUILDS {
        let directory = manifest.join(directory);
        // A directory is watched with everything in it; one that does not exist yet, through its parent (which
        // holds the build's sources, not its dependencies: pnpm keeps those in web/node_modules).
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
        // The fixture is for the tests alone.
        if name == "FIXTURE" {
            code.push_str("#[cfg(test)]\n");
        }
        let _ = writeln!(code, "pub(crate) static {name}: &[(&str, &[u8])] = &[");
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
