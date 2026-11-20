// SPDX-License-Identifier: AGPL-3.0-or-later
//! kernoid's login UI and web app (`web/login`, `web/app`), built: each a table of its files' paths (relative, with
//! `/`, sorted) and contents, made by `build.rs` with `include_bytes!` – so the binary is rebuilt when a file changes.
//! A table is empty when there was no build (a `cargo build` without `pnpm build` in `web/`); kernoid-server then
//! answers 404 at `/login` and `/app`.

mod builds {
    include!(concat!(env!("OUT_DIR"), "/builds.rs"));
}

/// The files of a build: paths relative to its root, sorted, with their contents.
pub type Files = &'static [(&'static str, &'static [u8])];

/// The login UI (`web/login`), served at `/login`.
pub static LOGIN_UI: Files = builds::LOGIN_UI;

/// The web app (`web/app`), served at `/app`.
pub static WEB_APP: Files = builds::WEB_APP;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tables_are_sorted_for_a_binary_search() {
        for files in [LOGIN_UI, WEB_APP] {
            assert!(files.windows(2).all(|pair| pair[0].0 < pair[1].0));
            assert!(files.iter().all(|(path, _)| !path.starts_with('/') && !path.contains('\\')));
        }
    }
}
