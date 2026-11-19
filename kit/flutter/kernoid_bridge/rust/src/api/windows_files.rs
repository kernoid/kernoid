// SPDX-License-Identifier: MIT
//! kernoid's stores in Windows' Explorer (docs/plan.md, 5), started and stopped from the app. The shell has a login of
//! its own – set up once with kernoid's login page, then kept in `state_dir` protected with DPAPI – and never the
//! app's: kernoid rotates refresh tokens, and two holders renewing one would end it. Elsewhere these do nothing.

use flutter_rust_bridge::frb;

use crate::api::kernoid::KernoidError;
use crate::provider::cloud_files;

/// How the shell in Explorer is doing.
#[derive(Debug, Clone)]
pub struct WindowsFilesStatus {
    pub running: bool,
    /// The folders in Explorer, one per store.
    pub folders: Vec<String>,
    /// What failed lately, for people.
    pub problems: Vec<String>,
    /// The shell's login has ended: set it up again.
    pub signed_out: bool,
    /// When kernoid was last asked what changed (RFC 3339).
    pub last_round: Option<String>,
}

/// Whether this system has Explorer's cloud files (Windows).
#[frb(sync)]
pub fn windows_files_available() -> bool {
    cfg!(windows)
}

/// Whether the shell was set up in `state_dir` – it has a login of its own there.
#[frb(sync)]
pub fn windows_files_configured(state_dir: String) -> bool {
    cloud_files::configured(&state_dir)
}

/// Shows the stores in Explorer as folders below `root_dir`, kept in step while the app runs. `kept` is a login made
/// for the shell just now (the app forgets it after handing it over); none resumes the one kept in `state_dir`.
/// Returns the folders.
pub fn windows_files_start(
    kept: Option<String>,
    root_dir: String,
    state_dir: String,
) -> Result<Vec<String>, KernoidError> {
    #[cfg(windows)]
    {
        // A thread of its own: the core waits on its runtime, which must not be entered from another.
        std::thread::spawn(move || cloud_files::system::start(kept.as_deref(), &root_dir, &state_dir))
            .join()
            .map_err(|_| KernoidError { unauthorized: false, message: "the Explorer shell failed".into() })?
            .map_err(|f| KernoidError { unauthorized: f.unauthorized, message: f.message })
    }
    #[cfg(not(windows))]
    {
        let _ = (kept, root_dir, state_dir);
        Ok(Vec::new())
    }
}

/// Stops the shell. With `forget` the folders are no longer cloud folders – what was downloaded stays – and the
/// shell's login and state are dropped.
pub fn windows_files_stop(state_dir: String, forget: bool) -> Result<(), KernoidError> {
    #[cfg(windows)]
    {
        std::thread::spawn(move || cloud_files::system::stop(&state_dir, forget))
            .join()
            .map_err(|_| KernoidError { unauthorized: false, message: "the Explorer shell failed".into() })?
            .map_err(|f| KernoidError { unauthorized: f.unauthorized, message: f.message })
    }
    #[cfg(not(windows))]
    {
        let _ = (state_dir, forget);
        Ok(())
    }
}

#[frb(sync)]
pub fn windows_files_status() -> WindowsFilesStatus {
    let s = cloud_files::status();
    WindowsFilesStatus {
        running: s.running,
        folders: s.folders,
        problems: s.problems,
        signed_out: s.signed_out,
        last_round: s.last_round,
    }
}
