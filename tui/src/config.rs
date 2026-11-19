// SPDX-License-Identifier: AGPL-3.0-or-later
//! Settings from `~/.config/kernoid/tui.toml` (or `$XDG_CONFIG_HOME`, or `KERNOID_TUI_CONFIG`) and the command
//! line, and the password: from `KERNOID_PASSWORD`, from a command (a password manager or the system keychain), or
//! asked for – never from an argument; likewise the recovery code of the account's key (`KERNOID_RECOVERY_CODE`).

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    /// The address to log in with.
    pub address: Option<String>,
    /// The server (`https://login.example.org`); without it, the domain of the address.
    pub server: Option<String>,
    /// A command that prints the password, e.g. `security find-generic-password -s kernoid -w`.
    pub password_command: Option<String>,
    /// Where downloads go; default the user's download directory.
    pub downloads: Option<PathBuf>,
    /// Allow plain HTTP to other hosts than this machine.
    #[serde(default)]
    pub allow_http: bool,
}

/// Where the settings file is.
pub fn path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("KERNOID_TUI_CONFIG") {
        return Some(PathBuf::from(path));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join("kernoid").join("tui.toml"))
}

/// Reads the settings file; none is no error.
pub fn load(path: Option<&Path>) -> Result<File, String> {
    let Some(path) = path else { return Ok(File::default()) };
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(File::default()),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// The download directory: the configured one, the user's, or the current one.
pub fn downloads(configured: Option<PathBuf>) -> PathBuf {
    configured
        .or_else(|| directories::UserDirs::new().and_then(|dirs| dirs.download_dir().map(Path::to_path_buf)))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// The password: `KERNOID_PASSWORD`, the output of `command` (its first line), or asked for on the terminal.
pub fn password(command: Option<&str>, address: &str) -> Result<String, String> {
    if let Ok(password) = std::env::var("KERNOID_PASSWORD")
        && !password.is_empty()
    {
        return Ok(password);
    }
    if let Some(command) = command {
        let output = shell(command).output().map_err(|error| format!("the password command: {error}"))?;
        if !output.status.success() {
            return Err(format!("the password command failed ({})", output.status));
        }
        let text = String::from_utf8(output.stdout).map_err(|_| "the password command printed no text".to_owned())?;
        let password = text.lines().next().unwrap_or_default().to_owned();
        if password.is_empty() {
            return Err("the password command printed nothing".into());
        }
        return Ok(password);
    }
    rpassword::prompt_password(format!("App password for {address}: ")).map_err(|error| error.to_string())
}

/// The recovery code that unlocks the account's key for end-to-end encryption (RFC 0006, 4.2), from
/// `KERNOID_RECOVERY_CODE` – else the app asks for it when it needs it. Never from an argument.
pub fn recovery_code() -> Option<String> {
    std::env::var("KERNOID_RECOVERY_CODE").ok().filter(|code| !code.trim().is_empty())
}

/// A command line run by the shell.
pub fn shell(command: &str) -> Command {
    if cfg!(windows) {
        let mut out = Command::new("cmd");
        out.args(["/C", command]);
        out
    } else {
        let mut out = Command::new("sh");
        out.args(["-c", command]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file() {
        let file: File = toml::from_str(
            "address = \"a@x.example\"\nserver = \"https://login.x.example\"\npassword_command = \"pass kernoid\"\n",
        )
        .unwrap();
        assert_eq!(file.address.as_deref(), Some("a@x.example"));
        assert!(!file.allow_http);
        assert!(toml::from_str::<File>("password = \"no\"").is_err());
    }
}
