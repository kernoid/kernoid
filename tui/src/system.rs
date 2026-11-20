// SPDX-License-Identifier: AGPL-3.0-or-later
//! What the terminal app asks of the system, in kernoid's own code: the system's key store (`get_secret`,
//! `set_secret`: the Keychain on macOS through security-framework, the Credential Manager on Windows, the Secret Service
//! over D-Bus elsewhere – [`crate::dbus`]), reading a password without showing it (`read_hidden`: termios on Unix, the
//! console's mode on Windows) and the user's download directory (`download_dir`).
//!
//! The only unsafe code of the app is here – calls of the C interfaces of termios (libc) and of Windows (windows-sys),
//! each with what it relies on.
#![allow(unsafe_code, reason = "termios and the Windows API are C interfaces; each call says what it relies on")]

use std::path::PathBuf;

/// The secret kept for `service` and `account` in the system's key store, if there is one.
pub fn get_secret(service: &str, account: &str) -> Result<Option<Vec<u8>>, String> {
    store::get(service, account)
}

/// Keeps `secret` for `service` and `account` in the system's key store, replacing what was there.
pub fn set_secret(service: &str, account: &str, secret: &[u8]) -> Result<(), String> {
    store::set(service, account, secret)
}

#[cfg(target_os = "macos")]
mod store {
    use security_framework::passwords::{get_generic_password, set_generic_password};

    /// errSecItemNotFound.
    const NOT_FOUND: i32 = -25300;

    pub fn get(service: &str, account: &str) -> Result<Option<Vec<u8>>, String> {
        match get_generic_password(service, account) {
            Ok(secret) => Ok(Some(secret)),
            Err(error) if error.code() == NOT_FOUND => Ok(None),
            Err(error) => Err(format!("the Keychain: {error}")),
        }
    }

    pub fn set(service: &str, account: &str, secret: &[u8]) -> Result<(), String> {
        set_generic_password(service, account, secret).map_err(|error| format!("the Keychain: {error}"))
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod store {
    use crate::dbus::Secrets;
    use std::collections::BTreeMap;

    /// The attributes of an item: the service and the account, as other programs name them.
    fn attributes(service: &str, account: &str) -> BTreeMap<String, String> {
        BTreeMap::from([("service".to_owned(), service.to_owned()), ("username".to_owned(), account.to_owned())])
    }

    pub fn get(service: &str, account: &str) -> Result<Option<Vec<u8>>, String> {
        Secrets::open()?.get(&attributes(service, account)).map_err(|error| format!("the Secret Service: {error}"))
    }

    pub fn set(service: &str, account: &str, secret: &[u8]) -> Result<(), String> {
        Secrets::open()?
            .set(&format!("{service} ({account})"), &attributes(service, account), secret)
            .map_err(|error| format!("the Secret Service: {error}"))
    }
}

#[cfg(windows)]
mod store {
    use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, GetLastError};
    use windows_sys::Win32::Security::Credentials::{
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW, CredWriteW,
    };

    /// A string as Windows takes it: UTF-16, ended by a zero.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// The name of a credential: `account.service`.
    fn target(service: &str, account: &str) -> Vec<u16> {
        wide(&format!("{account}.{service}"))
    }

    pub fn get(service: &str, account: &str) -> Result<Option<Vec<u8>>, String> {
        let name = target(service, account);
        let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: `name` is a zero-ended UTF-16 string that lives through the call; `credential` is written by the
        // call when it succeeds.
        let found = unsafe { CredReadW(name.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) };
        if found == 0 {
            // SAFETY: reads the calling thread's last error, nothing else.
            let error = unsafe { GetLastError() };
            return if error == ERROR_NOT_FOUND {
                Ok(None)
            } else {
                Err(format!("the Credential Manager: error {error}"))
            };
        }
        // SAFETY: the call succeeded, so `credential` points to a credential whose blob has `CredentialBlobSize`
        // bytes (or is null when there are none); it is freed with `CredFree` once copied, and not used after.
        unsafe {
            let blob = (*credential).CredentialBlob;
            let size = (*credential).CredentialBlobSize as usize;
            let secret = if blob.is_null() { Vec::new() } else { std::slice::from_raw_parts(blob, size).to_vec() };
            CredFree(credential.cast());
            Ok(Some(secret))
        }
    }

    pub fn set(service: &str, account: &str, secret: &[u8]) -> Result<(), String> {
        let mut name = target(service, account);
        let mut user = wide(account);
        let mut blob = secret.to_vec();
        let size = u32::try_from(blob.len()).map_err(|_| "a secret too large".to_owned())?;
        // SAFETY: an all-zero CREDENTIALW is valid (null pointers, no attributes); the fields set below point into
        // `name`, `user` and `blob`, which live through the call. The call copies what it keeps.
        let written = unsafe {
            let mut credential: CREDENTIALW = std::mem::zeroed();
            credential.Type = CRED_TYPE_GENERIC;
            credential.TargetName = name.as_mut_ptr();
            credential.UserName = user.as_mut_ptr();
            credential.CredentialBlobSize = size;
            credential.CredentialBlob = blob.as_mut_ptr();
            credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
            CredWriteW(&credential, 0)
        };
        if written == 0 {
            // SAFETY: reads the calling thread's last error, nothing else.
            return Err(format!("the Credential Manager: error {}", unsafe { GetLastError() }));
        }
        Ok(())
    }
}

/// Asks for a password on the terminal and reads it without showing it.
pub fn read_hidden(prompt: &str) -> Result<String, String> {
    terminal::read_hidden(prompt).map_err(|error| format!("reading the password: {error}"))
}

#[cfg(unix)]
mod terminal {
    use std::io::{BufRead, BufReader, Write};
    use std::os::fd::AsRawFd;

    pub fn read_hidden(prompt: &str) -> std::io::Result<String> {
        // The terminal itself, also when the standard streams are redirected.
        let mut tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty")?;
        let fd = tty.as_raw_fd();
        // SAFETY: an all-zero termios is a valid value to be overwritten; `fd` is open for the whole function.
        let mut settings: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `fd` is an open descriptor and `settings` a valid termios to write to.
        if unsafe { libc::tcgetattr(fd, &mut settings) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let shown = settings;
        settings.c_lflag &= !libc::ECHO;
        // The newline the user types is still shown.
        settings.c_lflag |= libc::ECHONL;
        tty.write_all(prompt.as_bytes())?;
        tty.flush()?;
        // SAFETY: as above; the settings are put back below on every path.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &settings) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut line = String::new();
        let read = BufReader::new(&tty).read_line(&mut line);
        // SAFETY: as above, with the settings read at the start.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &shown) };
        read?;
        Ok(super::without_newline(line))
    }
}

#[cfg(windows)]
mod terminal {
    use std::io::Write;
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
    };

    pub fn read_hidden(prompt: &str) -> std::io::Result<String> {
        // SAFETY: asks for the process's input handle, nothing else.
        let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let mut mode = 0;
        // SAFETY: `input` is the process's input handle; `mode` is written by the call.
        if unsafe { GetConsoleMode(input, &mut mode) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        eprint!("{prompt}");
        std::io::stderr().flush()?;
        // SAFETY: as above; the mode is put back below on every path.
        if unsafe { SetConsoleMode(input, mode & !ENABLE_ECHO_INPUT) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut line = String::new();
        let read = std::io::stdin().read_line(&mut line);
        // SAFETY: as above, with the mode read at the start.
        unsafe { SetConsoleMode(input, mode) };
        eprintln!();
        read?;
        Ok(super::without_newline(line))
    }
}

/// A line read, without its line end.
fn without_newline(mut line: String) -> String {
    while line.ends_with(['\n', '\r']) {
        line.pop();
    }
    line
}

/// The user's download directory, if the system names one.
pub fn download_dir() -> Option<PathBuf> {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)?;
    if cfg!(any(target_os = "macos", windows)) {
        // The place both systems make it in (a Downloads folder moved elsewhere on Windows is not followed).
        return Some(home.join("Downloads"));
    }
    // The XDG user directories: `XDG_DOWNLOAD_DIR` in `$XDG_CONFIG_HOME/user-dirs.dirs`.
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| home.join(".config"));
    let text = std::fs::read_to_string(config.join("user-dirs.dirs")).ok()?;
    user_dir(&text, "XDG_DOWNLOAD_DIR", &home)
}

/// A directory of `user-dirs.dirs`: `NAME="$HOME/…"` or `NAME="/…"`; `$HOME` alone is no download directory.
fn user_dir(text: &str, name: &str, home: &std::path::Path) -> Option<PathBuf> {
    text.lines().filter(|line| !line.trim_start().starts_with('#')).find_map(|line| {
        let value = line.trim().strip_prefix(name)?.trim_start().strip_prefix('=')?.trim();
        let value = value.strip_prefix('"')?.strip_suffix('"')?;
        if let Some(below) = value.strip_prefix("$HOME/") {
            (!below.is_empty()).then(|| home.join(below))
        } else if value.starts_with('/') {
            Some(PathBuf::from(value))
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_directories() {
        let home = std::path::Path::new("/home/a");
        let text = "# written by xdg-user-dirs-update\nXDG_DESKTOP_DIR=\"$HOME/Desktop\"\nXDG_DOWNLOAD_DIR=\"$HOME/Herunterladen\"\n";
        assert_eq!(user_dir(text, "XDG_DOWNLOAD_DIR", home), Some(PathBuf::from("/home/a/Herunterladen")));
        assert_eq!(
            user_dir("XDG_DOWNLOAD_DIR=\"/data/dl\"", "XDG_DOWNLOAD_DIR", home),
            Some(PathBuf::from("/data/dl"))
        );
        assert_eq!(user_dir("XDG_DOWNLOAD_DIR=\"$HOME/\"", "XDG_DOWNLOAD_DIR", home), None);
        assert_eq!(user_dir("#XDG_DOWNLOAD_DIR=\"/x\"", "XDG_DOWNLOAD_DIR", home), None);
        assert_eq!(user_dir("XDG_DOWNLOAD_DIRX=\"/x\"", "XDG_DOWNLOAD_DIR", home), None);
    }

    #[test]
    fn line_ends() {
        assert_eq!(without_newline("secret\r\n".into()), "secret");
        assert_eq!(without_newline("se cret\n".into()), "se cret");
    }

    /// The real key store of this computer – run by hand with `KERNOID_TEST_KEY_STORE=1` (macOS may ask to allow it).
    #[test]
    fn the_key_store() {
        if std::env::var_os("KERNOID_TEST_KEY_STORE").is_none() {
            return;
        }
        let (service, account) = ("kernoid-tui test", "test@kernoid.invalid");
        set_secret(service, account, b"one").unwrap();
        assert_eq!(get_secret(service, account).unwrap().as_deref(), Some(b"one".as_slice()));
        set_secret(service, account, b"two").unwrap();
        assert_eq!(get_secret(service, account).unwrap().as_deref(), Some(b"two".as_slice()));
        assert_eq!(get_secret(service, "nobody@kernoid.invalid").unwrap(), None);
    }
}
