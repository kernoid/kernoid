// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reading a secret from the terminal without showing it: the terminal's echo is off while a [`NoEcho`] lives, and
//! back as it was when it is dropped – also when reading fails or panics.

/// The terminal of standard input with its echo turned off.
#[derive(Debug)]
pub struct NoEcho {
    #[cfg(unix)]
    before: rustix::termios::Termios,
}

impl NoEcho {
    /// Turns the echo of standard input off; it must be a terminal.
    #[cfg(unix)]
    pub fn on_stdin() -> std::io::Result<Self> {
        use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};
        let stdin = std::io::stdin();
        let before = tcgetattr(&stdin)?;
        let mut quiet = before.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        tcsetattr(&stdin, OptionalActions::Flush, &quiet)?;
        Ok(Self { before })
    }

    /// kernoid's server runs on Unix only; elsewhere the secret is read as typed.
    #[cfg(not(unix))]
    pub fn on_stdin() -> std::io::Result<Self> {
        Ok(Self {})
    }
}

#[cfg(unix)]
impl Drop for NoEcho {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(std::io::stdin(), rustix::termios::OptionalActions::Now, &self.before);
    }
}
