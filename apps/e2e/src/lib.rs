// SPDX-License-Identifier: MIT
//! End-to-end encryption of kernoid's apps (RFC 0006): an account's OpenPGP key and the protected copies of its
//! secret key (`keys`), encrypting and decrypting data (`message`), mail as PGP/MIME with header protection and the
//! summary the apps show in lists (`mime`). All of it is rpgp; nothing here is cryptography of its own.

pub mod keys;
pub mod message;
pub mod mime;
#[cfg(feature = "wasm")]
mod wasm;

pub use keys::{Kind, PublicKey, SecretKey};

/// What can go wrong. Decryption failures are one `Decrypt` – which key or packet failed is not for the user.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not an OpenPGP key: {0}")]
    Key(String),
    #[error("the key has no usable subkey for encryption")]
    NoEncryptionKey,
    #[error("wrong passphrase, or the protected key is damaged")]
    Unlock,
    #[error("cannot decrypt the message with these keys")]
    Decrypt,
    #[error("not an encrypted message")]
    NotEncrypted,
    #[error("not a mail message")]
    NotMail,
    #[error("OpenPGP: {0}")]
    Pgp(String),
}

impl From<pgp::errors::Error> for Error {
    fn from(error: pgp::errors::Error) -> Self {
        Error::Pgp(error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
