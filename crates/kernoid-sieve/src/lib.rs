// SPDX-License-Identifier: AGPL-3.0-or-later
//! kernoid's Sieve interpreter, written from the RFCs.
//!
//! A script is compiled once ([`Script::compile`]) – errors carry the line and column – and run on a message
//! ([`Script::run`]), which gives the actions to carry out ([`Outcome`]). Running has no side effects: what the
//! interpreter must ask about the world (does a mailbox exist, was a message seen before) goes through
//! [`Environment`], and what it decides is up to the caller to do.
//!
//! Supported: the base language of RFC 5228 (with `encoded-character`, `fileinto`, `envelope`), `reject` and
//! `ereject` (RFC 5429), `imap4flags` (RFC 5232), `variables` (RFC 5229), `vacation` (RFC 5230) with
//! `vacation-seconds` (RFC 6131), `relational` (RFC 5231) with `comparator-i;ascii-numeric` (RFC 4790), `body`
//! (RFC 5173), `copy` (RFC 3894), `date` and `index` (RFC 5260), `mailbox` (RFC 5490), `subaddress` (RFC 5233),
//! `enotify` (RFC 5435: the action and its tests) and `duplicate` (RFC 7352). See [`CAPABILITIES`].
//!
//! Limits ([`Limits`]) bound the size of a script, its nesting, the work a run may do, the actions it may take and
//! the variables it may keep, so that a script cannot keep a delivery busy or flood anyone.

mod compile;
mod lexer;
mod matching;
mod message;
mod parser;
mod run;
mod strings;
mod vacation;

use std::fmt;

pub use run::{Action, Notify, Vacation};

/// The capabilities `require` accepts – what ManageSieve would announce as `SIEVE`.
pub const CAPABILITIES: &[&str] = &[
    "fileinto",
    "reject",
    "ereject",
    "envelope",
    "encoded-character",
    "comparator-i;octet",
    "comparator-i;ascii-casemap",
    "comparator-i;ascii-numeric",
    "imap4flags",
    "variables",
    "vacation",
    "vacation-seconds",
    "relational",
    "body",
    "copy",
    "date",
    "index",
    "mailbox",
    "subaddress",
    "enotify",
    "duplicate",
];

/// Limits against scripts that would take too much.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The largest script compiled, in bytes.
    pub max_script_size: usize,
    /// How deep blocks and test lists may be nested.
    pub max_nesting: usize,
    /// The work a run may do: every command, test and comparison costs, long values more.
    pub max_instructions: u64,
    /// Actions a run may take, the implicit keep not counted.
    pub max_actions: usize,
    /// Addresses a run may redirect to.
    pub max_redirects: usize,
    /// Variables a run may set.
    pub max_variables: usize,
    /// The longest value of a variable, in bytes; longer ones are cut.
    pub max_variable_size: usize,
    /// The longest string after variables are put in, in bytes; longer ones are cut.
    pub max_string_size: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_script_size: 64 * 1024,
            max_nesting: 32,
            max_instructions: 250_000,
            max_actions: 64,
            max_redirects: 5,
            max_variables: 128,
            max_variable_size: 4096,
            max_string_size: 64 * 1024,
        }
    }
}

/// A place in a script: line and column, both from 1 (the column counts characters).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Position {
    pub line: u32,
    pub column: u32,
}

/// Why a script does not compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    /// Where, if the error is at one place of the script.
    pub position: Option<Position>,
    pub message: String,
}

impl CompileError {
    pub(crate) fn at(position: Position, message: impl Into<String>) -> Self {
        CompileError { position: Some(position), message: message.into() }
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.position {
            Some(Position { line, column }) => write!(f, "line {line}, column {column}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for CompileError {}

/// Why a run failed; the caller then keeps the message (RFC 5228, 2.10.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeError {
    pub message: String,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RuntimeError {}

/// A compiled script.
#[derive(Debug, Clone)]
pub struct Script {
    pub(crate) commands: Vec<compile::Command>,
    pub(crate) limits: Limits,
}

impl Script {
    /// Compiles `source` within `limits`, which the runs keep.
    pub fn compile(source: &str, limits: &Limits) -> Result<Script, CompileError> {
        if source.len() > limits.max_script_size {
            return Err(CompileError {
                position: None,
                message: format!("the script has more than {} bytes", limits.max_script_size),
            });
        }
        let tokens = lexer::tokenize(source)?;
        let commands = parser::parse(tokens, limits.max_nesting)?;
        let commands = compile::compile(commands)?;
        Ok(Script { commands, limits: *limits })
    }

    /// Runs the script on the raw message `message`.
    pub fn run(
        &self,
        message: &[u8],
        context: &Context<'_>,
        environment: &mut dyn Environment,
    ) -> Result<Outcome, RuntimeError> {
        run::run(self, message, context, environment)
    }
}

/// What a run knows about the delivery.
#[derive(Debug, Clone)]
pub struct Context<'a> {
    /// The envelope's sender (`MAIL FROM`), empty for a bounce.
    pub envelope_from: &'a str,
    /// The envelope's recipient (`RCPT TO`) this delivery is for.
    pub envelope_to: &'a str,
    /// The recipient's own addresses, for `vacation` (RFC 5230, 4.5); the first is the reply's sender. Empty: the
    /// envelope's recipient.
    pub user_addresses: Vec<String>,
    /// Now, in seconds since the Unix epoch – for `currentdate` and the vacation reply's `Date`.
    pub now: i64,
    /// The time zone `date` and `currentdate` use without `:zone`, in seconds east of UTC.
    pub zone: i32,
}

impl<'a> Context<'a> {
    /// A delivery from `envelope_from` to `envelope_to`, now, in UTC.
    pub fn new(envelope_from: &'a str, envelope_to: &'a str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| i64::try_from(since.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or_default();
        Context { envelope_from, envelope_to, user_addresses: Vec::new(), now, zone: 0 }
    }
}

/// What a run asks about the world.
pub trait Environment {
    /// Whether the mailbox `name` exists (`mailboxexists`, RFC 5490).
    fn mailbox_exists(&self, name: &str) -> bool {
        let _ = name;
        false
    }

    /// Whether `key` was seen within `seconds` (`duplicate`, RFC 7352); `last` says to count from the last time it
    /// was seen rather than the first. It is the environment's to remember it when the run succeeds.
    fn duplicate(&mut self, key: &str, seconds: u64, last: bool) -> bool {
        let _ = (key, seconds, last);
        false
    }
}

/// An environment where no mailbox exists and nothing was seen before.
impl Environment for () {}

/// What a run decided.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// In the order the script took them; the implicit keep, if it held, comes last as a [`Action::Keep`]. Without
    /// any keep or `fileinto`, the message is not stored.
    pub actions: Vec<Action>,
}
