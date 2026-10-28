// SPDX-License-Identifier: MIT
//! kernoid in the terminal: mail, files, calendars and contacts over JMAP. The protocol layer (`jmap`) and the
//! writing of messages (`compose`) are a library, so they can be tested apart from the screen.

pub mod compose;
pub mod config;
pub mod forms;
pub mod jmap;
