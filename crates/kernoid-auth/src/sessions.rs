// SPDX-License-Identifier: AGPL-3.0-or-later
//! The program's own sessions after a login: who is behind a session id (the cookie of its web app), until when, and
//! which login at the provider it came from – so that the provider's back-channel logout ends it. Kept behind a
//! trait, so that a program keeps them in its own database; [`MemorySessions`] keeps them in the process.

use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::relying::{Login, Principal};

/// How long a session of the program lasts by default.
pub const SESSION_LIFETIME: SignedDuration = SignedDuration::from_hours(8);

/// A session of the program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub principal: Principal,
    /// For logging out at the provider (`id_token_hint`).
    pub id_token: String,
    pub expires_at: Timestamp,
}

impl Session {
    pub fn new(login: Login, lifetime: SignedDuration) -> Self {
        Self { principal: login.principal, id_token: login.id_token, expires_at: Timestamp::now() + lifetime }
    }

    pub fn expired(&self) -> bool {
        self.expires_at <= Timestamp::now()
    }
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Where a program keeps its sessions. Ids are random and secret; implementations should keep only their hash.
pub trait Sessions: Send + Sync + std::fmt::Debug + 'static {
    fn put<'a>(&'a self, id: &'a str, session: Session) -> BoxFuture<'a, ()>;
    /// The session, unless it has expired.
    fn get<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Option<Session>>;
    fn remove<'a>(&'a self, id: &'a str) -> BoxFuture<'a, ()>;
    /// Ends the sessions a back-channel logout names: those of the provider's login `session`, or all of `subject`.
    fn remove_logins<'a>(&'a self, subject: Option<&'a str>, session: Option<&'a str>) -> BoxFuture<'a, usize>;
}

/// Sessions in the process: lost on restart, not shared between processes – for one process, and for tests.
#[derive(Debug, Clone, Default)]
pub struct MemorySessions {
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

impl MemorySessions {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Sessions for MemorySessions {
    fn put<'a>(&'a self, id: &'a str, session: Session) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut sessions = self.sessions.lock().await;
            sessions.retain(|_, session| !session.expired());
            sessions.insert(id.to_owned(), session);
        })
    }

    fn get<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Option<Session>> {
        Box::pin(async move { self.sessions.lock().await.get(id).filter(|session| !session.expired()).cloned() })
    }

    fn remove<'a>(&'a self, id: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.sessions.lock().await.remove(id);
        })
    }

    fn remove_logins<'a>(&'a self, subject: Option<&'a str>, session: Option<&'a str>) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            let mut sessions = self.sessions.lock().await;
            let before = sessions.len();
            sessions.retain(|_, kept| {
                let principal = &kept.principal;
                let named = match (subject, session) {
                    (_, Some(sid)) => principal.session.as_deref() == Some(sid),
                    (Some(sub), None) => principal.subject == sub,
                    (None, None) => false,
                };
                !named
            });
            before - sessions.len()
        })
    }
}
