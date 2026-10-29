// SPDX-License-Identifier: AGPL-3.0-or-later
//! Modules: the parts of kernoid that connect it to one particular outside service (Jitsi, WOPI, virus scanning …).
//!
//! Modules are maintained in this repository and compiled in. Each is off unless the configuration switches it on
//! (`[modules.<name>] enabled = true`); a module that is off gets no routes and runs no jobs – it opens no ports and
//! does nothing in the background. Whether a tenant uses a module that is on is decided per tenant (with the tenant
//! aggregate). Services of others do not become modules: they connect from outside, through actions and hooks.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use axum::Router;
use futures_util::future::BoxFuture;
use kernoid_events::EventStore;
use kernoid_store::{BlobStore, PgPool};
use tokio_util::sync::CancellationToken;

pub use tokio_util::sync::CancellationToken as Shutdown;

/// What a module works with.
#[derive(Debug, Clone)]
pub struct Context {
    pub db: PgPool,
    pub events: EventStore,
    pub blobs: BlobStore,
    /// The module's own configuration: its `[modules.<name>]` table without `enabled`.
    pub config: toml::Table,
}

/// A background job: runs until `shutdown` is cancelled, then returns.
pub type Job = Box<dyn FnOnce(CancellationToken) -> BoxFuture<'static, Result<(), String>> + Send>;

pub trait Module: Send + Sync + 'static {
    /// Stable name: the configuration table `[modules.<name>]` and the path `/modules/<name>/`.
    fn name(&self) -> &'static str;

    /// Checks the module's configuration before anything starts.
    fn check(&self, _config: &toml::Table) -> Result<(), String> {
        Ok(())
    }

    /// HTTP routes, served below `/modules/<name>/` by processes with the `api` role.
    fn routes(&self, _context: &Context) -> Option<Router> {
        None
    }

    /// Background jobs, run by processes with the `worker` role.
    fn jobs(&self, _context: &Context) -> Vec<Job> {
        Vec::new()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("[modules.{0}]: there is no such module")]
    Unknown(String),
    #[error("[modules.{0}]: enabled must be true or false")]
    Enabled(String),
    #[error("[modules.{name}]: {message}")]
    Config { name: String, message: String },
}

/// The modules switched on for this installation, with their configuration.
pub struct Registry {
    enabled: Vec<(&'static dyn Module, toml::Table)>,
}

impl fmt::Debug for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.names()).finish()
    }
}

impl Registry {
    /// Picks from `available` the modules that `config` (the `[modules]` table) switches on. A table for a module
    /// that does not exist is an error, so that a misspelt name does not silently leave a module off.
    pub fn new(available: &[&'static dyn Module], config: &BTreeMap<String, toml::Table>) -> Result<Self, Error> {
        let known: BTreeSet<_> = available.iter().map(|module| module.name()).collect();
        if let Some(unknown) = config.keys().find(|name| !known.contains(name.as_str())) {
            return Err(Error::Unknown(unknown.clone()));
        }
        let mut enabled = Vec::new();
        for module in available {
            let Some(table) = config.get(module.name()) else { continue };
            let mut table = table.clone();
            let on = match table.remove("enabled") {
                None => false,
                Some(toml::Value::Boolean(on)) => on,
                Some(_) => return Err(Error::Enabled(module.name().to_owned())),
            };
            if on {
                module.check(&table).map_err(|message| Error::Config { name: module.name().to_owned(), message })?;
                enabled.push((*module, table));
            }
        }
        Ok(Self { enabled })
    }

    /// No module switched on.
    pub fn none() -> Self {
        Self { enabled: Vec::new() }
    }

    pub fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.enabled.iter().map(|(module, _)| module.name())
    }

    /// The configuration of a module that is on.
    pub fn config(&self, name: &str) -> Option<&toml::Table> {
        self.enabled.iter().find(|(module, _)| module.name() == name).map(|(_, table)| table)
    }

    /// The routes of all modules that are on, each nested below `/modules/<name>`.
    pub fn routes(&self, context: impl Fn(toml::Table) -> Context) -> Router {
        self.enabled.iter().fold(Router::new(), |router, (module, table)| {
            match module.routes(&context(table.clone())) {
                Some(routes) => router.nest(&format!("/modules/{}", module.name()), routes),
                None => router,
            }
        })
    }

    /// The jobs of all modules that are on, named by their module.
    pub fn jobs(&self, context: impl Fn(toml::Table) -> Context) -> Vec<(&'static str, Job)> {
        self.enabled
            .iter()
            .flat_map(|(module, table)| {
                module.jobs(&context(table.clone())).into_iter().map(|job| (module.name(), job))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use axum::{body::Body, http::Request, routing::get};
    use kernoid_store::{TenantKeys, crypto::Key};
    use tower::ServiceExt;

    use super::*;

    /// A module with one route, one job that records that it ran, and a required `greeting` setting.
    struct Echo {
        ran: Arc<AtomicBool>,
    }

    impl Module for Echo {
        fn name(&self) -> &'static str {
            "echo"
        }

        fn check(&self, config: &toml::Table) -> Result<(), String> {
            config.get("greeting").and_then(toml::Value::as_str).map(drop).ok_or_else(|| "greeting is missing".into())
        }

        fn routes(&self, context: &Context) -> Option<Router> {
            let greeting = context.config["greeting"].as_str().unwrap().to_owned();
            Some(Router::new().route("/hello", get(move || async move { greeting })))
        }

        fn jobs(&self, _context: &Context) -> Vec<Job> {
            let ran = self.ran.clone();
            vec![Box::new(move |shutdown: CancellationToken| {
                Box::pin(async move {
                    ran.store(true, Ordering::SeqCst);
                    shutdown.cancelled().await;
                    Ok(())
                })
            })]
        }
    }

    fn echo() -> &'static Echo {
        Box::leak(Box::new(Echo { ran: Arc::new(AtomicBool::new(false)) }))
    }

    fn config(toml: &str) -> BTreeMap<String, toml::Table> {
        toml::from_str(toml).unwrap()
    }

    fn context(table: toml::Table) -> Context {
        let db = sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://nobody@127.0.0.1:1/none").unwrap();
        let keys = Arc::new(TenantKeys::new(db.clone(), Key::random().unwrap()));
        let blobs = BlobStore::from_config(&kernoid_config::Blob::Memory, keys).unwrap();
        Context { events: EventStore::new(db.clone()), db, blobs, config: table }
    }

    async fn status(router: Router, path: &str) -> u16 {
        router.oneshot(Request::get(path).body(Body::empty()).unwrap()).await.unwrap().status().as_u16()
    }

    #[tokio::test]
    async fn modules_are_off_unless_switched_on() {
        let module = echo();
        for toml in ["", "[echo]\ngreeting = \"hi\"", "[echo]\nenabled = false\ngreeting = \"hi\""] {
            let registry = Registry::new(&[module], &config(toml)).unwrap();
            assert_eq!(registry.names().count(), 0, "{toml:?}");
            assert_eq!(status(registry.routes(context), "/modules/echo/hello").await, 404);
            assert!(registry.jobs(context).is_empty());
        }
        assert!(!module.ran.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_module_that_is_on_serves_and_works() {
        let module = echo();
        let registry = Registry::new(&[module], &config("[echo]\nenabled = true\ngreeting = \"hi\"")).unwrap();
        assert_eq!(registry.names().collect::<Vec<_>>(), ["echo"]);
        assert_eq!(status(registry.routes(context), "/modules/echo/hello").await, 200);

        let shutdown = CancellationToken::new();
        let tasks: Vec<_> =
            registry.jobs(context).into_iter().map(|(_, job)| tokio::spawn(job(shutdown.clone()))).collect();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(module.ran.load(Ordering::SeqCst));
        shutdown.cancel();
        for task in tasks {
            task.await.unwrap().unwrap();
        }
    }

    #[test]
    fn configuration_mistakes_are_refused() {
        let module = echo();
        assert_eq!(
            Registry::new(&[module], &config("[ecco]\nenabled = true")).unwrap_err(),
            Error::Unknown("ecco".into())
        );
        assert_eq!(
            Registry::new(&[module], &config("[echo]\nenabled = \"yes\"")).unwrap_err(),
            Error::Enabled("echo".into())
        );
        assert_eq!(
            Registry::new(&[module], &config("[echo]\nenabled = true")).unwrap_err(),
            Error::Config { name: "echo".into(), message: "greeting is missing".into() }
        );
    }
}
