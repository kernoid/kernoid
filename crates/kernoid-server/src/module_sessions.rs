// SPDX-License-Identifier: AGPL-3.0-or-later
//! The core's logins for the routes of modules (`kernoid_module::Sessions`): the session of the instance a request is
//! for, from its cookie – with the same CSRF check as every other route – or its bearer token.

use futures_util::future::BoxFuture;
use kernoid_module::{Caller, Sessions};

use crate::{AppState, Client, instance::of_request};

#[derive(Debug, Clone)]
pub struct ModuleSessions(AppState);

impl ModuleSessions {
    pub fn new(state: AppState) -> Self {
        Self(state)
    }
}

impl Sessions for ModuleSessions {
    fn caller<'a>(&'a self, request: &'a axum::http::request::Parts) -> BoxFuture<'a, Option<Caller>> {
        Box::pin(async move {
            let state = &self.0;
            let client = request.extensions.get::<Client>();
            let instance = of_request(&state.identity, client).await.ok()??;
            let token = crate::cookie::session_token(state, &request.method, &request.headers, Some(&instance)).ok()?;
            let account = state.identity.session(instance.id, &token).await.ok()?.account;
            // An account of another instance does not use this one.
            (account.instance == instance.id).then(|| Caller {
                account: account.id,
                tenant: account.tenant,
                instance: instance.id,
                display_name: account.display_name,
                address: account.address,
                base: state.oidc.issuer(&instance.primary_domain),
            })
        })
    }
}
