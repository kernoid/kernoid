// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relay's administration in GraphQL (RFC 0010, 4) – the same checks as the REST routes in `crate::relay`.

use async_graphql::{Context, Object, SimpleObject};
use kernoid_identity::{IdentityError, role::Permission};

use super::{DateTime, admin::admin, error};
use crate::AppState;

/// The relay – only where the installation has the service `relay` (RFC 0008, 4).
fn relay<'a>(context: &'a Context<'_>) -> async_graphql::Result<&'a kernoid_relay::Relay> {
    let state = context.data::<AppState>()?;
    match (&state.relay, state.services.relay) {
        (Some(relay), true) => Ok(relay),
        _ => Err(crate::graphql::service_off("relay")),
    }
}

fn store(failure: sqlx::Error) -> async_graphql::Error {
    error(IdentityError::Store(failure.into()))
}

/// An end-to-end encrypted space on the relay, as its tenant's administrators see it – never its content.
#[derive(SimpleObject)]
pub struct RelaySpace {
    space: String,
    /// The program whose space it is: `kernoid`, `aktujo` …
    domain: String,
    founder: Option<String>,
    bytes: i64,
    created_at: DateTime,
    written_at: DateTime,
}

#[derive(Default)]
pub struct RelayQuery;

#[Object]
impl RelayQuery {
    /// The tenant's spaces on this relay, newest first (needs `directory.read`).
    async fn relay_spaces(&self, context: &Context<'_>) -> async_graphql::Result<Vec<RelaySpace>> {
        let relay = relay(context)?;
        let (_, admin) = admin(context).await?;
        admin.require(Permission::DirectoryRead).map_err(error)?;
        Ok(relay
            .spaces(admin.tenant())
            .await
            .map_err(store)?
            .into_iter()
            .map(|info| RelaySpace {
                space: info.space,
                domain: info.domain,
                founder: info.founder.map(|id| id.to_string()),
                bytes: info.bytes,
                created_at: DateTime(info.created_at),
                written_at: DateTime(info.written_at),
            })
            .collect())
    }
}

#[derive(Default)]
pub struct RelayMutation;

#[Object]
impl RelayMutation {
    /// Removes a space of the tenant with everything it holds (needs `tenant.manage`); false if there is none.
    async fn remove_relay_space(&self, context: &Context<'_>, space: String) -> async_graphql::Result<bool> {
        let relay = relay(context)?;
        let (_, admin) = admin(context).await?;
        admin.require(Permission::TenantManage).map_err(error)?;
        relay.remove_space(admin.tenant(), &space).await.map_err(store)
    }
}
