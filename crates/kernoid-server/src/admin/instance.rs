// SPDX-License-Identifier: AGPL-3.0-or-later
//! The instance, for its administrators: name, domains, tenants, instance roles and signing keys.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use kernoid_identity::{DomainName, IdentityError, TenantInfo, role::Role};
use kernoid_oidc::{federation::SamlKeyInfo, keys::KeyInfo};
use serde::{Deserialize, Serialize};

use super::{AdminSession, AssignmentView, created, id, no_content, principal, respond, respond_oidc};
use crate::{AppState, Problem};

fn domain(value: &str) -> Result<DomainName, IdentityError> {
    DomainName::parse(value).map_err(|error| IdentityError::Refused(error.to_string()))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct InstanceDetails {
    id: String,
    name: String,
    primary_domain: String,
    domains: Vec<String>,
    /// The instance's own login UI; without one, kernoid's at `/login`.
    login_ui_url: Option<String>,
    /// The WebAuthn RP ID its passkeys are bound to.
    passkey_rp_id: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct LoginUi {
    /// An HTTPS URL without query or fragment; `null` for kernoid's own.
    url: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct Name {
    name: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct PrimaryDomain {
    domain: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct TenantSummary {
    id: String,
    name: String,
    active: bool,
}

impl From<TenantInfo> for TenantSummary {
    fn from(tenant: TenantInfo) -> Self {
        Self { id: tenant.id.to_string(), name: tenant.name, active: tenant.active }
    }
}

#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub(crate) struct TenantChange {
    name: Option<String>,
    active: Option<bool>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct InstanceRoleView {
    /// `instance_admin`, `instance_auditor`, or one of the instance's own.
    name: String,
    /// At the instance.
    permissions: Vec<String>,
    /// In every tenant of the instance.
    tenant_permissions: Vec<String>,
    builtin: bool,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct InstanceRoleDefinition {
    /// Instance permissions (e.g. `instance.read`), applied at the instance, and tenant permissions (e.g.
    /// `directory.read`), applied in every tenant.
    permissions: Vec<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct PasskeyRpId {
    /// One of the instance's domains or a parent domain of one.
    rp_id: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct InstanceRolesView {
    roles: Vec<InstanceRoleView>,
    assignments: Vec<AssignmentView>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct SigningKeyView {
    kid: String,
    algorithm: String,
    /// `initial` (published, not signing), `active` (signing) or `inactive` (published, no longer signing).
    state: String,
    created_at: DateTime<Utc>,
    state_since: DateTime<Utc>,
}

impl From<KeyInfo> for SigningKeyView {
    fn from(key: KeyInfo) -> Self {
        Self {
            kid: key.kid,
            algorithm: key.algorithm,
            state: key.state.as_str().into(),
            created_at: key.created_at,
            state_since: key.state_since,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct NewKey {
    kid: String,
}

/// The instance with all its domains (needs `instance.read`).
#[utoipa::path(get, path = "/v1/instance/details", tag = "instance",
    responses((status = 200, body = InstanceDetails), (status = 403, body = Problem)))]
pub(crate) async fn details(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond(state.identity.admin_instance(&admin).await, |overview| {
        Json(InstanceDetails {
            id: overview.instance.id.to_string(),
            name: overview.instance.name,
            primary_domain: overview.instance.primary_domain,
            domains: overview.domains,
            login_ui_url: overview.instance.login_ui,
            passkey_rp_id: overview.instance.passkey_rp_id,
        })
        .into_response()
    })
}

/// Renames the instance (needs `instance.manage`).
#[utoipa::path(patch, path = "/v1/instance", tag = "instance", request_body = Name, responses((status = 204)))]
pub(crate) async fn rename(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<Name>,
) -> Response {
    respond(state.identity.admin_rename_instance(&admin, &body.name).await, no_content)
}

/// Reaches the instance under another domain as well (needs `instance.manage`).
#[utoipa::path(put, path = "/v1/instance/domains/{domain}", tag = "instance",
    responses((status = 204), (status = 409, description = "in use", body = Problem)))]
pub(crate) async fn add_domain(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(name): Path<String>,
) -> Response {
    let result = async { state.identity.admin_add_instance_domain(&admin, &domain(&name)?).await }.await;
    respond(result, no_content)
}

/// Removes a domain; not the primary one (needs `instance.manage`).
#[utoipa::path(delete, path = "/v1/instance/domains/{domain}", tag = "instance",
    responses((status = 204), (status = 400, description = "the primary domain", body = Problem)))]
pub(crate) async fn remove_domain(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(name): Path<String>,
) -> Response {
    let result = async { state.identity.admin_remove_instance_domain(&admin, &domain(&name)?).await }.await;
    respond(result, no_content)
}

/// Sets the domain the issuer and links use (needs `instance.manage`). Passkeys are bound to it.
#[utoipa::path(put, path = "/v1/instance/primary-domain", tag = "instance", request_body = PrimaryDomain,
    responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn set_primary_domain(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<PrimaryDomain>,
) -> Response {
    let result = async { state.identity.admin_set_primary_domain(&admin, &domain(&body.domain)?).await }.await;
    respond(result, no_content)
}

/// Sends logins to a login UI of the instance's own, which may then call the API from its origin (needs
/// `instance.manage`).
#[utoipa::path(put, path = "/v1/instance/login-ui", tag = "instance", request_body = LoginUi,
    responses((status = 204), (status = 400, body = Problem)))]
pub(crate) async fn set_login_ui(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<LoginUi>,
) -> Response {
    respond(state.identity.admin_set_login_ui(&admin, body.url.as_deref()).await, no_content)
}

/// The instance's tenants (needs `instance.read`).
#[utoipa::path(get, path = "/v1/instance/tenants", tag = "instance", responses((status = 200, body = [TenantSummary])))]
pub(crate) async fn tenants(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond(state.identity.admin_tenants(&admin).await, |list| {
        Json(list.into_iter().map(TenantSummary::from).collect::<Vec<_>>()).into_response()
    })
}

/// Creates a tenant (needs `tenants.manage`).
#[utoipa::path(post, path = "/v1/instance/tenants", tag = "instance", request_body = Name,
    responses((status = 201, body = super::Created)))]
pub(crate) async fn add_tenant(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<Name>,
) -> Response {
    respond(state.identity.admin_add_tenant(&admin, &body.name).await, created)
}

/// Renames, deactivates or reactivates a tenant (needs `tenants.manage`); not one's own by deactivation.
#[utoipa::path(patch, path = "/v1/instance/tenants/{id}", tag = "instance", request_body = TenantChange,
    responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn change_tenant(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(tenant): Path<String>,
    Json(body): Json<TenantChange>,
) -> Response {
    let result = async {
        let tenant = id(&tenant, "the tenant")?;
        state.identity.admin_update_tenant(&admin, tenant, body.name.as_deref(), body.active).await
    }
    .await;
    respond(result, no_content)
}

/// The instance roles and who holds them (needs `instance.read`).
#[utoipa::path(get, path = "/v1/instance/roles", tag = "instance", responses((status = 200, body = InstanceRolesView)))]
pub(crate) async fn roles(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    let result = async {
        let roles = state.identity.admin_instance_roles(&admin).await?;
        Ok((roles, state.identity.admin_instance_role_assignments(&admin).await?))
    }
    .await;
    respond(result, |(roles, assignments)| {
        Json(InstanceRolesView {
            roles: roles
                .into_iter()
                .map(|info| InstanceRoleView {
                    name: info.role.to_string(),
                    permissions: info.permissions.iter().map(ToString::to_string).collect(),
                    tenant_permissions: info.tenant_permissions.iter().map(ToString::to_string).collect(),
                    builtin: info.builtin,
                })
                .collect(),
            assignments: assignments.into_iter().map(|a| AssignmentView::new(a.principal, a.role)).collect(),
        })
        .into_response()
    })
}

/// Defines an instance role of the instance's own, or changes its permissions (needs `instance_roles.manage`).
#[utoipa::path(put, path = "/v1/instance/roles/{role}", tag = "instance", request_body = InstanceRoleDefinition,
    responses((status = 204), (status = 400, description = "a built-in role, or no permission", body = Problem)))]
pub(crate) async fn define_role(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(role): Path<String>,
    Json(body): Json<InstanceRoleDefinition>,
) -> Response {
    let result = async {
        let permissions = super::directory::permissions(&body.permissions)?;
        state.identity.admin_define_instance_role(&admin, &Role::parse(&role)?, &permissions).await
    }
    .await;
    respond(result, no_content)
}

/// Deletes an instance role of the instance's own, once nobody holds it (needs `instance_roles.manage`).
#[utoipa::path(delete, path = "/v1/instance/roles/{role}", tag = "instance",
    responses((status = 204), (status = 400, description = "still assigned", body = Problem)))]
pub(crate) async fn delete_role(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(role): Path<String>,
) -> Response {
    let result = async { state.identity.admin_delete_instance_role(&admin, &Role::parse(&role)?).await }.await;
    respond(result, no_content)
}

/// Binds passkeys to another RP ID – one of the instance's domains or a parent domain of one (needs
/// `instance.manage`). Passkeys registered under the former RP ID stop working.
#[utoipa::path(put, path = "/v1/instance/passkey-rp-id", tag = "instance", request_body = PasskeyRpId,
    responses((status = 204), (status = 400, body = Problem)))]
pub(crate) async fn set_passkey_rp_id(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<PasskeyRpId>,
) -> Response {
    let result = async { state.identity.admin_set_passkey_rp_id(&admin, &domain(&body.rp_id)?).await }.await;
    respond(result, no_content)
}

/// Assigns an instance role to an account or group of any tenant of the instance (needs `instance_roles.manage`).
#[utoipa::path(put, path = "/v1/instance/roles/{role}/{kind}/{id}", tag = "instance",
    responses((status = 204), (status = 403, body = Problem)))]
pub(crate) async fn grant_role(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((role, kind, holder)): Path<(String, String, String)>,
) -> Response {
    let result = async {
        let role = Role::parse(&role)?;
        state.identity.admin_grant_instance_role(&admin, principal(&kind, &holder)?, &role).await
    }
    .await;
    respond(result, no_content)
}

/// Takes an instance role back; the last `instance_admin` stays (needs `instance_roles.manage`).
#[utoipa::path(delete, path = "/v1/instance/roles/{role}/{kind}/{id}", tag = "instance",
    responses((status = 204), (status = 400, body = Problem)))]
pub(crate) async fn revoke_role(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((role, kind, holder)): Path<(String, String, String)>,
) -> Response {
    let result = async {
        let role = Role::parse(&role)?;
        state.identity.admin_revoke_instance_role(&admin, principal(&kind, &holder)?, &role).await
    }
    .await;
    respond(result, no_content)
}

/// The instance's signing keys (needs `instance.read`).
#[utoipa::path(get, path = "/v1/instance/signing-keys", tag = "instance",
    responses((status = 200, body = [SigningKeyView])))]
pub(crate) async fn signing_keys(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond_oidc(state.oidc.admin_signing_keys(&admin).await, |keys| {
        Json(keys.into_iter().map(SigningKeyView::from).collect::<Vec<_>>()).into_response()
    })
}

/// Creates a signing key: published at once, signing once activated (needs `instance.manage`).
#[utoipa::path(post, path = "/v1/instance/signing-keys", tag = "instance", responses((status = 201, body = NewKey)))]
pub(crate) async fn add_signing_key(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond_oidc(state.oidc.admin_add_signing_key(&admin).await, |kid| {
        (StatusCode::CREATED, Json(NewKey { kid })).into_response()
    })
}

/// Signs with this key from now on (needs `instance.manage`).
#[utoipa::path(post, path = "/v1/instance/signing-keys/{kid}/activate", tag = "instance",
    responses((status = 204), (status = 400, body = Problem)))]
pub(crate) async fn activate_signing_key(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(kid): Path<String>,
) -> Response {
    respond_oidc(state.oidc.admin_activate_signing_key(&admin, &kid).await, no_content)
}

/// Removes an inactive key whose tokens have expired (needs `instance.manage`).
#[utoipa::path(delete, path = "/v1/instance/signing-keys/{kid}", tag = "instance",
    responses((status = 204), (status = 400, body = Problem)))]
pub(crate) async fn remove_signing_key(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(kid): Path<String>,
) -> Response {
    respond_oidc(state.oidc.admin_remove_signing_key(&admin, &kid).await, no_content)
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct SamlKeyView {
    id: String,
    /// `next` (in the metadata, not signing yet), `active` (signing) or `retired` (only decrypting).
    state: String,
    created_at: DateTime<Utc>,
    state_since: DateTime<Utc>,
    /// SHA-256 of the certificate, in hex.
    fingerprint: String,
}

impl From<SamlKeyInfo> for SamlKeyView {
    fn from(key: SamlKeyInfo) -> Self {
        Self {
            id: key.id.to_string(),
            state: key.state,
            created_at: key.created_at,
            state_since: key.state_since,
            fingerprint: key.fingerprint,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct NewSamlKey {
    id: String,
}

/// kernoid's SAML keys of the instance (needs `instance.read`).
#[utoipa::path(get, path = "/v1/instance/saml-keys", tag = "instance", responses((status = 200, body = [SamlKeyView])))]
pub(crate) async fn saml_keys(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond_oidc(state.oidc.admin_saml_keys(&admin).await, |keys| {
        Json(keys.into_iter().map(SamlKeyView::from).collect::<Vec<_>>()).into_response()
    })
}

/// Starts a change of kernoid's SAML key (needs `instance.manage`): a new key, in the metadata at once – for the
/// providers to take in – and signing once activated. If a key waits already, that one.
#[utoipa::path(post, path = "/v1/instance/saml-keys", tag = "instance", responses((status = 201, body = NewSamlKey)))]
pub(crate) async fn add_saml_key(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond_oidc(state.oidc.admin_add_saml_key(&admin).await, |id| {
        (StatusCode::CREATED, Json(NewSamlKey { id: id.to_string() })).into_response()
    })
}

/// Signs with the waiting SAML key from now on; the key active so far leaves the metadata (needs `instance.manage`).
#[utoipa::path(post, path = "/v1/instance/saml-keys/{id}/activate", tag = "instance",
    responses((status = 204), (status = 400, body = Problem)))]
pub(crate) async fn activate_saml_key(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(key): Path<String>,
) -> Response {
    let key = match id(&key, "the key") {
        Ok(key) => key,
        Err(error) => return crate::sessions::problem(error),
    };
    respond_oidc(state.oidc.admin_activate_saml_key(&admin, key).await, no_content)
}
