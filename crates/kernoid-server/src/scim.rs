// SPDX-License-Identifier: AGPL-3.0-or-later
//! SCIM 2.0 (RFC 7643, RFC 7644; RFC 0001, 7.8) at `/scim/v2`: a tenant's directory – Entra ID, Okta, … – creates,
//! changes and deactivates accounts and groups. Requests carry a SCIM token of the tenant as the bearer token.
//!
//! - **Users** are accounts: `userName` is the login name (an address on a verified domain of the tenant), further
//!   `emails` on such domains become aliases, `displayName` (or `name`) the display name. `DELETE` deactivates – an
//!   account is also a mailbox and owns files; kernoid does not delete it on a directory's word.
//! - **Groups** are groups, with accounts of the tenant as members.
//! - A SCIM token may not deactivate an account that holds permissions beyond accounts and groups, nor change the
//!   members of a group that holds roles – the same safeguards as for administrators.
//! - Filters: `userName eq "…"`, `externalId eq "…"`, `displayName eq "…"` – what directories use to find what they
//!   provisioned. PATCH takes the forms Entra ID and Okta send.
//! - Sorting (`sortBy`, `sortOrder`), ETags (`meta.version` from the resource's last event; `If-Match` on changes),
//!   passwords (only for accounts SCIM may manage; they end the account's sessions), and Bulk (RFC 7644, 3.7) with
//!   `bulkId` references to resources created earlier in the same request.
#![allow(
    clippy::result_large_err,
    reason = "the helpers return the finished SCIM error answer; it is built once, on the error path"
)]

use axum::{
    body::Bytes,
    extract::{FromRef, FromRequestParts, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use kernoid_identity::{
    Address, IdentityError,
    provisioning::{ScimClient, ScimFilter, ScimGroup, ScimMeta, ScimSort, ScimUser},
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{AppState, CurrentInstance, sessions::bearer};

const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const PATCH: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const BULK_REQUEST: &str = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
const BULK_RESPONSE: &str = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";
/// Most operations in one Bulk request.
const MAX_OPERATIONS: usize = 100;
/// Largest Bulk request body.
const MAX_PAYLOAD: usize = 1024 * 1024;

/// A SCIM answer: `application/scim+json`.
fn scim(status: StatusCode, body: Value) -> Response {
    let mut response = (status, body.to_string()).into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/scim+json"));
    response
}

/// One resource, with its version as the ETag.
fn resource(status: StatusCode, body: Value, meta: &ScimMeta) -> Response {
    let mut response = scim(status, body);
    if let Ok(etag) = HeaderValue::from_str(&meta.etag()) {
        response.headers_mut().insert(header::ETAG, etag);
    }
    response
}

/// `If-Match`: the change only applies to the version the client knows (RFC 7644, 3.14) – else `412`.
fn precondition(headers: &HeaderMap, meta: &ScimMeta) -> Result<(), Response> {
    let Some(wanted) = headers.get(header::IF_MATCH).and_then(|value| value.to_str().ok()) else { return Ok(()) };
    let current = meta.etag();
    let strong = current.trim_start_matches("W/");
    let matches = wanted.split(',').map(str::trim).any(|tag| tag == "*" || tag == current || tag == strong);
    if matches { Ok(()) } else { Err(error(StatusCode::PRECONDITION_FAILED, "the resource has changed since", None)) }
}

fn meta_json(resource_type: &str, location: String, meta: &ScimMeta) -> Value {
    json!({
        "resourceType": resource_type,
        "location": location,
        "created": meta.created.to_rfc3339(),
        "lastModified": meta.last_modified.to_rfc3339(),
        "version": meta.etag(),
    })
}

/// A SCIM error (RFC 7644, 3.12).
fn error(status: StatusCode, detail: &str, scim_type: Option<&str>) -> Response {
    let mut body = json!({ "schemas": [ERROR], "status": status.as_u16().to_string(), "detail": detail });
    if let Some(kind) = scim_type {
        body["scimType"] = json!(kind);
    }
    scim(status, body)
}

fn identity_error(failure: IdentityError) -> Response {
    match &failure {
        IdentityError::NotFound(_) => error(StatusCode::NOT_FOUND, &failure.to_string(), None),
        IdentityError::Exists(_) | IdentityError::AddressTaken(_) => {
            error(StatusCode::CONFLICT, &failure.to_string(), Some("uniqueness"))
        }
        IdentityError::Forbidden(_) => error(StatusCode::FORBIDDEN, &failure.to_string(), None),
        IdentityError::Store(store) => {
            tracing::error!(error = %store, "scim");
            error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", None)
        }
        _ => error(StatusCode::BAD_REQUEST, &failure.to_string(), Some("invalidValue")),
    }
}

fn bad(detail: &str) -> Response {
    error(StatusCode::BAD_REQUEST, detail, Some("invalidValue"))
}

/// The SCIM client of a request: its token at the instance of its host.
pub struct Scim(ScimClient, String);

impl<S> FromRequestParts<S> for Scim
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response> {
        let CurrentInstance(instance) =
            CurrentInstance::from_request_parts(parts, state).await.map_err(IntoResponse::into_response)?;
        let state = AppState::from_ref(state);
        let unauthorized = || error(StatusCode::UNAUTHORIZED, "a valid SCIM token is required", None);
        let token = bearer(&parts.headers).ok_or_else(unauthorized)?;
        let client =
            state.identity.scim_client(instance.id, &token).await.map_err(identity_error)?.ok_or_else(unauthorized)?;
        Ok(Self(client, format!("{}/scim/v2", state.oidc.issuer(&instance.primary_domain))))
    }
}

/// The JSON of a request body, whatever its content type says.
fn body(bytes: &Bytes) -> Result<Value, Response> {
    serde_json::from_slice(bytes)
        .map_err(|_| error(StatusCode::BAD_REQUEST, "the body is not JSON", Some("invalidSyntax")))
}

/// `attribute eq "value"`.
fn parse_filter(filter: &str) -> Result<ScimFilter, Response> {
    let invalid = || {
        error(
            StatusCode::BAD_REQUEST,
            "only filters of the form attribute eq \"value\" are supported",
            Some("invalidFilter"),
        )
    };
    let mut parts = filter.trim().splitn(3, char::is_whitespace);
    let (Some(attribute), Some(operator), Some(value)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(invalid());
    };
    if !operator.eq_ignore_ascii_case("eq") {
        return Err(invalid());
    }
    let value = value.trim();
    let value = value.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')).ok_or_else(invalid)?;
    let value = value.replace("\\\"", "\"").replace("\\\\", "\\");
    match attribute.to_ascii_lowercase().as_str() {
        "username" => Ok(ScimFilter::UserName(value)),
        "externalid" => Ok(ScimFilter::ExternalId(value)),
        "displayname" => Ok(ScimFilter::DisplayName(value)),
        _ => Err(invalid()),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct ListQuery {
    filter: Option<String>,
    #[serde(rename = "startIndex")]
    start_index: Option<i64>,
    count: Option<i64>,
    #[serde(rename = "excludedAttributes")]
    excluded_attributes: Option<String>,
    #[serde(rename = "sortBy")]
    sort_by: Option<String>,
    #[serde(rename = "sortOrder")]
    sort_order: Option<String>,
}

impl ListQuery {
    fn sort(&self) -> Result<(ScimSort, bool), Response> {
        let sort = match self.sort_by.as_deref() {
            None => ScimSort::default(),
            Some(attribute) => ScimSort::parse(attribute)
                .ok_or_else(|| bad("sortBy is one of userName, displayName, externalId, meta.created"))?,
        };
        let descending = match self.sort_order.as_deref().map(str::to_ascii_lowercase).as_deref() {
            None | Some("ascending") => false,
            Some("descending") => true,
            Some(_) => return Err(bad("sortOrder is ascending or descending")),
        };
        Ok((sort, descending))
    }
}

fn list(total: i64, start: i64, resources: Vec<Value>) -> Response {
    scim(
        StatusCode::OK,
        json!({ "schemas": [LIST], "totalResults": total, "startIndex": start, "itemsPerPage": resources.len(), "Resources": resources }),
    )
}

fn user_json(user: &ScimUser, base: &str) -> Value {
    let emails: Vec<Value> = user
        .addresses
        .iter()
        .map(|address| json!({ "value": address, "type": "work", "primary": address == &user.account.address }))
        .collect();
    let mut value = json!({
        "schemas": [USER],
        "id": user.account.id.to_string(),
        "userName": user.account.address,
        "displayName": user.account.display_name,
        "name": { "formatted": user.account.display_name },
        "emails": emails,
        "active": user.account.active,
        "meta": meta_json("User", format!("{base}/Users/{}", user.account.id), &user.meta),
    });
    if let Some(external) = &user.external_id {
        value["externalId"] = json!(external);
    }
    value
}

fn group_json(group: &ScimGroup, base: &str, members: bool) -> Value {
    let mut value = json!({
        "schemas": [GROUP],
        "id": group.id.to_string(),
        "displayName": group.name,
        "meta": meta_json("Group", format!("{base}/Groups/{}", group.id), &group.meta),
    });
    if members {
        value["members"] = group
            .members
            .iter()
            .map(|(id, address)| json!({ "value": id.to_string(), "display": address, "$ref": format!("{base}/Users/{id}") }))
            .collect();
    }
    if let Some(external) = &group.external_id {
        value["externalId"] = json!(external);
    }
    value
}

fn id(value: &str) -> Result<Uuid, Response> {
    Uuid::parse_str(value).map_err(|_| error(StatusCode::NOT_FOUND, "no such resource", None))
}

/// A boolean as directories send it – Entra ID sometimes sends `"False"`.
fn boolean(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(flag) => Some(*flag),
        Value::String(text) if text.eq_ignore_ascii_case("true") => Some(true),
        Value::String(text) if text.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

/// The display name a user resource asks for.
fn display_name(user: &Value) -> Option<String> {
    let name = &user["name"];
    user["displayName"]
        .as_str()
        .or(name["formatted"].as_str())
        .map(str::to_owned)
        .or_else(|| match (name["givenName"].as_str(), name["familyName"].as_str()) {
            (Some(given), Some(family)) => Some(format!("{given} {family}")),
            (Some(one), None) | (None, Some(one)) => Some(one.to_owned()),
            _ => None,
        })
        .filter(|name| !name.trim().is_empty())
}

// Discovery

/// What this SCIM service supports (RFC 7643, 5).
pub(crate) async fn service_provider_config() -> Response {
    scim(
        StatusCode::OK,
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": { "supported": true },
            "bulk": { "supported": true, "maxOperations": MAX_OPERATIONS, "maxPayloadSize": MAX_PAYLOAD },
            "filter": { "supported": true, "maxResults": 200 },
            "changePassword": { "supported": true },
            "sort": { "supported": true },
            "etag": { "supported": true },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "SCIM token",
                "description": "A SCIM token of the tenant (kscim1.…) as the bearer token",
            }],
        }),
    )
}

pub(crate) async fn resource_types(Scim(_, base): Scim) -> Response {
    let types = vec![
        json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "User", "name": "User",
                "endpoint": "/Users", "schema": USER, "meta": { "location": format!("{base}/ResourceTypes/User") } }),
        json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "Group", "name": "Group",
                "endpoint": "/Groups", "schema": GROUP, "meta": { "location": format!("{base}/ResourceTypes/Group") } }),
    ];
    list(2, 1, types)
}

pub(crate) async fn schemas(Scim(..): Scim) -> Response {
    let attribute = |name: &str, kind: &str, required: bool| {
        json!({ "name": name, "type": kind, "multiValued": false, "required": required, "mutability": "readWrite",
                "returned": "default", "uniqueness": if name == "userName" { "server" } else { "none" } })
    };
    let user = json!({ "id": USER, "name": "User", "attributes": [
        attribute("userName", "string", true), attribute("displayName", "string", false),
        attribute("active", "boolean", false), attribute("externalId", "string", false),
        json!({ "name": "password", "type": "string", "multiValued": false, "required": false,
                "mutability": "writeOnly", "returned": "never", "uniqueness": "none" }),
    ]});
    let group = json!({ "id": GROUP, "name": "Group", "attributes": [
        attribute("displayName", "string", true), attribute("externalId", "string", false),
    ]});
    list(2, 1, vec![user, group])
}

// Users

pub(crate) async fn list_users(
    State(state): State<AppState>,
    Scim(client, base): Scim,
    Query(query): Query<ListQuery>,
) -> Response {
    let filter = match query.filter.as_deref().map(parse_filter).transpose() {
        Ok(filter) => filter,
        Err(response) => return response,
    };
    let (sort, descending) = match query.sort() {
        Ok(sort) => sort,
        Err(response) => return response,
    };
    let start = query.start_index.unwrap_or(1).max(1);
    let count = query.count.unwrap_or(100);
    match state.identity.scim_users(client.tenant, filter.as_ref(), start, count, sort, descending).await {
        Ok((total, users)) => list(total, start, users.iter().map(|user| user_json(user, &base)).collect()),
        Err(failure) => identity_error(failure),
    }
}

pub(crate) async fn get_user(
    State(state): State<AppState>,
    Scim(client, base): Scim,
    Path(user): Path<String>,
) -> Response {
    let user = match id(&user) {
        Ok(user) => user,
        Err(response) => return response,
    };
    match state.identity.scim_user(client.tenant, user).await {
        Ok(user) => resource(StatusCode::OK, user_json(&user, &base), &user.meta),
        Err(failure) => identity_error(failure),
    }
}

pub(crate) async fn create_user(State(state): State<AppState>, Scim(client, base): Scim, bytes: Bytes) -> Response {
    let user = match body(&bytes) {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(user_name) = user["userName"].as_str() else { return bad("userName is required") };
    let Ok(address) = Address::parse(user_name) else { return bad("userName must be an email address") };
    let creator = client.creator();
    let identity = &state.identity;
    let name = display_name(&user).unwrap_or_else(|| address.to_string());
    let account = match identity.add_account(client.tenant, &address, &name, &creator).await {
        Ok(account) => account,
        Err(failure) => return identity_error(failure),
    };
    let result = async {
        add_aliases(&state, account, &address, &user, &creator).await?;
        if let Some(external) = user["externalId"].as_str() {
            identity.set_account_external_id(account, Some(external), &creator).await?;
        }
        if boolean(&user["active"]) == Some(false) {
            identity.set_account_active(account, false, &creator).await?;
        }
        if let Some(password) = user["password"].as_str() {
            identity.set_password(account, password, &creator).await?;
        }
        identity.scim_user(client.tenant, account).await
    }
    .await;
    match result {
        Ok(user) => resource(StatusCode::CREATED, user_json(&user, &base), &user.meta),
        Err(failure) => identity_error(failure),
    }
}

/// Further `emails` on verified domains of the tenant become aliases; others are left out.
async fn add_aliases(
    state: &AppState,
    account: Uuid,
    primary: &Address,
    user: &Value,
    creator: &str,
) -> Result<(), IdentityError> {
    for email in user["emails"].as_array().into_iter().flatten() {
        let Some(Ok(address)) = email["value"].as_str().map(Address::parse) else { continue };
        if &address == primary || state.identity.account_by_address(&address).await?.is_some() {
            continue;
        }
        match state.identity.add_alias(account, &address, creator).await {
            Ok(()) | Err(IdentityError::Refused(_)) => {}
            Err(failure) => return Err(failure),
        }
    }
    Ok(())
}

/// What a PUT or PATCH changes of a user.
#[derive(Debug, Default)]
struct UserChange {
    user_name: Option<String>,
    display_name: Option<String>,
    active: Option<bool>,
    external_id: Option<Option<String>>,
    password: Option<String>,
}

impl UserChange {
    fn take(&mut self, attribute: &str, value: &Value) -> Result<(), Response> {
        match attribute.to_ascii_lowercase().as_str() {
            "username" => self.user_name = Some(value.as_str().ok_or_else(|| bad("userName is a string"))?.to_owned()),
            "displayname" | "name.formatted" => {
                self.display_name = Some(value.as_str().ok_or_else(|| bad("displayName is a string"))?.to_owned());
            }
            "name" => self.display_name = display_name(&json!({ "name": value })),
            "active" => self.active = Some(boolean(value).ok_or_else(|| bad("active is a boolean"))?),
            "externalid" => self.external_id = Some(value.as_str().map(str::to_owned)),
            "password" => self.password = Some(value.as_str().ok_or_else(|| bad("password is a string"))?.to_owned()),
            // Parts kernoid does not keep (given and family name, emails by type, …) are accepted and left alone.
            _ => {}
        }
        Ok(())
    }

    async fn apply(self, state: &AppState, client: &ScimClient, account: Uuid) -> Result<(), IdentityError> {
        let identity = &state.identity;
        let creator = client.creator();
        if let Some(name) = self.display_name {
            identity.rename_account(account, &name, &creator).await?;
        }
        if let Some(user_name) = self.user_name {
            let address = Address::parse(&user_name).map_err(|e| IdentityError::Refused(e.to_string()))?;
            let current = identity.scim_user(client.tenant, account).await?;
            if current.account.address != address.as_str() {
                if !current.addresses.iter().any(|known| known == address.as_str()) {
                    identity.add_alias(account, &address, &creator).await?;
                }
                identity.set_primary_address(account, &address, &creator).await?;
            }
        }
        if let Some(external) = self.external_id {
            identity.set_account_external_id(account, external.as_deref(), &creator).await?;
        }
        // A new password, like an administrator's, ends the account's sessions.
        if let Some(password) = self.password {
            identity.scim_may_manage(client.tenant, account).await?;
            identity.set_password(account, &password, &creator).await?;
            identity.terminate_account_sessions(account, &creator).await?;
        }
        if let Some(active) = self.active {
            let current = identity.account(account).await?;
            if current.active != active {
                identity.scim_may_manage(client.tenant, account).await?;
                identity.set_account_active(account, active, &creator).await?;
                if !active {
                    identity.terminate_account_sessions(account, &creator).await?;
                }
            }
        }
        Ok(())
    }
}

pub(crate) async fn replace_user(
    State(state): State<AppState>,
    Scim(client, base): Scim,
    Path(user): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let (account, value) = match (id(&user), body(&bytes)) {
        (Ok(account), Ok(value)) => (account, value),
        (Err(response), _) | (_, Err(response)) => return response,
    };
    match state.identity.scim_user(client.tenant, account).await {
        Ok(current) => {
            if let Err(response) = precondition(&headers, &current.meta) {
                return response;
            }
        }
        Err(failure) => return identity_error(failure),
    }
    let mut change =
        UserChange { external_id: Some(value["externalId"].as_str().map(str::to_owned)), ..UserChange::default() };
    for attribute in ["userName", "active", "password"] {
        if !value[attribute].is_null()
            && let Err(response) = change.take(attribute, &value[attribute])
        {
            return response;
        }
    }
    change.display_name = display_name(&value);
    let result = async {
        change.apply(&state, &client, account).await?;
        state.identity.scim_user(client.tenant, account).await
    }
    .await;
    match result {
        Ok(user) => resource(StatusCode::OK, user_json(&user, &base), &user.meta),
        Err(failure) => identity_error(failure),
    }
}

/// The operations of a PATCH request (RFC 7644, 3.5.2).
fn operations(value: &Value) -> Result<Vec<(String, Option<String>, Value)>, Response> {
    if !value["schemas"].as_array().is_some_and(|schemas| schemas.iter().any(|schema| schema == PATCH)) {
        return Err(error(StatusCode::BAD_REQUEST, "a PatchOp is expected", Some("invalidSyntax")));
    }
    let list = value["Operations"]
        .as_array()
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "Operations are missing", Some("invalidSyntax")))?;
    list.iter()
        .map(|operation| {
            let op = operation["op"].as_str().map(str::to_ascii_lowercase).ok_or_else(|| bad("op is missing"))?;
            if !matches!(op.as_str(), "add" | "replace" | "remove") {
                return Err(bad("op is add, replace or remove"));
            }
            Ok((op, operation["path"].as_str().map(str::to_owned), operation["value"].clone()))
        })
        .collect()
}

pub(crate) async fn patch_user(
    State(state): State<AppState>,
    Scim(client, base): Scim,
    Path(user): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let (account, value) = match (id(&user), body(&bytes)) {
        (Ok(account), Ok(value)) => (account, value),
        (Err(response), _) | (_, Err(response)) => return response,
    };
    let operations = match operations(&value) {
        Ok(operations) => operations,
        Err(response) => return response,
    };
    match state.identity.scim_user(client.tenant, account).await {
        Ok(current) => {
            if let Err(response) = precondition(&headers, &current.meta) {
                return response;
            }
        }
        Err(failure) => return identity_error(failure),
    }
    let mut change = UserChange::default();
    for (op, path, value) in operations {
        let result = match (op.as_str(), path) {
            ("remove", Some(path)) if path.eq_ignore_ascii_case("externalId") => {
                change.external_id = Some(None);
                Ok(())
            }
            ("remove", _) => Ok(()),
            (_, Some(path)) => change.take(&path, &value),
            (_, None) => match value.as_object() {
                Some(fields) => fields.iter().try_for_each(|(attribute, value)| change.take(attribute, value)),
                None => Err(bad("an operation without path needs an object as value")),
            },
        };
        if let Err(response) = result {
            return response;
        }
    }
    let result = async {
        change.apply(&state, &client, account).await?;
        state.identity.scim_user(client.tenant, account).await
    }
    .await;
    match result {
        Ok(user) => resource(StatusCode::OK, user_json(&user, &base), &user.meta),
        Err(failure) => identity_error(failure),
    }
}

/// Deactivates the account and ends its sessions – kernoid does not delete accounts on a directory's word.
pub(crate) async fn delete_user(
    State(state): State<AppState>,
    Scim(client, _): Scim,
    Path(user): Path<String>,
    headers: HeaderMap,
) -> Response {
    let account = match id(&user) {
        Ok(account) => account,
        Err(response) => return response,
    };
    match state.identity.scim_user(client.tenant, account).await {
        Ok(current) => {
            if let Err(response) = precondition(&headers, &current.meta) {
                return response;
            }
        }
        Err(failure) => return identity_error(failure),
    }
    let result = UserChange { active: Some(false), ..UserChange::default() }.apply(&state, &client, account).await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(failure) => identity_error(failure),
    }
}

// Groups

pub(crate) async fn list_groups(
    State(state): State<AppState>,
    Scim(client, base): Scim,
    Query(query): Query<ListQuery>,
) -> Response {
    let filter = match query.filter.as_deref().map(parse_filter).transpose() {
        Ok(filter) => filter,
        Err(response) => return response,
    };
    let members = !query
        .excluded_attributes
        .as_deref()
        .is_some_and(|excluded| excluded.split(',').any(|a| a.trim().eq_ignore_ascii_case("members")));
    let (sort, descending) = match query.sort() {
        Ok(sort) => sort,
        Err(response) => return response,
    };
    let start = query.start_index.unwrap_or(1).max(1);
    let count = query.count.unwrap_or(100);
    match state.identity.scim_groups(client.tenant, filter.as_ref(), start, count, sort, descending).await {
        Ok((total, groups)) => {
            list(total, start, groups.iter().map(|group| group_json(group, &base, members)).collect())
        }
        Err(failure) => identity_error(failure),
    }
}

pub(crate) async fn get_group(
    State(state): State<AppState>,
    Scim(client, base): Scim,
    Path(group): Path<String>,
) -> Response {
    let group = match id(&group) {
        Ok(group) => group,
        Err(response) => return response,
    };
    match state.identity.scim_group(client.tenant, group).await {
        Ok(group) => resource(StatusCode::OK, group_json(&group, &base, true), &group.meta),
        Err(failure) => identity_error(failure),
    }
}

/// The account ids in a list of members (`[{ "value": "<id>" }]`).
fn member_ids(value: &Value) -> Result<Vec<Uuid>, Response> {
    let list = match value {
        Value::Array(list) => list.clone(),
        Value::Object(_) => vec![value.clone()],
        Value::Null => Vec::new(),
        _ => return Err(bad("members are a list of { value }")),
    };
    list.iter()
        .map(|member| {
            member["value"]
                .as_str()
                .and_then(|value| Uuid::parse_str(value).ok())
                .ok_or_else(|| bad("a member's value is an account id"))
        })
        .collect()
}

/// Brings a group's members to `wanted`.
async fn set_members(state: &AppState, client: &ScimClient, group: Uuid, wanted: &[Uuid]) -> Result<(), IdentityError> {
    let current: Vec<Uuid> =
        state.identity.scim_group(client.tenant, group).await?.members.iter().map(|(id, _)| *id).collect();
    change_members(
        state,
        client,
        group,
        &wanted.iter().filter(|id| !current.contains(id)).copied().collect::<Vec<_>>(),
        &current.iter().filter(|id| !wanted.contains(id)).copied().collect::<Vec<_>>(),
    )
    .await
}

async fn change_members(
    state: &AppState,
    client: &ScimClient,
    group: Uuid,
    add: &[Uuid],
    remove: &[Uuid],
) -> Result<(), IdentityError> {
    if add.is_empty() && remove.is_empty() {
        return Ok(());
    }
    state.identity.scim_may_change_members(group).await?;
    let creator = client.creator();
    for account in add {
        state.identity.add_group_member(client.tenant, group, *account, &creator).await?;
    }
    for account in remove {
        match state.identity.remove_group_member(client.tenant, group, *account, &creator).await {
            Ok(()) | Err(IdentityError::NotFound(_)) => {}
            Err(failure) => return Err(failure),
        }
    }
    Ok(())
}

pub(crate) async fn create_group(State(state): State<AppState>, Scim(client, base): Scim, bytes: Bytes) -> Response {
    let value = match body(&bytes) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Some(name) = value["displayName"].as_str() else { return bad("displayName is required") };
    let members = match member_ids(&value["members"]) {
        Ok(members) => members,
        Err(response) => return response,
    };
    let creator = client.creator();
    let result = async {
        let group = state.identity.add_group(client.tenant, name, &creator).await?;
        if let Some(external) = value["externalId"].as_str() {
            state.identity.set_group_external_id(client.tenant, group, Some(external), &creator).await?;
        }
        change_members(&state, &client, group, &members, &[]).await?;
        state.identity.scim_group(client.tenant, group).await
    }
    .await;
    match result {
        Ok(group) => resource(StatusCode::CREATED, group_json(&group, &base, true), &group.meta),
        Err(failure) => identity_error(failure),
    }
}

pub(crate) async fn replace_group(
    State(state): State<AppState>,
    Scim(client, base): Scim,
    Path(group): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let (group, value) = match (id(&group), body(&bytes)) {
        (Ok(group), Ok(value)) => (group, value),
        (Err(response), _) | (_, Err(response)) => return response,
    };
    let members = match member_ids(&value["members"]) {
        Ok(members) => members,
        Err(response) => return response,
    };
    let creator = client.creator();
    match state.identity.scim_group(client.tenant, group).await {
        Ok(current) => {
            if let Err(response) = precondition(&headers, &current.meta) {
                return response;
            }
        }
        Err(failure) => return identity_error(failure),
    }
    let result = async {
        if let Some(name) = value["displayName"].as_str() {
            state.identity.rename_group(client.tenant, group, name, &creator).await?;
        }
        state.identity.set_group_external_id(client.tenant, group, value["externalId"].as_str(), &creator).await?;
        set_members(&state, &client, group, &members).await?;
        state.identity.scim_group(client.tenant, group).await
    }
    .await;
    match result {
        Ok(group) => resource(StatusCode::OK, group_json(&group, &base, true), &group.meta),
        Err(failure) => identity_error(failure),
    }
}

/// `members[value eq "<id>"]`.
fn member_in_path(path: &str) -> Option<Uuid> {
    let inner = path.strip_prefix("members[")?.strip_suffix(']')?;
    let (attribute, rest) = inner.trim().split_once(char::is_whitespace)?;
    if !attribute.eq_ignore_ascii_case("value") {
        return None;
    }
    Uuid::parse_str(rest.split('"').nth(1)?).ok()
}

pub(crate) async fn patch_group(
    State(state): State<AppState>,
    Scim(client, base): Scim,
    Path(group): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let (group, value) = match (id(&group), body(&bytes)) {
        (Ok(group), Ok(value)) => (group, value),
        (Err(response), _) | (_, Err(response)) => return response,
    };
    let operations = match operations(&value) {
        Ok(operations) => operations,
        Err(response) => return response,
    };
    let creator = client.creator();
    let result: Result<Result<ScimGroup, Response>, IdentityError> = async {
        let current = state.identity.scim_group(client.tenant, group).await?;
        if let Err(response) = precondition(&headers, &current.meta) {
            return Ok(Err(response));
        }
        for (op, path, value) in operations {
            let lower = path.as_deref().map(str::to_ascii_lowercase);
            match (op.as_str(), lower.as_deref()) {
                ("add", Some("members")) => match member_ids(&value) {
                    Ok(add) => change_members(&state, &client, group, &add, &[]).await?,
                    Err(response) => return Ok(Err(response)),
                },
                ("replace", Some("members")) => match member_ids(&value) {
                    Ok(wanted) => set_members(&state, &client, group, &wanted).await?,
                    Err(response) => return Ok(Err(response)),
                },
                ("remove", Some("members")) if value.is_null() => set_members(&state, &client, group, &[]).await?,
                ("remove", Some("members")) => match member_ids(&value) {
                    Ok(remove) => change_members(&state, &client, group, &[], &remove).await?,
                    Err(response) => return Ok(Err(response)),
                },
                ("remove", Some(path)) if path.starts_with("members[") => match member_in_path(path.trim()) {
                    Some(member) => change_members(&state, &client, group, &[], &[member]).await?,
                    None => return Ok(Err(bad("members[value eq \"<id>\"] is expected"))),
                },
                ("remove", Some("externalid")) => {
                    state.identity.set_group_external_id(client.tenant, group, None, &creator).await?
                }
                (_, Some("displayname")) => match value.as_str() {
                    Some(name) => state.identity.rename_group(client.tenant, group, name, &creator).await?,
                    None => return Ok(Err(bad("displayName is a string"))),
                },
                (_, Some("externalid")) => {
                    state.identity.set_group_external_id(client.tenant, group, value.as_str(), &creator).await?;
                }
                (_, None) => {
                    if let Some(name) = value["displayName"].as_str() {
                        state.identity.rename_group(client.tenant, group, name, &creator).await?;
                    }
                    if let Some(external) = value["externalId"].as_str() {
                        state.identity.set_group_external_id(client.tenant, group, Some(external), &creator).await?;
                    }
                    if !value["members"].is_null() {
                        match member_ids(&value["members"]) {
                            Ok(wanted) if op == "replace" => set_members(&state, &client, group, &wanted).await?,
                            Ok(add) => change_members(&state, &client, group, &add, &[]).await?,
                            Err(response) => return Ok(Err(response)),
                        }
                    }
                }
                _ => return Ok(Err(bad("this path is not supported for groups"))),
            }
        }
        Ok(Ok(state.identity.scim_group(client.tenant, group).await?))
    }
    .await;
    match result {
        Ok(Ok(group)) => resource(StatusCode::OK, group_json(&group, &base, true), &group.meta),
        Ok(Err(response)) => response,
        Err(failure) => identity_error(failure),
    }
}

/// Removes a group – refused while it holds roles.
pub(crate) async fn delete_group(
    State(state): State<AppState>,
    Scim(client, _): Scim,
    Path(group): Path<String>,
    headers: HeaderMap,
) -> Response {
    let group = match id(&group) {
        Ok(group) => group,
        Err(response) => return response,
    };
    match state.identity.scim_group(client.tenant, group).await {
        Ok(current) => {
            if let Err(response) = precondition(&headers, &current.meta) {
                return response;
            }
        }
        Err(failure) => return identity_error(failure),
    }
    match state.identity.remove_group(client.tenant, group, &client.creator()).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(IdentityError::Refused(detail)) => error(StatusCode::CONFLICT, &detail, Some("mutability")),
        Err(failure) => identity_error(failure),
    }
}

// Bulk

/// Replaces `bulkId:<id>` references with the ids of resources made earlier in the request.
fn resolve(value: &mut Value, made: &std::collections::HashMap<String, String>) -> Result<(), String> {
    match value {
        Value::String(text) => {
            if let Some(reference) = text.strip_prefix("bulkId:") {
                *text = made.get(reference).cloned().ok_or_else(|| format!("bulkId:{reference} is not known yet"))?;
            }
        }
        Value::Array(list) => list.iter_mut().try_for_each(|item| resolve(item, made))?,
        Value::Object(fields) => fields.values_mut().try_for_each(|item| resolve(item, made))?,
        _ => {}
    }
    Ok(())
}

/// One operation of a Bulk request, run as the single request it stands for.
async fn run_operation(
    state: &AppState,
    client: ScimClient,
    base: &str,
    method: &str,
    path: &str,
    data: Value,
    version: Option<&str>,
) -> Response {
    let mut headers = HeaderMap::new();
    if let Some(version) = version.and_then(|version| HeaderValue::from_str(version).ok()) {
        headers.insert(header::IF_MATCH, version);
    }
    let bytes = Bytes::from(data.to_string());
    let scim = || Scim(client, base.to_owned());
    let state = || State(state.clone());
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match (method, segments.as_slice()) {
        ("POST", ["Users"]) => create_user(state(), scim(), bytes).await,
        ("PUT", ["Users", id]) => replace_user(state(), scim(), Path((*id).to_owned()), headers, bytes).await,
        ("PATCH", ["Users", id]) => patch_user(state(), scim(), Path((*id).to_owned()), headers, bytes).await,
        ("DELETE", ["Users", id]) => delete_user(state(), scim(), Path((*id).to_owned()), headers).await,
        ("POST", ["Groups"]) => create_group(state(), scim(), bytes).await,
        ("PUT", ["Groups", id]) => replace_group(state(), scim(), Path((*id).to_owned()), headers, bytes).await,
        ("PATCH", ["Groups", id]) => patch_group(state(), scim(), Path((*id).to_owned()), headers, bytes).await,
        ("DELETE", ["Groups", id]) => delete_group(state(), scim(), Path((*id).to_owned()), headers).await,
        _ => bad("a Bulk operation is POST, PUT, PATCH or DELETE on /Users or /Groups"),
    }
}

/// Bulk (RFC 7644, 3.7): many operations in one request, run in order. `bulkId:<id>` in a path or value refers to a
/// resource made by an earlier operation; with `failOnErrors`, kernoid stops after that many errors.
pub(crate) async fn bulk(State(state): State<AppState>, Scim(client, base): Scim, bytes: Bytes) -> Response {
    if bytes.len() > MAX_PAYLOAD {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "the Bulk request is too large", None);
    }
    let request = match body(&bytes) {
        Ok(request) => request,
        Err(response) => return response,
    };
    if !request["schemas"].as_array().is_some_and(|schemas| schemas.iter().any(|schema| schema == BULK_REQUEST)) {
        return error(StatusCode::BAD_REQUEST, "a BulkRequest is expected", Some("invalidSyntax"));
    }
    let Some(operations) = request["Operations"].as_array() else {
        return error(StatusCode::BAD_REQUEST, "Operations are missing", Some("invalidSyntax"));
    };
    if operations.len() > MAX_OPERATIONS {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "too many operations", Some("tooMany"));
    }
    let fail_on_errors = request["failOnErrors"].as_u64().filter(|limit| *limit > 0);
    let mut made = std::collections::HashMap::new();
    let mut results = Vec::new();
    let mut errors = 0;
    for operation in operations {
        if fail_on_errors.is_some_and(|limit| errors >= limit) {
            break;
        }
        let method = operation["method"].as_str().unwrap_or_default().to_ascii_uppercase();
        let bulk_id = operation["bulkId"].as_str();
        let mut path = Value::String(operation["path"].as_str().unwrap_or_default().to_owned());
        let mut data = operation["data"].clone();
        let response = match resolve(&mut path, &made).and_then(|()| resolve(&mut data, &made)) {
            Ok(()) => {
                let path = path.as_str().unwrap_or_default();
                run_operation(&state, client, &base, &method, path, data, operation["version"].as_str()).await
            }
            Err(detail) => error(StatusCode::CONFLICT, &detail, Some("invalidValue")),
        };
        let status = response.status();
        let etag = response.headers().get(header::ETAG).and_then(|value| value.to_str().ok()).map(str::to_owned);
        let body = axum::body::to_bytes(response.into_body(), MAX_PAYLOAD).await.unwrap_or_default();
        let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let mut result = json!({ "method": method, "status": status.as_u16().to_string() });
        if let Some(bulk_id) = bulk_id {
            result["bulkId"] = json!(bulk_id);
        }
        if let Some(location) = body["meta"]["location"].as_str() {
            result["location"] = json!(location);
        }
        if let Some(etag) = etag {
            result["version"] = json!(etag);
        }
        if status.is_success() {
            if let (Some(bulk_id), Some(id)) = (bulk_id, body["id"].as_str()) {
                made.insert(bulk_id.to_owned(), id.to_owned());
            }
        } else {
            errors += 1;
            result["response"] = body;
        }
        results.push(result);
    }
    scim(StatusCode::OK, json!({ "schemas": [BULK_RESPONSE], "Operations": results }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_and_member_paths() {
        assert_eq!(parse_filter(r#"userName eq "bob@firma.de""#).unwrap(), ScimFilter::UserName("bob@firma.de".into()));
        assert_eq!(parse_filter(r#"externalId EQ "a \"b\"""#).unwrap(), ScimFilter::ExternalId(r#"a "b""#.into()));
        assert!(parse_filter(r#"userName co "bob""#).is_err());
        assert!(parse_filter("title eq \"x\"").is_err());
        let id = Uuid::now_v7();
        assert_eq!(member_in_path(&format!(r#"members[value eq "{id}"]"#)), Some(id));
        assert_eq!(member_in_path(r#"members[display eq "x"]"#), None);
        assert_eq!(boolean(&json!("False")), Some(false));
    }
}
