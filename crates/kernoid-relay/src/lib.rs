// SPDX-License-Identifier: AGPL-3.0-or-later
//! kernoid as the relay of end-to-end encrypted spaces (RFC 0010, 4): it holds, per space, the ordered member list and
//! the envelopes of events and originals, and passes them on to the members. It cannot read them: it checks signatures,
//! the rules of the member list and who may write, never content. The protocol is that of aktujo's relay (taken over
//! with the foundation, aktujo 0.4.1); the storage is kernoid's – PostgreSQL through sqlx's checked macros, envelopes
//! larger than 64 KiB in object storage through `BlobStore`.
//!
//! A program's spaces are reached below `/relay/<scheme>/v1/spaces/{space}/`, `<scheme>` being the program's domain
//! (`kernoid`, `aktujo` …) as `relay.domains` allows it:
//!
//! | Request | |
//! |---|---|
//! | `GET …/members?after={seq}` | the records after `seq`, in order – open |
//! | `POST …/members` | a record: `201` when it is the next valid one, `409` when it does not follow, `403` when it is not valid. Record 0 founds the space: open on an open relay (`relay.open_for_tenant`), else with an account's token in `kernoid-session` |
//! | `POST …/envelopes` | an envelope: `201`, or `200` if held already |
//! | `GET …/envelopes?after={n}&limit={m}` | `{"envelopes": [{"position": …, "envelope": …}], "more": …}` |
//! | `POST …/requests` | a request to join – open |
//! | `GET …/requests` | the requests to join, for members who may manage |
//!
//! Every request but the open ones is signed by a member (`kernoid_crypt::request_signature`).

use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{Extensions, HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
};
use kernoid_base::{SpaceId, from_root, to_root};
use kernoid_crypt::{
    Domain, Envelope, JoinRequest, Member, MemberId, MemberList, MemberRecord, MemberRole, RecordProblem, Rights,
    verify_request,
};
use kernoid_store::{BlobStore, PgPool, garbage};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

/// How long a request to join is kept, in seconds.
const REQUEST_LIFETIME: i64 = 24 * 60 * 60;
/// How many requests to join a space may wait at once.
const MAX_REQUESTS: i64 = 20;
/// The largest request body: an original in an envelope (aktujo's limit).
pub const MAX_BODY: usize = 64 * 1024 * 1024;
/// Envelopes up to this size stay in PostgreSQL; larger ones go to object storage.
const INLINE: usize = 64 * 1024;
/// The header with the token of the account that founds a space on a relay that is not open.
pub const FOUNDER_HEADER: &str = "kernoid-session";

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Who founds a space: an account, for its tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Founder {
    pub tenant: Uuid,
    pub account: Uuid,
}

/// Finds the account behind a request that founds a space – kernoid-server's sessions and app tokens.
pub trait Founders: Send + Sync + std::fmt::Debug + 'static {
    /// The account whose token `kernoid-session` carries, of the instance the request is for; None if none is valid.
    fn founder<'a>(&'a self, extensions: &'a Extensions, headers: &'a HeaderMap) -> BoxFuture<'a, Option<Founder>>;
}

/// The relay of an installation.
#[derive(Debug, Clone)]
pub struct Relay {
    db: PgPool,
    blobs: BlobStore,
    domains: Arc<BTreeMap<String, Domain>>,
    /// The tenant whose storage keeps the spaces anyone founds; None where only accounts found spaces.
    open_for: Option<Uuid>,
    founders: Arc<dyn Founders>,
}

/// An error answered to a request, as `{"error": …}`.
#[derive(Debug)]
pub struct RelayError(StatusCode, String);

impl IntoResponse for RelayError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<sqlx::Error> for RelayError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "relay: database");
        RelayError(StatusCode::INTERNAL_SERVER_ERROR, "the relay is not available".into())
    }
}

impl From<kernoid_store::BlobError> for RelayError {
    fn from(error: kernoid_store::BlobError) -> Self {
        tracing::error!(%error, "relay: object storage");
        RelayError(StatusCode::INTERNAL_SERVER_ERROR, "the relay is not available".into())
    }
}

fn bad(message: impl Into<String>) -> RelayError {
    RelayError(StatusCode::BAD_REQUEST, message.into())
}

fn forbidden(message: impl Into<String>) -> RelayError {
    RelayError(StatusCode::FORBIDDEN, message.into())
}

fn not_found() -> RelayError {
    RelayError(StatusCode::NOT_FOUND, "no such space here".into())
}

/// Seconds since 1970-01-01 UTC.
fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

fn space_id(text: &str) -> Result<SpaceId, RelayError> {
    text.parse().map_err(|_| bad("not the identity of a space"))
}

/// A space the relay holds, as its administration sees it.
#[derive(Debug, Clone, Serialize)]
pub struct SpaceInfo {
    pub space: String,
    pub domain: String,
    pub founder: Option<Uuid>,
    pub bytes: i64,
    pub created_at: jiff::Timestamp,
    pub written_at: jiff::Timestamp,
}

impl Relay {
    /// The relay for the programs `domains` names (their schemes); `open_for` lets anyone found a space, kept for
    /// that tenant.
    pub fn new(
        db: PgPool,
        blobs: BlobStore,
        domains: &[String],
        open_for: Option<Uuid>,
        founders: Arc<dyn Founders>,
    ) -> Self {
        // A domain's labels are needed for the life of the process; there are few, read once at start.
        let domains = domains
            .iter()
            .map(|scheme| {
                let scheme: &'static str = Box::leak(scheme.clone().into_boxed_str());
                let label: &'static str = Box::leak(format!("{scheme}/crypt").into_boxed_str());
                (scheme.to_owned(), Domain { label, scheme })
            })
            .collect();
        Self { db, blobs, domains: Arc::new(domains), open_for, founders }
    }

    fn domain(&self, scheme: &str) -> Result<Domain, RelayError> {
        self.domains
            .get(scheme)
            .copied()
            .ok_or_else(|| RelayError(StatusCode::NOT_FOUND, "no such program here".into()))
    }

    /// The domain and tenant of a space the relay holds, in the domain the request names.
    async fn held(&self, scheme: &str, space: &SpaceId) -> Result<(Domain, Uuid), RelayError> {
        let domain = self.domain(scheme)?;
        let row = sqlx::query!("SELECT domain, tenant_id FROM relay_spaces WHERE space = $1", space.as_str())
            .fetch_optional(&self.db)
            .await?
            .ok_or_else(not_found)?;
        if row.domain != scheme {
            return Err(not_found());
        }
        Ok((domain, row.tenant_id))
    }

    /// The member list of a space, as stored.
    async fn members<'c>(
        &self,
        executor: impl sqlx::PgExecutor<'c>,
        domain: Domain,
        space: &SpaceId,
    ) -> Result<MemberList, RelayError> {
        let rows =
            sqlx::query_scalar!("SELECT canonical FROM relay_records WHERE space = $1 ORDER BY seq", space.as_str())
                .fetch_all(executor)
                .await?;
        let mut list = MemberList::new(domain, space.clone());
        for row in rows {
            let record: MemberRecord = from_root(&row).map_err(|e| bad(e.to_string()))?;
            list.apply(record).map_err(|e| RelayError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
        Ok(list)
    }

    /// The member who signed a request, if it is a current member of the space with at least `rights`.
    async fn member(
        &self,
        domain: Domain,
        space: &SpaceId,
        headers: &HeaderMap,
        method: &Method,
        uri: &Uri,
        rights: Rights,
    ) -> Result<(MemberList, Member), RelayError> {
        let header = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| RelayError(StatusCode::UNAUTHORIZED, "a signed request is needed".into()))?;
        let path = uri.path_and_query().map_or(uri.path(), |p| p.as_str());
        let id = verify_request(domain, header, method.as_str(), path, now())
            .ok_or_else(|| RelayError(StatusCode::UNAUTHORIZED, "the signature or its time is not valid".into()))?;
        let list = self.members(&self.db, domain, space).await?;
        let member = list.member(&id).cloned().ok_or_else(|| forbidden("not a member of this space"))?;
        if member.rights < rights {
            return Err(forbidden("not allowed"));
        }
        Ok((list, member))
    }

    /// The spaces of a tenant, newest first.
    pub async fn spaces(&self, tenant: Uuid) -> Result<Vec<SpaceInfo>, sqlx::Error> {
        let rows = sqlx::query!(
            "SELECT space, domain, account_id, bytes, created_at, written_at FROM relay_spaces
             WHERE tenant_id = $1 ORDER BY created_at DESC",
            tenant,
        )
        .fetch_all(&self.db)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| SpaceInfo {
                space: row.space,
                domain: row.domain,
                founder: row.account_id,
                bytes: row.bytes,
                created_at: row.created_at.to_jiff(),
                written_at: row.written_at.to_jiff(),
            })
            .collect())
    }

    /// Removes a space of a tenant with all it holds; false if the tenant has no such space. Its objects become
    /// garbage, removed by the worker.
    pub async fn remove_space(&self, tenant: Uuid, space: &str) -> Result<bool, sqlx::Error> {
        let mut transaction = self.db.begin().await?;
        let blobs = sqlx::query_scalar!(
            r#"SELECT e.blob AS "blob!" FROM relay_envelopes e JOIN relay_spaces s ON s.space = e.space
               WHERE s.space = $1 AND s.tenant_id = $2 AND e.blob IS NOT NULL"#,
            space,
            tenant,
        )
        .fetch_all(&mut *transaction)
        .await?;
        let removed = sqlx::query!("DELETE FROM relay_spaces WHERE space = $1 AND tenant_id = $2", space, tenant)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
        for key in blobs {
            garbage::mark_now(&mut transaction, tenant, &key).await?;
        }
        transaction.commit().await?;
        Ok(removed > 0)
    }
}

/// The routes of the relay, below `/relay/{scheme}/v1/`.
pub fn router(relay: Relay) -> Router {
    Router::new()
        .route("/relay/{scheme}/v1/spaces/{space}/members", get(members).post(add_record))
        .route("/relay/{scheme}/v1/spaces/{space}/envelopes", get(envelopes).post(add_envelope))
        .route("/relay/{scheme}/v1/spaces/{space}/requests", get(requests).post(add_request))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(relay)
}

#[derive(Debug, Deserialize)]
struct After {
    after: Option<i64>,
    limit: Option<i64>,
}

/// The records after `after`, in order – open.
async fn members(
    State(relay): State<Relay>,
    Path((scheme, space)): Path<(String, String)>,
    Query(query): Query<After>,
) -> Result<Json<Vec<Value>>, RelayError> {
    let space = space_id(&space)?;
    match relay.held(&scheme, &space).await {
        Ok(_) => {}
        // A space not founded yet has no records – the device that founds it asks first.
        Err(RelayError(StatusCode::NOT_FOUND, _)) if relay.domain(&scheme).is_ok() => return Ok(Json(Vec::new())),
        Err(error) => return Err(error),
    }
    let rows = sqlx::query_scalar!(
        "SELECT canonical FROM relay_records WHERE space = $1 AND seq > $2 ORDER BY seq",
        space.as_str(),
        query.after.unwrap_or(-1),
    )
    .fetch_all(&relay.db)
    .await?;
    let records = rows
        .iter()
        .map(|row| serde_json::from_slice(row).map_err(|_| bad("a stored record is not JSON")))
        .collect::<Result<Vec<Value>, _>>()?;
    Ok(Json(records))
}

/// A record of the member list: the next valid one, or refused. Record 0 founds the space.
async fn add_record(
    State(relay): State<Relay>,
    Path((scheme, space)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    extensions: Extensions,
    body: Bytes,
) -> Result<StatusCode, RelayError> {
    let space = space_id(&space)?;
    let domain = relay.domain(&scheme)?;
    let record: MemberRecord = from_root(&body).map_err(|e| bad(e.to_string()))?;
    let seq = record.seq;
    let added: Vec<MemberId> = record.add.iter().map(|m| m.id).collect();
    let canonical = to_root(&record).map_err(|e| bad(e.to_string()))?;
    let mut transaction = relay.db.begin().await?;
    if seq == 0 {
        // A space held already has its record 0.
        let held = sqlx::query_scalar!("SELECT space FROM relay_spaces WHERE space = $1", space.as_str())
            .fetch_optional(&mut *transaction)
            .await?;
        if held.is_some() {
            return Err(RelayError(StatusCode::CONFLICT, "not the next record".into()));
        }
        let (tenant, account) = match relay.open_for {
            Some(tenant) => (tenant, None),
            None => {
                let founder =
                    relay.founders.founder(&extensions, &headers).await.ok_or_else(|| {
                        RelayError(StatusCode::UNAUTHORIZED, "founding a space needs an account".into())
                    })?;
                (founder.tenant, Some(founder.account))
            }
        };
        let inserted = sqlx::query!(
            "INSERT INTO relay_spaces (space, domain, tenant_id, account_id) VALUES ($1, $2, $3, $4)
             ON CONFLICT (space) DO NOTHING",
            space.as_str(),
            scheme,
            tenant,
            account,
        )
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if inserted == 0 {
            return Err(RelayError(StatusCode::CONFLICT, "not the next record".into()));
        }
    } else {
        relay.held(&scheme, &space).await?;
        relay.member(domain, &space, &headers, &method, &uri, Rights::Manage).await?;
        // One writer per space at a time: the records' order is the relay's.
        sqlx::query!("SELECT space FROM relay_spaces WHERE space = $1 FOR UPDATE", space.as_str())
            .fetch_one(&mut *transaction)
            .await?;
    }
    let mut list = relay.members(&mut *transaction, domain, &space).await?;
    match list.apply(record) {
        Ok(()) => {}
        Err(RecordProblem::NotNext) => return Err(RelayError(StatusCode::CONFLICT, "not the next record".into())),
        Err(problem) => return Err(forbidden(problem.to_string())),
    }
    sqlx::query!(
        "INSERT INTO relay_records (space, seq, canonical) VALUES ($1, $2, $3)",
        space.as_str(),
        seq as i64,
        canonical,
    )
    .execute(&mut *transaction)
    .await?;
    for id in added {
        sqlx::query!("DELETE FROM relay_requests WHERE space = $1 AND member = $2", space.as_str(), id.to_string())
            .execute(&mut *transaction)
            .await?;
    }
    sqlx::query!("UPDATE relay_spaces SET written_at = now() WHERE space = $1", space.as_str())
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(StatusCode::CREATED)
}

/// An envelope from a member who may write.
async fn add_envelope(
    State(relay): State<Relay>,
    Path((scheme, space)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, RelayError> {
    let space = space_id(&space)?;
    let (domain, tenant) = relay.held(&scheme, &space).await?;
    let (list, _) = relay.member(domain, &space, &headers, &method, &uri, Rights::Write).await?;
    let envelope: Envelope = from_root(&body).map_err(|e| bad(e.to_string()))?;
    let author = list.member(&envelope.author).ok_or_else(|| forbidden("the author is not a member"))?;
    let writes = author.rights >= Rights::Write && author.role != MemberRole::Recovery;
    if envelope.space != space || !writes || !envelope.is_authentic() {
        return Err(forbidden("the envelope is not one a member may send"));
    }
    if list.key_index().is_none_or(|current| envelope.key > current) {
        return Err(forbidden("no such key yet"));
    }
    let id = envelope.id.to_string();
    let known =
        sqlx::query_scalar!("SELECT position FROM relay_envelopes WHERE space = $1 AND id = $2", space.as_str(), id)
            .fetch_optional(&relay.db)
            .await?;
    if known.is_some() {
        return Ok(StatusCode::OK);
    }
    let canonical = to_root(&envelope).map_err(|e| bad(e.to_string()))?;
    let size = canonical.len() as i64;
    // Large envelopes go to object storage first – named as garbage until the row that needs them commits.
    let owner = tenant;
    let (inline, blob) = if canonical.len() <= INLINE {
        (Some(canonical), None)
    } else {
        let key = format!("relay/{}/{id}", space.as_str());
        garbage::pending(&relay.db, owner, &key).await?;
        relay.blobs.put(owner, &key, Bytes::from(canonical)).await?;
        (None, Some(key))
    };
    let mut transaction = relay.db.begin().await?;
    sqlx::query!("SELECT space FROM relay_spaces WHERE space = $1 FOR UPDATE", space.as_str())
        .fetch_one(&mut *transaction)
        .await?;
    let position = sqlx::query_scalar!(
        r#"SELECT coalesce(max(position), 0) + 1 AS "next!" FROM relay_envelopes WHERE space = $1"#,
        space.as_str(),
    )
    .fetch_one(&mut *transaction)
    .await?;
    let inserted = sqlx::query!(
        "INSERT INTO relay_envelopes (space, position, id, canonical, blob, size) VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (space, id) DO NOTHING",
        space.as_str(),
        position,
        id,
        inline,
        blob,
        size,
    )
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    sqlx::query!(
        "UPDATE relay_spaces SET bytes = bytes + $2, written_at = now() WHERE space = $1",
        space.as_str(),
        if inserted > 0 { size } else { 0 },
    )
    .execute(&mut *transaction)
    .await?;
    if inserted > 0
        && let Some(key) = &blob
    {
        garbage::keep(&mut transaction, owner, key).await?;
    }
    transaction.commit().await?;
    Ok(if inserted > 0 { StatusCode::CREATED } else { StatusCode::OK })
}

/// The envelopes after a position, for members.
async fn envelopes(
    State(relay): State<Relay>,
    Path((scheme, space)): Path<(String, String)>,
    Query(query): Query<After>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<Value>, RelayError> {
    let space = space_id(&space)?;
    let (domain, tenant) = relay.held(&scheme, &space).await?;
    relay.member(domain, &space, &headers, &method, &uri, Rights::Read).await?;
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let rows = sqlx::query!(
        "SELECT position, canonical, blob FROM relay_envelopes WHERE space = $1 AND position > $2
         ORDER BY position LIMIT $3",
        space.as_str(),
        query.after.unwrap_or(0),
        limit + 1,
    )
    .fetch_all(&relay.db)
    .await?;
    let more = rows.len() as i64 > limit;
    let mut envelopes = Vec::new();
    for row in rows.into_iter().take(limit as usize) {
        let canonical = match (row.canonical, row.blob) {
            (Some(canonical), _) => canonical,
            (None, Some(key)) => relay.blobs.get(tenant, &key).await?.to_vec(),
            (None, None) => return Err(bad("a stored envelope has no content")),
        };
        let envelope: Value = serde_json::from_slice(&canonical).map_err(|_| bad("a stored envelope is not JSON"))?;
        envelopes.push(json!({ "position": row.position, "envelope": envelope }));
    }
    Ok(Json(json!({ "envelopes": envelopes, "more": more })))
}

/// A request to join – open; the inviting member checks its proof.
async fn add_request(
    State(relay): State<Relay>,
    Path((scheme, space)): Path<(String, String)>,
    body: Bytes,
) -> Result<StatusCode, RelayError> {
    let space = space_id(&space)?;
    relay.held(&scheme, &space).await?;
    let request: JoinRequest = from_root(&body).map_err(|e| bad(e.to_string()))?;
    let canonical = to_root(&request).map_err(|e| bad(e.to_string()))?;
    sqlx::query!(
        "DELETE FROM relay_requests WHERE received_at < now() - make_interval(secs => $1)",
        REQUEST_LIFETIME as f64,
    )
    .execute(&relay.db)
    .await?;
    let waiting =
        sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM relay_requests WHERE space = $1"#, space.as_str())
            .fetch_one(&relay.db)
            .await?;
    if waiting >= MAX_REQUESTS {
        return Err(RelayError(StatusCode::TOO_MANY_REQUESTS, "too many requests waiting".into()));
    }
    sqlx::query!(
        "INSERT INTO relay_requests (space, member, canonical) VALUES ($1, $2, $3)
         ON CONFLICT (space, member) DO UPDATE SET canonical = EXCLUDED.canonical, received_at = now()",
        space.as_str(),
        request.member.id.to_string(),
        canonical,
    )
    .execute(&relay.db)
    .await?;
    Ok(StatusCode::CREATED)
}

/// The requests to join, for members who may manage.
async fn requests(
    State(relay): State<Relay>,
    Path((scheme, space)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<Vec<Value>>, RelayError> {
    let space = space_id(&space)?;
    let (domain, _) = relay.held(&scheme, &space).await?;
    relay.member(domain, &space, &headers, &method, &uri, Rights::Manage).await?;
    let rows = sqlx::query_scalar!(
        "SELECT canonical FROM relay_requests WHERE space = $1 AND received_at >= now() - make_interval(secs => $2)
         ORDER BY received_at",
        space.as_str(),
        REQUEST_LIFETIME as f64,
    )
    .fetch_all(&relay.db)
    .await?;
    let requests = rows
        .iter()
        .map(|row| serde_json::from_slice(row).map_err(|_| bad("a stored request is not JSON")))
        .collect::<Result<Vec<Value>, _>>()?;
    Ok(Json(requests))
}
