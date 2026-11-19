// SPDX-License-Identifier: AGPL-3.0-or-later
//! Protocol 2 of the relay: streams (RFC 0012). A space has a roster – the one list the relay reads – and streams it
//! knows only by identity: it keeps their records and originals and serves them to whoever shows a token of the
//! stream and signs as a device of the roster; it appends for a device with `write` that shows a write token (or, into
//! a person's stream, a link sealed to the person). Below `/relay/<scheme>/v2/spaces/{space}/`:
//!
//! | Request | |
//! |---|---|
//! | `GET roster?after={seq}` | the roster's records after `seq` – open |
//! | `POST roster` | the next record (`201`, `409` when it does not follow, `403` when not valid); record 0 founds the space |
//! | `PUT streams/{stream}` | a new stream with its first generation's token hashes (`write`) |
//! | `POST streams/{stream}/generations` | the next generation's token hashes (`write`, write token of the last one) |
//! | `POST streams/{stream}/records` | a record (`write`, write token – or a sealed link into a person's stream) |
//! | `GET streams/{stream}/records?after=&limit=` | records after a position (read token of a generation) |
//! | `POST follow` | `[{stream, after, read}]` → what is new in each |
//! | `PUT`/`GET streams/{stream}/originals/{hash}` | an original (write / read token) |
//! | `DELETE streams/{stream}` | a stream with what it holds (`purge`, write token) |
//! | `POST requests` / `GET requests` | requests to join – open / for devices with `members` |
//!
//! Tokens travel in `kernoid-read` and `kernoid-write` (base64url); the relay compares their SHA-256.

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{Extensions, HeaderMap, Method, StatusCode, Uri},
    routing::{get, post, put},
};
use kernoid_base::{Sha256Hash, SpaceId, from_base64url, from_root, to_root};
use kernoid_crypt::{
    Domain,
    stream::{
        Device, Joining, Permission, RecordKind, Roster, RosterProblem, RosterRecord, StreamId, StreamRecord,
        verify_request,
    },
};
use kernoid_store::garbage;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    INLINE, MAX_BODY, MAX_REQUESTS, REQUEST_LIFETIME, Relay, RelayError, bad, forbidden, not_found, now, space_id,
};

pub use kernoid_crypt::stream::{READ_HEADER, WRITE_HEADER};
/// How many records a page holds at most.
const PAGE: i64 = 1000;
/// How many streams one `follow` may name.
const MAX_FOLLOW: usize = 1000;

fn stream_id(text: &str) -> Result<StreamId, RelayError> {
    text.parse().map_err(|_| bad("not the identity of a stream"))
}

fn token_hash(headers: &HeaderMap, header: &str) -> Option<Vec<u8>> {
    let token = from_base64url(headers.get(header)?.to_str().ok()?)?;
    Some(Sha256Hash::of(&token).0.to_vec())
}

impl Relay {
    /// The domain and tenant of a space of protocol 2.
    async fn held_v2(&self, scheme: &str, space: &SpaceId) -> Result<(Domain, Uuid), RelayError> {
        let domain = self.domain(scheme)?;
        let row = sqlx::query!("SELECT domain, tenant_id, protocol FROM relay_spaces WHERE space = $1", space.as_str())
            .fetch_optional(&self.db)
            .await?
            .ok_or_else(not_found)?;
        if row.domain != scheme || row.protocol != 2 {
            return Err(not_found());
        }
        Ok((domain, row.tenant_id))
    }

    async fn roster<'c>(
        &self,
        executor: impl sqlx::PgExecutor<'c>,
        domain: Domain,
        space: &SpaceId,
    ) -> Result<Roster, RelayError> {
        let rows =
            sqlx::query_scalar!("SELECT canonical FROM relay_roster WHERE space = $1 ORDER BY seq", space.as_str())
                .fetch_all(executor)
                .await?;
        let mut roster = Roster::new(domain, space.clone());
        for row in rows {
            let record: RosterRecord = from_root(&row).map_err(|e| bad(e.to_string()))?;
            roster.apply(record).map_err(|e| RelayError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
        Ok(roster)
    }

    /// The device of the roster that signed a request, with `permission` if one is named.
    async fn device(
        &self,
        domain: Domain,
        space: &SpaceId,
        headers: &HeaderMap,
        method: &Method,
        uri: &Uri,
        permission: Option<Permission>,
    ) -> Result<(Roster, Device), RelayError> {
        let header = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| RelayError(StatusCode::UNAUTHORIZED, "a signed request is needed".into()))?;
        let path = uri.path_and_query().map_or(uri.path(), |p| p.as_str());
        let roster = self.roster(&self.db, domain, space).await?;
        let device = verify_request(&roster, header, method.as_str(), path, now())
            .cloned()
            .ok_or_else(|| RelayError(StatusCode::UNAUTHORIZED, "not signed by a device of this space".into()))?;
        if permission.is_some_and(|p| !device.may(p)) {
            return Err(forbidden("not allowed"));
        }
        Ok((roster, device))
    }

    /// The generation whose token the request carries in `header`; `generation` must be the latest for a write.
    async fn token(
        &self,
        space: &SpaceId,
        stream: &StreamId,
        headers: &HeaderMap,
        header: &str,
    ) -> Result<i32, RelayError> {
        let hash = token_hash(headers, header).ok_or_else(|| forbidden("a token of the stream is needed"))?;
        let generation = if header == READ_HEADER {
            sqlx::query_scalar!(
                "SELECT generation FROM relay_stream_tokens WHERE space = $1 AND stream = $2 AND read_hash = $3",
                space.as_str(),
                stream.as_str(),
                hash,
            )
            .fetch_optional(&self.db)
            .await?
        } else {
            sqlx::query_scalar!(
                "SELECT generation FROM relay_stream_tokens WHERE space = $1 AND stream = $2 AND write_hash = $3",
                space.as_str(),
                stream.as_str(),
                hash,
            )
            .fetch_optional(&self.db)
            .await?
        };
        generation.ok_or_else(|| forbidden("not a token of this stream"))
    }

    async fn latest_generation(&self, space: &SpaceId, stream: &StreamId) -> Result<Option<i32>, RelayError> {
        Ok(sqlx::query_scalar!(
            "SELECT max(generation) FROM relay_stream_tokens WHERE space = $1 AND stream = $2",
            space.as_str(),
            stream.as_str(),
        )
        .fetch_one(&self.db)
        .await?)
    }

    /// Records of a stream after `after` that a reader of `generation` gets: those of its generation and before, and
    /// the `generation` record of the next – it learns there is a newer key, nothing more.
    async fn records_for(
        &self,
        space: &SpaceId,
        stream: &StreamId,
        generation: i32,
        after: i64,
        limit: i64,
    ) -> Result<(Vec<Value>, bool), RelayError> {
        let rows = sqlx::query!(
            "SELECT position, canonical FROM relay_stream_records
             WHERE space = $1 AND stream = $2 AND position > $3
               AND (generation <= $4 OR (generation = $4 + 1 AND kind = 'generation'))
             ORDER BY position LIMIT $5",
            space.as_str(),
            stream.as_str(),
            after,
            generation,
            limit + 1,
        )
        .fetch_all(&self.db)
        .await?;
        let more = rows.len() as i64 > limit;
        let records = rows
            .into_iter()
            .take(limit as usize)
            .map(|row| {
                let record: Value =
                    serde_json::from_slice(&row.canonical).map_err(|_| bad("a stored record is not JSON"))?;
                Ok(json!({ "position": row.position, "record": record }))
            })
            .collect::<Result<Vec<_>, RelayError>>()?;
        Ok((records, more))
    }
}

/// The routes of protocol 2.
pub(crate) fn routes() -> Router<Relay> {
    Router::new()
        .route("/relay/{scheme}/v2/spaces/{space}/roster", get(roster).post(add_roster_record))
        .route("/relay/{scheme}/v2/spaces/{space}/streams/{stream}", put(add_stream).delete(remove_stream))
        .route("/relay/{scheme}/v2/spaces/{space}/streams/{stream}/generations", post(add_generation))
        .route("/relay/{scheme}/v2/spaces/{space}/streams/{stream}/records", get(records).post(add_record))
        .route("/relay/{scheme}/v2/spaces/{space}/streams/{stream}/originals/{hash}", get(original).put(add_original))
        .route("/relay/{scheme}/v2/spaces/{space}/follow", post(follow))
        .route("/relay/{scheme}/v2/spaces/{space}/requests", get(requests).post(add_request))
        .layer(DefaultBodyLimit::max(MAX_BODY))
}

#[derive(Debug, Deserialize)]
struct After {
    after: Option<i64>,
    limit: Option<i64>,
}

async fn roster(
    State(relay): State<Relay>,
    Path((scheme, space)): Path<(String, String)>,
    Query(query): Query<After>,
) -> Result<Json<Vec<Value>>, RelayError> {
    let space = space_id(&space)?;
    match relay.held_v2(&scheme, &space).await {
        Ok(_) => {}
        Err(RelayError(StatusCode::NOT_FOUND, _)) if relay.domain(&scheme).is_ok() => return Ok(Json(Vec::new())),
        Err(error) => return Err(error),
    }
    let rows = sqlx::query_scalar!(
        "SELECT canonical FROM relay_roster WHERE space = $1 AND seq > $2 ORDER BY seq",
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

async fn add_roster_record(
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
    let record: RosterRecord = from_root(&body).map_err(|e| bad(e.to_string()))?;
    let seq = record.seq;
    let added: Vec<String> = record.add_devices.iter().map(|d| d.id.hex()).collect();
    let canonical = to_root(&record).map_err(|e| bad(e.to_string()))?;
    let mut transaction = relay.db.begin().await?;
    if seq == 0 {
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
            "INSERT INTO relay_spaces (space, domain, tenant_id, account_id, protocol) VALUES ($1, $2, $3, $4, 2)
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
        relay.held_v2(&scheme, &space).await?;
        // Signed by a device of the roster; what the record may do, the roster's rules decide below.
        relay.device(domain, &space, &headers, &method, &uri, None).await?;
        sqlx::query!("SELECT space FROM relay_spaces WHERE space = $1 FOR UPDATE", space.as_str())
            .fetch_one(&mut *transaction)
            .await?;
    }
    let mut roster = relay.roster(&mut *transaction, domain, &space).await?;
    match roster.apply(record) {
        Ok(()) => {}
        Err(RosterProblem::NotNext) => return Err(RelayError(StatusCode::CONFLICT, "not the next record".into())),
        Err(problem) => return Err(forbidden(problem.to_string())),
    }
    sqlx::query!(
        "INSERT INTO relay_roster (space, seq, canonical) VALUES ($1, $2, $3)",
        space.as_str(),
        seq as i64,
        canonical,
    )
    .execute(&mut *transaction)
    .await?;
    for id in added {
        sqlx::query!("DELETE FROM relay_requests WHERE space = $1 AND member = $2", space.as_str(), id)
            .execute(&mut *transaction)
            .await?;
    }
    sqlx::query!("UPDATE relay_spaces SET written_at = now() WHERE space = $1", space.as_str())
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(StatusCode::CREATED)
}

#[derive(Debug, Deserialize)]
struct Generation {
    generation: i32,
    /// SHA-256 of the read token, base64url.
    read: kernoid_base::Bytes,
    write: kernoid_base::Bytes,
    #[serde(default)]
    inbox: bool,
}

async fn add_stream(
    State(relay): State<Relay>,
    Path((scheme, space, stream)): Path<(String, String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Json(body): Json<Generation>,
) -> Result<StatusCode, RelayError> {
    let (space, stream) = (space_id(&space)?, stream_id(&stream)?);
    let (domain, _) = relay.held_v2(&scheme, &space).await?;
    relay.device(domain, &space, &headers, &method, &uri, Some(Permission::Write)).await?;
    if body.generation != 0 || body.read.0.len() != 32 || body.write.0.len() != 32 {
        return Err(bad("a stream starts with generation 0 and two token hashes of 32 bytes"));
    }
    let mut transaction = relay.db.begin().await?;
    let inserted = sqlx::query!(
        "INSERT INTO relay_streams (space, stream, inbox) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        space.as_str(),
        stream.as_str(),
        body.inbox,
    )
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Err(RelayError(StatusCode::CONFLICT, "the stream exists".into()));
    }
    sqlx::query!(
        "INSERT INTO relay_stream_tokens (space, stream, generation, read_hash, write_hash) VALUES ($1, $2, 0, $3, $4)",
        space.as_str(),
        stream.as_str(),
        body.read.0,
        body.write.0,
    )
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(StatusCode::CREATED)
}

async fn add_generation(
    State(relay): State<Relay>,
    Path((scheme, space, stream)): Path<(String, String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Json(body): Json<Generation>,
) -> Result<StatusCode, RelayError> {
    let (space, stream) = (space_id(&space)?, stream_id(&stream)?);
    let (domain, _) = relay.held_v2(&scheme, &space).await?;
    relay.device(domain, &space, &headers, &method, &uri, Some(Permission::Write)).await?;
    let shown = relay.token(&space, &stream, &headers, WRITE_HEADER).await?;
    let latest = relay.latest_generation(&space, &stream).await?.ok_or_else(not_found)?;
    if shown != latest {
        return Err(forbidden("the write token of the latest generation is needed"));
    }
    if body.generation != latest + 1 || body.read.0.len() != 32 || body.write.0.len() != 32 {
        return Err(RelayError(StatusCode::CONFLICT, "not the next generation".into()));
    }
    let inserted = sqlx::query!(
        "INSERT INTO relay_stream_tokens (space, stream, generation, read_hash, write_hash) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT DO NOTHING",
        space.as_str(),
        stream.as_str(),
        body.generation,
        body.read.0,
        body.write.0,
    )
    .execute(&relay.db)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Err(RelayError(StatusCode::CONFLICT, "not the next generation".into()));
    }
    Ok(StatusCode::CREATED)
}

async fn add_record(
    State(relay): State<Relay>,
    Path((scheme, space, stream)): Path<(String, String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, RelayError> {
    let (space, stream) = (space_id(&space)?, stream_id(&stream)?);
    let (domain, tenant) = relay.held_v2(&scheme, &space).await?;
    let (_, device) = relay.device(domain, &space, &headers, &method, &uri, Some(Permission::Write)).await?;
    let record: StreamRecord = from_root(&body).map_err(|e| bad(e.to_string()))?;
    if record.space != space || record.stream != stream || !record.is_authentic(domain, &device) {
        return Err(forbidden("the record is not one this device may send here"));
    }
    let inbox = sqlx::query_scalar!(
        "SELECT inbox FROM relay_streams WHERE space = $1 AND stream = $2",
        space.as_str(),
        stream.as_str(),
    )
    .fetch_optional(&relay.db)
    .await?
    .ok_or_else(not_found)?;
    let sealed_into_inbox = inbox && record.kind == RecordKind::Sealed && token_hash(&headers, WRITE_HEADER).is_none();
    if !sealed_into_inbox {
        relay.token(&space, &stream, &headers, WRITE_HEADER).await?;
        let latest = relay.latest_generation(&space, &stream).await?.unwrap_or(-1);
        if record.kind != RecordKind::Sealed && i64::from(record.generation) > i64::from(latest) {
            return Err(forbidden("no such generation yet"));
        }
    }
    let id = record.id.to_string();
    let canonical = to_root(&record).map_err(|e| bad(e.to_string()))?;
    let size = canonical.len() as i64;
    relay.within_quota(tenant, size).await?;
    let kind = match record.kind {
        RecordKind::Event => "event",
        RecordKind::Generation => "generation",
        RecordKind::Link => "link",
        RecordKind::Sealed => "sealed",
    };
    let mut transaction = relay.db.begin().await?;
    sqlx::query!(
        "SELECT stream FROM relay_streams WHERE space = $1 AND stream = $2 FOR UPDATE",
        space.as_str(),
        stream.as_str(),
    )
    .fetch_one(&mut *transaction)
    .await?;
    let position = sqlx::query_scalar!(
        r#"SELECT coalesce(max(position), 0) + 1 AS "next!" FROM relay_stream_records WHERE space = $1 AND stream = $2"#,
        space.as_str(),
        stream.as_str(),
    )
    .fetch_one(&mut *transaction)
    .await?;
    let inserted = sqlx::query!(
        "INSERT INTO relay_stream_records (space, stream, position, id, generation, kind, canonical)
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (space, stream, id) DO NOTHING",
        space.as_str(),
        stream.as_str(),
        position,
        id,
        record.generation as i32,
        kind,
        canonical,
    )
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if inserted > 0 {
        sqlx::query!(
            "UPDATE relay_streams SET bytes = bytes + $3 WHERE space = $1 AND stream = $2",
            space.as_str(),
            stream.as_str(),
            size,
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::query!(
            "UPDATE relay_spaces SET bytes = bytes + $2, written_at = now() WHERE space = $1",
            space.as_str(),
            size,
        )
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(if inserted > 0 { StatusCode::CREATED } else { StatusCode::OK })
}

async fn records(
    State(relay): State<Relay>,
    Path((scheme, space, stream)): Path<(String, String, String)>,
    Query(query): Query<After>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<Value>, RelayError> {
    let (space, stream) = (space_id(&space)?, stream_id(&stream)?);
    let (domain, _) = relay.held_v2(&scheme, &space).await?;
    relay.device(domain, &space, &headers, &method, &uri, None).await?;
    let generation = relay.token(&space, &stream, &headers, READ_HEADER).await?;
    let limit = query.limit.unwrap_or(PAGE).clamp(1, PAGE);
    let (records, more) = relay.records_for(&space, &stream, generation, query.after.unwrap_or(0), limit).await?;
    Ok(Json(json!({ "records": records, "more": more })))
}

#[derive(Debug, Deserialize)]
struct Followed {
    stream: StreamId,
    after: i64,
    /// The read token, base64url.
    read: String,
}

/// For each stream a device follows: what is new after its position – `{"streams": {stream: {records, more}}}`;
/// a stream whose token is not (or no longer) valid answers `{"error": …}`.
async fn follow(
    State(relay): State<Relay>,
    Path((scheme, space)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Json(followed): Json<Vec<Followed>>,
) -> Result<Json<Value>, RelayError> {
    let space = space_id(&space)?;
    let (domain, _) = relay.held_v2(&scheme, &space).await?;
    relay.device(domain, &space, &headers, &method, &uri, None).await?;
    if followed.len() > MAX_FOLLOW {
        return Err(bad("too many streams at once"));
    }
    let mut streams = serde_json::Map::new();
    for item in followed {
        let hash = from_base64url(&item.read).map(|token| Sha256Hash::of(&token).0.to_vec());
        let generation =
            match hash {
                Some(hash) => sqlx::query_scalar!(
                    "SELECT generation FROM relay_stream_tokens WHERE space = $1 AND stream = $2 AND read_hash = $3",
                    space.as_str(),
                    item.stream.as_str(),
                    hash,
                )
                .fetch_optional(&relay.db)
                .await?,
                None => None,
            };
        let answer = match generation {
            Some(generation) => {
                let (records, more) = relay.records_for(&space, &item.stream, generation, item.after, PAGE).await?;
                json!({ "records": records, "more": more })
            }
            None => json!({ "error": "not a token of this stream" }),
        };
        streams.insert(item.stream.to_string(), answer);
    }
    Ok(Json(json!({ "streams": streams })))
}

async fn add_original(
    State(relay): State<Relay>,
    Path((scheme, space, stream, hash)): Path<(String, String, String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, RelayError> {
    let (space, stream) = (space_id(&space)?, stream_id(&stream)?);
    let (domain, tenant) = relay.held_v2(&scheme, &space).await?;
    relay.device(domain, &space, &headers, &method, &uri, Some(Permission::Write)).await?;
    relay.token(&space, &stream, &headers, WRITE_HEADER).await?;
    let expected: Sha256Hash = hash.parse().map_err(|_| bad("not a hash"))?;
    if Sha256Hash::of(&body) != expected {
        return Err(bad("the bytes are not those of the hash"));
    }
    let known = sqlx::query_scalar!(
        "SELECT size FROM relay_stream_originals WHERE space = $1 AND stream = $2 AND hash = $3",
        space.as_str(),
        stream.as_str(),
        hash,
    )
    .fetch_optional(&relay.db)
    .await?;
    if known.is_some() {
        return Ok(StatusCode::OK);
    }
    let size = body.len() as i64;
    relay.within_quota(tenant, size).await?;
    let (content, blob) = if body.len() <= INLINE {
        (Some(body.to_vec()), None)
    } else {
        let key = format!("relay/{}/{}/{}", space.as_str(), stream.as_str(), expected.hex());
        garbage::pending(&relay.db, tenant, &key).await?;
        relay.blobs.put(tenant, &key, body).await?;
        (None, Some(key))
    };
    let mut transaction = relay.db.begin().await?;
    let inserted = sqlx::query!(
        "INSERT INTO relay_stream_originals (space, stream, hash, content, blob, size) VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT DO NOTHING",
        space.as_str(),
        stream.as_str(),
        hash,
        content,
        blob,
        size,
    )
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if inserted > 0 {
        sqlx::query!(
            "UPDATE relay_streams SET bytes = bytes + $3 WHERE space = $1 AND stream = $2",
            space.as_str(),
            stream.as_str(),
            size,
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::query!(
            "UPDATE relay_spaces SET bytes = bytes + $2, written_at = now() WHERE space = $1",
            space.as_str(),
            size,
        )
        .execute(&mut *transaction)
        .await?;
        if let Some(key) = &blob {
            garbage::keep(&mut transaction, tenant, key).await?;
        }
    }
    transaction.commit().await?;
    Ok(if inserted > 0 { StatusCode::CREATED } else { StatusCode::OK })
}

async fn original(
    State(relay): State<Relay>,
    Path((scheme, space, stream, hash)): Path<(String, String, String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Vec<u8>, RelayError> {
    let (space, stream) = (space_id(&space)?, stream_id(&stream)?);
    let (domain, tenant) = relay.held_v2(&scheme, &space).await?;
    relay.device(domain, &space, &headers, &method, &uri, None).await?;
    relay.token(&space, &stream, &headers, READ_HEADER).await?;
    let row = sqlx::query!(
        "SELECT content, blob FROM relay_stream_originals WHERE space = $1 AND stream = $2 AND hash = $3",
        space.as_str(),
        stream.as_str(),
        hash,
    )
    .fetch_optional(&relay.db)
    .await?
    .ok_or_else(|| RelayError(StatusCode::NOT_FOUND, "no such original".into()))?;
    match (row.content, row.blob) {
        (Some(content), _) => Ok(content),
        (None, Some(key)) => Ok(relay.blobs.get(tenant, &key).await?.to_vec()),
        (None, None) => Err(bad("a stored original has no content")),
    }
}

async fn remove_stream(
    State(relay): State<Relay>,
    Path((scheme, space, stream)): Path<(String, String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<StatusCode, RelayError> {
    let (space, stream) = (space_id(&space)?, stream_id(&stream)?);
    let (domain, tenant) = relay.held_v2(&scheme, &space).await?;
    relay.device(domain, &space, &headers, &method, &uri, Some(Permission::Purge)).await?;
    relay.token(&space, &stream, &headers, WRITE_HEADER).await?;
    let mut transaction = relay.db.begin().await?;
    let blobs = sqlx::query_scalar!(
        r#"SELECT blob AS "blob!" FROM relay_stream_originals WHERE space = $1 AND stream = $2 AND blob IS NOT NULL"#,
        space.as_str(),
        stream.as_str(),
    )
    .fetch_all(&mut *transaction)
    .await?;
    let bytes = sqlx::query_scalar!(
        "DELETE FROM relay_streams WHERE space = $1 AND stream = $2 RETURNING bytes",
        space.as_str(),
        stream.as_str(),
    )
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(not_found)?;
    sqlx::query!(
        "UPDATE relay_spaces SET bytes = greatest(bytes - $2, 0), written_at = now() WHERE space = $1",
        space.as_str(),
        bytes,
    )
    .execute(&mut *transaction)
    .await?;
    for key in blobs {
        garbage::mark_now(&mut transaction, tenant, &key).await?;
    }
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn add_request(
    State(relay): State<Relay>,
    Path((scheme, space)): Path<(String, String)>,
    body: Bytes,
) -> Result<StatusCode, RelayError> {
    let space = space_id(&space)?;
    relay.held_v2(&scheme, &space).await?;
    let request: Joining = from_root(&body).map_err(|e| bad(e.to_string()))?;
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
        request.device.id.hex(),
        canonical,
    )
    .execute(&relay.db)
    .await?;
    Ok(StatusCode::CREATED)
}

async fn requests(
    State(relay): State<Relay>,
    Path((scheme, space)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<Vec<Value>>, RelayError> {
    let space = space_id(&space)?;
    let (domain, _) = relay.held_v2(&scheme, &space).await?;
    // A device of the person who invites adds its own devices; one with `members` adds anyone.
    relay.device(domain, &space, &headers, &method, &uri, None).await?;
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
