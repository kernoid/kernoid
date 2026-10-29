// SPDX-License-Identifier: AGPL-3.0-or-later
//! JMAP Blob Management (RFC 9404; RFC 0005, 5): `Blob/upload` makes a blob of pieces – other blobs or ranges of
//! them, and inline data – so that a client can upload a large file in pieces, send again only a piece that broke
//! off, and join them; `Blob/get` reads a blob's size, digest and (small) data; `Blob/lookup` tells which emails,
//! mailboxes, threads and files use a blob.

use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures_util::{Stream, StreamExt, stream};
use kernoid_store::scan::Refused;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    MAX_SIZE_REQUEST,
    blob::{BlobError, BlobId},
    mailbox::{ids, invalid_properties},
    request::{Context, MethodError, MethodResult},
};

pub const BLOB: &str = "urn:ietf:params:jmap:blob";
/// Pieces one `Blob/upload` may join.
pub const MAX_DATA_SOURCES: usize = 1024;
/// What `Blob/lookup` knows.
pub const TYPE_NAMES: [&str; 4] = ["Email", "Mailbox", "Thread", "FileNode"];

/// The capability (RFC 9404, 3) for an account of `max_size` bytes per blob.
pub fn capability(max_size: u64) -> Value {
    json!({
        "maxSizeBlobSet": max_size,
        "maxDataSources": MAX_DATA_SOURCES,
        "supportedTypeNames": TYPE_NAMES,
        "supportedDigestAlgorithms": ["sha-256"],
    })
}

type Piece = std::pin::Pin<Box<dyn Stream<Item = Result<Bytes, kernoid_store::BlobError>> + Send>>;

fn blob_error(error: BlobError) -> Value {
    match error {
        BlobError::NotFound | BlobError::Forbidden => json!({ "type": "blobNotFound" }),
        BlobError::TooLarge(description) => json!({ "type": "tooLarge", "description": description }),
        BlobError::Refused(refused @ Refused::Infected(_)) => {
            json!({ "type": "forbidden", "description": refused.to_string() })
        }
        BlobError::Refused(refused) => json!({ "type": "serverFail", "description": refused.to_string() }),
        _ => json!({ "type": "serverFail" }),
    }
}

impl Context<'_> {
    fn blob_account(&self, args: &Map<String, Value>) -> Result<String, MethodError> {
        args.get("accountId")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| MethodError::invalid("accountId is required"))
    }

    /// The pieces of one blob to make, checked before anything is written: each blob the caller may read.
    async fn pieces(&self, account: &str, data: &[Value]) -> Result<(Vec<Piece>, u64), Value> {
        if data.is_empty() || data.len() > MAX_DATA_SOURCES {
            return Err(json!({ "type": "tooManyDataSources", "description": "1 to 1024 data sources" }));
        }
        let mut pieces: Vec<Piece> = Vec::new();
        let mut size = 0u64;
        for source in data {
            let source = source.as_object().ok_or_else(|| invalid_properties("a data source is an object"))?;
            let inline = match (source.get("data:asText"), source.get("data:asBase64")) {
                (Some(Value::String(text)), None) => Some(Bytes::from(text.clone().into_bytes())),
                (None, Some(Value::String(encoded))) => Some(Bytes::from(
                    STANDARD.decode(encoded).map_err(|_| invalid_properties("data:asBase64 is not base64"))?,
                )),
                (None, None) => None,
                _ => return Err(invalid_properties("a data source has one kind of data")),
            };
            if let Some(bytes) = inline {
                size += bytes.len() as u64;
                pieces.push(Box::pin(stream::once(async move { Ok(bytes) })));
                continue;
            }
            let blob = source.get("blobId").and_then(Value::as_str).ok_or_else(|| invalid_properties("blobId"))?;
            let number = |key: &str| match source.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(value) => value.as_u64().map(Some).ok_or_else(|| invalid_properties(format!("{key} is a number"))),
            };
            let (offset, length) = (number("offset")?.unwrap_or(0), number("length")?);
            let range = match length {
                Some(0) => continue,
                Some(length) => Some((offset, Some(offset + length - 1))),
                None if offset > 0 => Some((offset, None)),
                None => None,
            };
            let download = self.jmap.download(self.caller, account, blob, range).await.map_err(blob_error)?;
            if offset > download.size || length.is_some_and(|length| offset + length > download.size) {
                return Err(json!({ "type": "invalidProperties", "description": "the range is outside the blob" }));
            }
            size += download.end - download.start;
            pieces.push(download.content);
        }
        Ok((pieces, size))
    }

    /// `Blob/upload` (RFC 9404, 4.1).
    pub async fn blob_upload(&mut self, args: Map<String, Value>) -> MethodResult {
        let account = self.blob_account(&args)?;
        let mut created = Map::new();
        let mut not_created = Map::new();
        if let Some(Value::Object(create)) = args.get("create") {
            for (key, value) in create {
                let result = async {
                    let object = value.as_object().ok_or_else(|| invalid_properties("an upload is an object"))?;
                    let data =
                        object.get("data").and_then(Value::as_array).ok_or_else(|| invalid_properties("data"))?;
                    let kind = object.get("type").and_then(Value::as_str).unwrap_or("application/octet-stream");
                    let (pieces, _) = self.pieces(&account, data).await?;
                    let joined = stream::iter(pieces).flatten();
                    self.jmap.upload(self.caller, &account, kind, joined).await.map_err(blob_error)
                }
                .await;
                match result {
                    Ok(mut answer) => {
                        let id = answer["blobId"].clone();
                        if let Some(id) = id.as_str() {
                            self.created.insert(format!("#{key}"), id.to_owned());
                        }
                        answer["id"] = id;
                        let answer = json!({ "id": answer["id"], "type": answer["type"], "size": answer["size"] });
                        created.insert(key.clone(), answer);
                    }
                    Err(error) => {
                        not_created.insert(key.clone(), error);
                    }
                }
            }
        }
        let or_null = |map: Map<String, Value>| if map.is_empty() { Value::Null } else { Value::Object(map) };
        Ok(vec![(
            "Blob/upload".into(),
            json!({ "accountId": account, "created": or_null(created), "notCreated": or_null(not_created) }),
        )])
    }

    /// `Blob/get` (RFC 9404, 4.2): `size`, and of the range `offset` and `length` select `digest:sha-256` and the
    /// data – as text where it is UTF-8, else base64 – for at most the request limit of bytes (`isTruncated` beyond).
    pub async fn blob_get(&self, args: Map<String, Value>) -> MethodResult {
        let account = self.blob_account(&args)?;
        let list_ids = ids(&args)?.ok_or_else(|| MethodError::invalid("ids are required"))?;
        let properties: Vec<String> = match args.get("properties") {
            Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
            _ => vec!["data".into(), "size".into()],
        };
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let length = args.get("length").and_then(Value::as_u64);
        let wants = |name: &str| properties.iter().any(|property| property == name);
        let data_wanted = wants("data") || wants("data:asText") || wants("data:asBase64");
        let digest_wanted = wants("digest:sha-256");
        let mut list = Vec::new();
        let mut not_found = Vec::new();
        for id in list_ids {
            let Ok(download) = self.jmap.download(self.caller, &account, &id, None).await else {
                not_found.push(Value::String(id));
                continue;
            };
            let size = download.size;
            let mut object = json!({ "id": id });
            if wants("size") {
                object["size"] = json!(size);
            }
            if data_wanted || digest_wanted {
                let start = offset.min(size);
                let end = length.map_or(size, |length| start.saturating_add(length).min(size));
                let limit = start + (end - start).min(MAX_SIZE_REQUEST as u64);
                let mut hasher = Sha256::new();
                let mut data = Vec::new();
                let mut at = 0u64;
                let mut content = download.content;
                while let Some(chunk) = content.next().await {
                    let chunk = chunk.map_err(|_| MethodError::new("serverFail", "the blob could not be read"))?;
                    let (from, to) = (at, at + chunk.len() as u64);
                    let slice = |until: u64| {
                        let (keep_from, keep_to) = (start.max(from), until.min(to));
                        (keep_from < keep_to).then(|| &chunk[(keep_from - from) as usize..(keep_to - from) as usize])
                    };
                    if let Some(range) = slice(end) {
                        hasher.update(range);
                    }
                    if data_wanted && let Some(range) = slice(limit) {
                        data.extend_from_slice(range);
                    }
                    at = to;
                    if at >= if digest_wanted { end } else { limit } {
                        break;
                    }
                }
                if digest_wanted {
                    object["digest:sha-256"] = json!(STANDARD.encode(hasher.finalize()));
                }
                if data_wanted {
                    let text = String::from_utf8(data.clone()).ok();
                    if wants("data:asText") || (wants("data") && text.is_some()) {
                        match &text {
                            Some(text) => object["data:asText"] = json!(text),
                            None => {
                                object["data:asText"] = Value::Null;
                                object["isEncodingProblem"] = json!(true);
                            }
                        }
                    }
                    if wants("data:asBase64") || (wants("data") && text.is_none()) {
                        object["data:asBase64"] = json!(STANDARD.encode(&data));
                    }
                    if limit < end {
                        object["isTruncated"] = json!(true);
                    }
                }
            }
            list.push(object);
        }
        Ok(vec![("Blob/get".into(), json!({ "accountId": account, "list": list, "notFound": not_found }))])
    }

    /// `Blob/lookup` (RFC 9404, 4.3): the emails, mailboxes and threads an email's or a part's blob belongs to, the
    /// files whose content – current or a version – a file blob is. Uploads belong to nothing.
    pub async fn blob_lookup(&self, args: Map<String, Value>) -> MethodResult {
        let account = self.blob_account(&args)?;
        let owner = Uuid::parse_str(&account).map_err(|_| MethodError::new("accountNotFound", "no such account"))?;
        let type_names: Vec<String> = args
            .get("typeNames")
            .and_then(Value::as_array)
            .ok_or_else(|| MethodError::invalid("typeNames are required"))?
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        if let Some(unknown) = type_names.iter().find(|name| !TYPE_NAMES.contains(&name.as_str())) {
            return Err(MethodError::new("unknownDataType", format!("{unknown} is not known")));
        }
        let list_ids = ids(&args)?.ok_or_else(|| MethodError::invalid("ids are required"))?;
        let mut list = Vec::new();
        let mut not_found = Vec::new();
        for id in list_ids {
            if self.jmap.download(self.caller, &account, &id, Some((0, Some(0)))).await.is_err() {
                not_found.push(Value::String(id));
                continue;
            }
            let mut matched: Map<String, Value> = type_names.iter().map(|name| (name.clone(), json!([]))).collect();
            match BlobId::parse(&id) {
                Some(BlobId::Email(email) | BlobId::Part(email, _)) => {
                    if let Some(info) =
                        self.jmap.mail().emails(owner, &[email]).await.ok().and_then(|found| found.into_iter().next())
                    {
                        let mailboxes: Vec<String> =
                            info.mailboxes.iter().map(|(mailbox, _)| mailbox.to_string()).collect();
                        for (name, value) in matched.iter_mut() {
                            *value = match name.as_str() {
                                "Email" => json!([email.to_string()]),
                                "Thread" => json!([info.thread_id.to_string()]),
                                "Mailbox" => json!(mailboxes),
                                _ => json!([]),
                            };
                        }
                    }
                }
                Some(BlobId::File(content)) => {
                    if let (Some(files), Some(value)) = (self.jmap.files(), matched.get_mut("FileNode"))
                        && let Ok(Some(access)) = self.jmap.file_access(self.caller, owner).await
                        && let Ok(readable) = files.readable(&access, content).await
                    {
                        *value = json!([readable.info.node.to_string()]);
                    }
                }
                _ => {}
            }
            list.push(json!({ "id": id, "matchedIds": matched }));
        }
        Ok(vec![("Blob/lookup".into(), json!({ "accountId": account, "list": list, "notFound": not_found }))])
    }
}
