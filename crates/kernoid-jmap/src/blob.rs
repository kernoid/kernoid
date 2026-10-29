// SPDX-License-Identifier: AGPL-3.0-or-later
//! Blobs (RFC 8620, 6): an email's raw message (`m-…`), one of its parts (`p-…-n`), an upload (`u-…`), or the
//! content of a file (`f-…`, RFC 0005, 8).

use bytes::Bytes;
use futures_util::{Stream, stream};
use mail_parser::{MessageParser, MimeHeaders, PartType};
use serde_json::{Value, json};
use uuid::Uuid;

use kernoid_mail::{Access, EmailInfo, Rights};

use crate::{Caller, Jmap};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobId {
    Email(Uuid),
    /// A part of an email, by its index among the message's parts.
    Part(Uuid, usize),
    Upload(Uuid),
    /// The content of a file, by its content id.
    File(Uuid),
}

impl BlobId {
    pub fn parse(value: &str) -> Option<Self> {
        if let Some(id) = value.strip_prefix("m-") {
            return Uuid::parse_str(id).ok().map(Self::Email);
        }
        if let Some(id) = value.strip_prefix("u-") {
            return Uuid::parse_str(id).ok().map(Self::Upload);
        }
        if let Some(id) = value.strip_prefix("f-") {
            return Uuid::parse_str(id).ok().map(Self::File);
        }
        let rest = value.strip_prefix("p-")?;
        let (id, part) = rest.rsplit_once('-')?;
        Some(Self::Part(Uuid::parse_str(id).ok()?, part.parse().ok()?))
    }
}

impl std::fmt::Display for BlobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Email(id) => write!(f, "m-{id}"),
            Self::Part(id, part) => write!(f, "p-{id}-{part}"),
            Self::Upload(id) => write!(f, "u-{id}"),
            Self::File(id) => write!(f, "f-{id}"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("no such blob")]
    NotFound,
    #[error("no such account")]
    Forbidden,
    #[error("{0}")]
    TooLarge(String),
    #[error(transparent)]
    Mail(#[from] kernoid_mail::MailError),
    #[error(transparent)]
    Files(#[from] kernoid_files::FilesError),
    #[error(transparent)]
    Blob(#[from] kernoid_store::BlobError),
    /// The malware scanner refused it.
    #[error(transparent)]
    Refused(#[from] kernoid_store::scan::Refused),
}

/// Whether an email is in a mailbox the caller may read (RFC 0002, 12.2).
pub(crate) fn readable(email: &EmailInfo, access: &Access) -> bool {
    access.owned || email.mailboxes.iter().any(|(mailbox, _)| access.mailbox(*mailbox).contains(Rights::READ))
}

/// The decoded content of part `index` of `raw`.
pub(crate) fn part_content(raw: &[u8], index: usize) -> Option<Bytes> {
    let message = MessageParser::new().parse(raw)?;
    let part = message.parts.get(index)?;
    Some(match &part.body {
        PartType::Text(text) | PartType::Html(text) => Bytes::from(text.as_bytes().to_vec()),
        PartType::Binary(bytes) | PartType::InlineBinary(bytes) => Bytes::from(bytes.to_vec()),
        PartType::Message(_) | PartType::Multipart(_) => {
            Bytes::from(raw.get(part.offset_body as usize..part.offset_end as usize)?.to_vec())
        }
    })
}

/// The largest embedded image an email's view takes, and all of them together.
const MAX_EMBEDDED: usize = 5 * 1024 * 1024;
const MAX_EMBEDDED_ALL: usize = 20 * 1024 * 1024;

/// An email's HTML part as a page of its own, for the original view: its text, the images it embeds (`cid:`) as
/// `data:` URLs, links opening outside the frame. The server sends it with a policy that runs nothing, sends nothing
/// and loads nothing from elsewhere – a sandbox without scripts or forms.
fn email_view(raw: &[u8], index: usize) -> Option<String> {
    use base64::Engine;
    let message = MessageParser::new().parse(raw)?;
    let PartType::Html(html) = &message.parts.get(index)?.body else { return None };
    let mut html = html.to_string();
    let mut budget = MAX_EMBEDDED_ALL;
    for part in &message.parts {
        let (Some(id), PartType::Binary(bytes) | PartType::InlineBinary(bytes)) = (part.content_id(), &part.body)
        else {
            continue;
        };
        let kind = part.content_type().map(|kind| match kind.subtype() {
            Some(sub) => format!("{}/{sub}", kind.ctype()),
            None => kind.ctype().to_owned(),
        });
        let Some(kind) = kind.filter(|kind| kind.starts_with("image/")) else { continue };
        if bytes.len() > MAX_EMBEDDED || bytes.len() > budget {
            continue;
        }
        let reference = format!("cid:{}", id.trim_start_matches('<').trim_end_matches('>'));
        if html.contains(&reference) {
            budget -= bytes.len();
            let data = format!("data:{kind};base64,{}", base64::engine::general_purpose::STANDARD.encode(bytes));
            html = html.replace(&reference, &data);
        }
    }
    Some(format!("<meta charset=\"utf-8\"><base target=\"_blank\">{html}"))
}

/// A blob to send, as it is read: from byte `start` to `end` (exclusive) of `size`.
pub struct Download {
    pub size: u64,
    pub start: u64,
    pub end: u64,
    pub kind: Option<String>,
    pub content: std::pin::Pin<Box<dyn Stream<Item = Result<Bytes, kernoid_store::BlobError>> + Send>>,
}

impl std::fmt::Debug for Download {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Download")
            .field("size", &self.size)
            .field("start", &self.start)
            .field("end", &self.end)
            .finish()
    }
}

impl Download {
    /// The bytes, read to the end – for what is known to be small.
    pub async fn collect(mut self) -> Result<Bytes, kernoid_store::BlobError> {
        use futures_util::StreamExt;
        let mut out = Vec::with_capacity((self.end - self.start) as usize);
        while let Some(part) = self.content.next().await {
            out.extend_from_slice(&part?);
        }
        Ok(Bytes::from(out))
    }

    fn whole(content: Bytes, kind: Option<String>, range: Option<(u64, Option<u64>)>) -> Self {
        let size = content.len() as u64;
        let (start, end) = bounds(size, range);
        let part = content.slice(start as usize..end as usize);
        Self { size, start, end, kind, content: Box::pin(stream::once(async move { Ok(part) })) }
    }
}

/// The bytes a range asks for – from `start` to an inclusive end, or to the end – within `size`; all without one.
pub(crate) fn bounds(size: u64, range: Option<(u64, Option<u64>)>) -> (u64, u64) {
    match range {
        Some((start, last)) => {
            let end = last.map_or(size, |last| last.saturating_add(1)).min(size);
            (start.min(end), end)
        }
        None => (0, size),
    }
}

/// What the caller may do in an account: with its mail, with its files.
struct Reach {
    owner: Uuid,
    mail: Option<Access>,
    files: Option<kernoid_files::FileAccess>,
}

impl Jmap {
    /// The account the caller names, if it is theirs or – mail or files – shared with them.
    async fn reach(&self, caller: &Caller, account: &str) -> Result<Reach, BlobError> {
        let owner = Uuid::parse_str(account).map_err(|_| BlobError::Forbidden)?;
        let mail = match caller.mail {
            true => Some(self.mail().access(caller.account, owner).await?).filter(Access::any),
            false => None,
        };
        let files = self.file_access(caller, owner).await?;
        if mail.is_none() && files.is_none() && !(owner == caller.account && (caller.mail || caller.files)) {
            return Err(BlobError::Forbidden);
        }
        Ok(Reach { owner, mail, files })
    }

    /// Whether the caller may read email `id` of the store: it is in a mailbox they may read.
    pub(crate) async fn may_read(&self, access: &Access, id: Uuid) -> Result<bool, kernoid_mail::MailError> {
        if access.owned {
            return Ok(true);
        }
        Ok(self.mail().emails(access.owner, &[id]).await?.first().is_some_and(|email| readable(email, access)))
    }

    /// A blob, or the part of it `range` asks for (from a start to an inclusive end, or to the end), and its type
    /// where kernoid knows it.
    pub async fn download(
        &self,
        caller: &Caller,
        account: &str,
        blob: &str,
        range: Option<(u64, Option<u64>)>,
    ) -> Result<Download, BlobError> {
        let reach = self.reach(caller, account).await?;
        let account = reach.owner;
        let not_found = |error: kernoid_mail::MailError| match error {
            kernoid_mail::MailError::NotFound(_) => BlobError::NotFound,
            other => BlobError::Mail(other),
        };
        let blob = BlobId::parse(blob).ok_or(BlobError::NotFound)?;
        let mail_access = || reach.mail.as_ref().ok_or(BlobError::NotFound);
        match blob {
            BlobId::Email(id) | BlobId::Part(id, _) if !self.may_read(mail_access()?, id).await? => {
                Err(BlobError::NotFound)
            }
            BlobId::Email(id) => {
                let raw = self.mail().raw_email(account, id).await.map_err(not_found)?;
                Ok(Download::whole(raw, Some("message/rfc822".into()), range))
            }
            BlobId::Part(id, part) => {
                let raw = self.mail().raw_email(account, id).await.map_err(not_found)?;
                Ok(Download::whole(part_content(&raw, part).ok_or(BlobError::NotFound)?, None, range))
            }
            BlobId::Upload(id) => {
                let upload = self.mail().upload_info(account, id).await.map_err(not_found)?;
                let (start, end) = bounds(upload.size, range);
                Ok(Download {
                    size: upload.size,
                    start,
                    end,
                    content: self.mail().read_upload(&upload, start, end),
                    kind: Some(upload.content_type),
                })
            }
            BlobId::File(content) => match self.file_content(caller, account, content, range).await {
                Ok(download) => Ok(Download {
                    size: download.size,
                    start: download.start,
                    end: download.end,
                    kind: Some(download.media_type),
                    content: download.content,
                }),
                Err(kernoid_files::FilesError::NotFound(_)) => Err(BlobError::NotFound),
                Err(error) => Err(error.into()),
            },
        }
    }

    /// Stores an upload (RFC 8620, 6.1) as it arrives; the answer names its blob. Uploads go to an account whose mail
    /// the caller may change, or whose files it may add to or write.
    pub async fn upload<S, E>(&self, caller: &Caller, account: &str, kind: &str, content: S) -> Result<Value, BlobError>
    where
        S: Stream<Item = Result<Bytes, E>>,
        E: std::fmt::Display,
    {
        let reach = self.reach(caller, account).await?;
        let writes_files = reach.files.as_ref().is_some_and(|access| {
            let writing = |rights: kernoid_files::Rights| {
                rights.contains(kernoid_files::Rights::ADD) || rights.contains(kernoid_files::Rights::WRITE)
            };
            access.owned || writing(access.store) || access.nodes.values().any(|rights| writing(*rights))
        });
        let own = reach.owner == caller.account;
        if !own && !writes_files && !reach.mail.as_ref().is_some_and(Access::may_change) {
            return Err(BlobError::Forbidden);
        }
        let account = reach.owner;
        let (id, size) =
            self.mail().put_upload(account, kind, content, self.max_size).await.map_err(|error| match error {
                kernoid_mail::MailError::TooLarge { .. } => BlobError::TooLarge(error.to_string()),
                kernoid_mail::MailError::Refused(refused) => BlobError::Refused(refused),
                other => BlobError::Mail(other),
            })?;
        Ok(
            json!({ "accountId": account.to_string(), "blobId": BlobId::Upload(id).to_string(), "type": kind, "size": size }),
        )
    }

    /// Stores an upload that is in memory already.
    pub async fn upload_bytes(
        &self,
        caller: &Caller,
        account: &str,
        kind: &str,
        content: Bytes,
    ) -> Result<Value, BlobError> {
        self.upload(caller, account, kind, stream::iter([Ok::<_, std::convert::Infallible>(content)])).await
    }

    /// The HTML part `blob` of an email the caller may read, as a page of its own (`email_view`).
    pub async fn email_view(&self, caller: &Caller, account: &str, blob: &str) -> Result<String, BlobError> {
        // Whether the caller may read it, as for a download.
        self.download(caller, account, blob, Some((0, Some(0)))).await?;
        let Some(BlobId::Part(id, index)) = BlobId::parse(blob) else { return Err(BlobError::NotFound) };
        let owner = Uuid::parse_str(account).map_err(|_| BlobError::NotFound)?;
        let raw = self.mail().raw_email(owner, id).await.map_err(|_| BlobError::NotFound)?;
        email_view(&raw, index).ok_or(BlobError::NotFound)
    }

    /// The raw content of a blob the caller may use as a message (`Email/import`, `Email/parse`).
    pub(crate) async fn blob_bytes(&self, access: &Access, blob: &str) -> Option<Bytes> {
        let account = access.owner;
        let blob = BlobId::parse(blob)?;
        if let BlobId::Email(id) | BlobId::Part(id, _) = blob
            && !self.may_read(access, id).await.ok()?
        {
            return None;
        }
        match blob {
            BlobId::Email(id) => self.mail().raw_email(account, id).await.ok(),
            BlobId::Part(id, part) => part_content(&self.mail().raw_email(account, id).await.ok()?, part),
            BlobId::Upload(id) => self.mail().upload(account, id).await.ok().map(|(content, _)| content),
            BlobId::File(content) if access.owned => {
                let files = self.files()?;
                let readable = files.readable(&kernoid_files::FileAccess::own(account), content).await.ok()?;
                files.read_all(&readable.content, self.max_size).await.ok()
            }
            BlobId::File(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_html_part_with_its_embedded_images() {
        let raw = "From: a@x.example\r\nTo: b@x.example\r\nSubject: News\r\nMIME-Version: 1.0\r\n\
            Content-Type: multipart/related; boundary=b\r\n\r\n--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n\
            <p style=\"color:red\">Grüße <img src=\"cid:logo@x\"> <img src=\"https://tracker.example/p.gif\"></p>\r\n\
            --b\r\nContent-Type: image/png\r\nContent-ID: <logo@x>\r\nContent-Transfer-Encoding: base64\r\n\r\n\
            iVBORw0KGgo=\r\n--b--\r\n";
        let view = email_view(raw.as_bytes(), 1).unwrap();
        assert!(view.starts_with("<meta charset=\"utf-8\"><base target=\"_blank\">"), "{view}");
        assert!(view.contains("style=\"color:red\">Grüße"), "{view}");
        assert!(view.contains("src=\"data:image/png;base64,iVBORw0KGgo=\""), "{view}");
        // Remote images stay as they are: the page's policy does not load them.
        assert!(view.contains("https://tracker.example/p.gif"));
        assert_eq!(email_view(raw.as_bytes(), 2), None, "not an HTML part");
    }

    #[test]
    fn blob_ids_round_trip() {
        let id = Uuid::now_v7();
        for blob in [BlobId::Email(id), BlobId::Part(id, 3), BlobId::Upload(id), BlobId::File(id)] {
            assert_eq!(BlobId::parse(&blob.to_string()), Some(blob));
        }
        assert_eq!(BlobId::parse("x-1"), None);
    }
}
