// SPDX-License-Identifier: AGPL-3.0-or-later
//! The API request (RFC 8620, 3): the envelope, result references (3.7), creation ids, and the methods it calls.

use std::collections::HashMap;

use serde_json::{Map, Value, json};
use uuid::Uuid;

use kernoid_mail::Access;

use crate::{
    CALENDARS, CONTACTS, CORE, Caller, FILE_LINKS, FILE_VERSIONS, FILENODE, Jmap, MAIL, MAX_CALLS_IN_REQUEST,
    PRINCIPALS, SUBMISSION, blob_methods::BLOB,
};

/// A request that cannot be run at all (RFC 8620, 3.6.1); answered as problem details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    NotJson,
    NotRequest(String),
    UnknownCapability(String),
    Limit(&'static str),
}

impl RequestError {
    /// The problem details object.
    pub fn problem(&self) -> Value {
        let (kind, detail) = match self {
            Self::NotJson => ("notJSON", "the request is not JSON".to_owned()),
            Self::NotRequest(detail) => ("notRequest", detail.clone()),
            Self::UnknownCapability(capability) => ("unknownCapability", format!("unknown capability {capability}")),
            Self::Limit(limit) => ("limit", format!("over the limit {limit}")),
        };
        let mut problem = json!({
            "type": format!("urn:ietf:params:jmap:error:{kind}"),
            "status": 400,
            "detail": detail,
        });
        if let Self::Limit(limit) = self {
            problem["limit"] = json!(limit);
        }
        problem
    }
}

/// An error of one method call (RFC 8620, 3.6.2).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MethodError {
    pub kind: &'static str,
    pub description: Option<String>,
}

impl MethodError {
    pub fn new(kind: &'static str, description: impl Into<String>) -> Self {
        Self { kind, description: Some(description.into()) }
    }

    pub fn invalid(description: impl Into<String>) -> Self {
        Self::new("invalidArguments", description)
    }

    pub fn server_fail(error: impl std::fmt::Display) -> Self {
        tracing::warn!(%error, "a JMAP method failed");
        Self { kind: "serverFail", description: None }
    }

    fn value(&self) -> Value {
        let mut value = json!({ "type": self.kind });
        if let Some(description) = &self.description {
            value["description"] = json!(description);
        }
        value
    }
}

impl From<kernoid_mail::MailError> for MethodError {
    fn from(error: kernoid_mail::MailError) -> Self {
        match error {
            kernoid_mail::MailError::CannotCalculateChanges => Self::new("cannotCalculateChanges", error.to_string()),
            kernoid_mail::MailError::NotFound(_) | kernoid_mail::MailError::Invalid(_) => {
                Self::invalid(error.to_string())
            }
            other => Self::server_fail(other),
        }
    }
}

impl From<kernoid_groupware::GroupwareError> for MethodError {
    fn from(error: kernoid_groupware::GroupwareError) -> Self {
        use kernoid_groupware::GroupwareError;
        match error {
            GroupwareError::CannotCalculateChanges => Self::new("cannotCalculateChanges", error.to_string()),
            GroupwareError::NotFound(_) | GroupwareError::Invalid(_) => Self::invalid(error.to_string()),
            other => Self::server_fail(other),
        }
    }
}

pub(crate) type MethodResult = Result<Vec<(String, Value)>, MethodError>;

/// What the methods of one request share.
pub(crate) struct Context<'a> {
    pub jmap: &'a Jmap,
    pub caller: &'a Caller,
    /// Creation ids of this request and the ids they became (RFC 8620, 5.3).
    pub created: HashMap<String, String>,
}

impl Context<'_> {
    /// The account `accountId` names and what the caller may do with its mail: its own, or one shared with it
    /// (RFC 0002, 12.2); any other is unknown.
    pub async fn access(&self, args: &Map<String, Value>) -> Result<Access, MethodError> {
        self.require_mail()?;
        let id = args
            .get("accountId")
            .and_then(Value::as_str)
            .ok_or_else(|| MethodError::invalid("accountId is required"))?;
        let not_found = || MethodError::new("accountNotFound", "no such account");
        let owner = Uuid::parse_str(id).map_err(|_| not_found())?;
        let access = self.jmap.mail.access(self.caller.account, owner).await?;
        if access.any() { Ok(access) } else { Err(not_found()) }
    }

    /// Mail, calendars and contacts are only for an account with the service `mail` (RFC 0003, 4).
    fn require_mail(&self) -> Result<(), MethodError> {
        if self.caller.mail {
            Ok(())
        } else {
            Err(MethodError::new("accountNotSupportedByMethod", "this account has no mail"))
        }
    }

    /// Calendars and contacts of this installation.
    pub fn groupware(&self) -> Result<&kernoid_groupware::Groupware, MethodError> {
        self.jmap.groupware.as_ref().ok_or_else(|| MethodError::new("unknownMethod", "no calendars and contacts here"))
    }

    /// The account `accountId` names and what the caller may do with its calendars and address books: its own, or
    /// one that shares some with it (RFC 0004, 9); any other is unknown.
    pub async fn groupware_access(
        &self,
        args: &Map<String, Value>,
    ) -> Result<(Uuid, kernoid_groupware::CollectionAccess), MethodError> {
        self.require_mail()?;
        let id = args
            .get("accountId")
            .and_then(Value::as_str)
            .ok_or_else(|| MethodError::invalid("accountId is required"))?;
        let not_found = || MethodError::new("accountNotFound", "no such account");
        let owner = Uuid::parse_str(id).map_err(|_| not_found())?;
        let access = self.groupware()?.access(self.caller.account, owner).await?;
        if access.any() { Ok((owner, access)) } else { Err(not_found()) }
    }

    /// An id, or `#creationId` of something created earlier in this request.
    pub fn id(&self, value: &str) -> Option<Uuid> {
        match value.strip_prefix('#') {
            Some(creation) => self.created.get(creation).and_then(|id| Uuid::parse_str(id).ok()),
            None => Uuid::parse_str(value).ok(),
        }
    }
}

/// Follows a JSON pointer, where `*` maps over an array and flattens arrays of arrays (RFC 8620, 3.7).
fn pointer(value: &Value, path: &str) -> Option<Value> {
    let Some(path) = path.strip_prefix('/') else { return if path.is_empty() { Some(value.clone()) } else { None } };
    let (token, rest) = match path.split_once('/') {
        Some((token, rest)) => (token, Some(rest)),
        None => (path, None),
    };
    let token = token.replace("~1", "/").replace("~0", "~");
    let next = |value: &Value| match rest {
        Some(rest) => pointer(value, &format!("/{rest}")),
        None => Some(value.clone()),
    };
    match value {
        Value::Array(items) if token == "*" => {
            let mut out = Vec::new();
            for item in items {
                match next(item)? {
                    Value::Array(inner) => out.extend(inner),
                    other => out.push(other),
                }
            }
            Some(Value::Array(out))
        }
        Value::Array(items) => next(items.get(token.parse::<usize>().ok()?)?),
        Value::Object(map) => next(map.get(&token)?),
        _ => None,
    }
}

/// Replaces `#name` arguments by what they refer to.
fn resolve(args: &mut Map<String, Value>, responses: &[(String, Value, String)]) -> Result<(), MethodError> {
    let references: Vec<String> = args.keys().filter(|key| key.starts_with('#')).cloned().collect();
    for key in references {
        let name = &key[1..];
        if args.contains_key(name) {
            return Err(MethodError::invalid(format!("both {name} and #{name}")));
        }
        let reference = args.remove(&key).unwrap_or_default();
        let (Some(of), Some(method), Some(path)) = (
            reference.get("resultOf").and_then(Value::as_str),
            reference.get("name").and_then(Value::as_str),
            reference.get("path").and_then(Value::as_str),
        ) else {
            return Err(MethodError::new("invalidResultReference", "resultOf, name and path are required"));
        };
        let found = responses
            .iter()
            .find(|(response, _, call)| call == of && response == method)
            .and_then(|(_, result, _)| pointer(result, path))
            .ok_or_else(|| MethodError::new("invalidResultReference", format!("no result for #{name}")))?;
        args.insert(name.to_owned(), found);
    }
    Ok(())
}

impl Jmap {
    /// Runs an API request (RFC 8620, 3.3) for `caller`.
    pub async fn api(&self, caller: &Caller, body: &[u8]) -> Result<Value, RequestError> {
        let request: Value = serde_json::from_slice(body).map_err(|_| RequestError::NotJson)?;
        let using = request
            .get("using")
            .and_then(Value::as_array)
            .ok_or_else(|| RequestError::NotRequest("using is required".into()))?;
        for capability in using {
            let capability = capability.as_str().unwrap_or_default();
            if ![CORE, MAIL, SUBMISSION, CALENDARS, CONTACTS, FILENODE, FILE_VERSIONS, FILE_LINKS, PRINCIPALS, BLOB]
                .contains(&capability)
            {
                return Err(RequestError::UnknownCapability(capability.to_owned()));
            }
        }
        let calls = request
            .get("methodCalls")
            .and_then(Value::as_array)
            .ok_or_else(|| RequestError::NotRequest("methodCalls is required".into()))?;
        if calls.len() > MAX_CALLS_IN_REQUEST {
            return Err(RequestError::Limit("maxCallsInRequest"));
        }
        let mut context = Context { jmap: self, caller, created: HashMap::new() };
        if let Some(Value::Object(ids)) = request.get("createdIds") {
            for (creation, id) in ids {
                if let Some(id) = id.as_str() {
                    context.created.insert(creation.clone(), id.to_owned());
                }
            }
        }
        let mut responses: Vec<(String, Value, String)> = Vec::new();
        for call in calls {
            let (Some(name), Some(Value::Object(args)), Some(id)) =
                (call.get(0).and_then(Value::as_str), call.get(1), call.get(2).and_then(Value::as_str))
            else {
                return Err(RequestError::NotRequest("a method call is [name, arguments, id]".into()));
            };
            let mut args = args.clone();
            let result = match resolve(&mut args, &responses) {
                Ok(()) => self.call(&mut context, name, args).await,
                Err(error) => Err(error),
            };
            match result {
                Ok(results) => {
                    for (response, value) in results {
                        responses.push((response, value, id.to_owned()));
                    }
                }
                Err(error) => responses.push(("error".into(), error.value(), id.to_owned())),
            }
        }
        let session_state = self.session_state(caller).await.unwrap_or_default();
        let mut response = json!({
            "methodResponses": responses.into_iter().map(|(name, value, id)| json!([name, value, id])).collect::<Vec<_>>(),
            "sessionState": session_state,
        });
        if request.get("createdIds").is_some() {
            response["createdIds"] = json!(context.created);
        }
        Ok(response)
    }

    async fn call(&self, context: &mut Context<'_>, name: &str, args: Map<String, Value>) -> MethodResult {
        match name {
            "Core/echo" => Ok(vec![("Core/echo".into(), Value::Object(args))]),
            "Mailbox/get" => context.mailbox_get(args).await,
            "Mailbox/changes" => context.changes(args, kernoid_mail::ObjectType::Mailbox, "Mailbox/changes").await,
            "Mailbox/query" => context.mailbox_query(args).await,
            "Mailbox/queryChanges" | "Email/queryChanges" => {
                Err(MethodError::new("cannotCalculateChanges", "query again"))
            }
            "Mailbox/set" => context.mailbox_set(args).await,
            "Email/get" => context.email_get(args).await,
            "Email/changes" => context.changes(args, kernoid_mail::ObjectType::Email, "Email/changes").await,
            "Email/query" => context.email_query(args).await,
            "Email/set" => context.email_set(args).await,
            "Email/import" => context.email_import(args).await,
            "Email/parse" => context.email_parse(args).await,
            "Thread/get" => context.thread_get(args).await,
            "Thread/changes" => context.changes(args, kernoid_mail::ObjectType::Thread, "Thread/changes").await,
            "Identity/get" => context.identity_get(args).await,
            "Identity/changes" => Err(MethodError::new("cannotCalculateChanges", "get the identities again")),
            "EmailSubmission/set" => context.submission_set(args).await,
            "EmailSubmission/get" => context.submission_get(args).await,
            "SearchSnippet/get" => context.snippet_get(args).await,
            "AddressBook/get" => context.addressbook_get(args).await,
            "AddressBook/changes" => {
                context.groupware_changes(args, kernoid_groupware::ObjectType::AddressBook, "AddressBook/changes").await
            }
            "AddressBook/set" => context.addressbook_set(args).await,
            "ContactCard/get" => context.contact_get(args).await,
            "ContactCard/changes" => {
                context.groupware_changes(args, kernoid_groupware::ObjectType::Contact, "ContactCard/changes").await
            }
            "ContactCard/query" => context.contact_query(args).await,
            "ContactCard/queryChanges" | "CalendarEvent/queryChanges" => {
                Err(MethodError::new("cannotCalculateChanges", "query again"))
            }
            "ContactCard/set" => context.contact_set(args).await,
            "Calendar/get" => context.calendar_get(args).await,
            "Calendar/changes" => {
                context.groupware_changes(args, kernoid_groupware::ObjectType::Calendar, "Calendar/changes").await
            }
            "Calendar/set" => context.calendar_set(args).await,
            "CalendarEvent/get" => context.event_get(args).await,
            "CalendarEvent/changes" => {
                context.groupware_changes(args, kernoid_groupware::ObjectType::Event, "CalendarEvent/changes").await
            }
            "CalendarEvent/query" => context.event_query(args).await,
            "CalendarEvent/set" => context.event_set(args).await,
            "CalendarEvent/parse" => context.event_parse(args).await,
            "CalendarEventNotification/get" => context.notification_get(args).await,
            "CalendarEventNotification/changes" => {
                context
                    .groupware_changes(
                        args,
                        kernoid_groupware::ObjectType::Notification,
                        "CalendarEventNotification/changes",
                    )
                    .await
            }
            "CalendarEventNotification/set" => context.notification_set(args).await,
            "ParticipantIdentity/get" => context.participant_identity_get(args).await,
            "FileNode/get" => context.file_get(args).await,
            "FileNode/changes" => context.file_changes(args).await,
            "FileNode/set" => context.file_set(args).await,
            "FileNode/copy" => context.file_copy(args).await,
            "FileNode/query" => context.file_query(args).await,
            "FileNode/queryChanges" => Err(MethodError::new("cannotCalculateChanges", "query again")),
            "FileVersion/get" => context.file_versions(args).await,
            "Blob/upload" => context.blob_upload(args).await,
            "Blob/get" => context.blob_get(args).await,
            "Blob/lookup" => context.blob_lookup(args).await,
            "FileLink/get" => context.file_link_get(args).await,
            "FileLink/set" => context.file_link_set(args).await,
            "Principal/get" => context.principal_get(args).await,
            "Principal/query" => context.principal_query(args).await,
            _ => Err(MethodError::new("unknownMethod", format!("{name} is not known"))),
        }
    }
}

impl Context<'_> {
    /// `*/changes` (RFC 8620, 5.2): every type shares the account's state.
    pub async fn changes(&self, args: Map<String, Value>, kind: kernoid_mail::ObjectType, name: &str) -> MethodResult {
        let account = self.access(&args).await?.owner;
        let since = args
            .get("sinceState")
            .and_then(Value::as_str)
            .and_then(|state| state.parse::<u64>().ok())
            .ok_or_else(|| MethodError::new("cannotCalculateChanges", "unknown state"))?;
        let max = args.get("maxChanges").and_then(Value::as_u64).map(|max| max as usize);
        if max == Some(0) {
            return Err(MethodError::invalid("maxChanges must be positive"));
        }
        let changes = self.jmap.mail.changes(account, kind, since, max).await?;
        let ids = |ids: Vec<Uuid>| ids.into_iter().map(|id| id.to_string()).collect::<Vec<_>>();
        let mut response = json!({
            "accountId": account.to_string(),
            "oldState": changes.old_state.to_string(),
            "newState": changes.new_state.to_string(),
            "hasMoreChanges": changes.has_more_changes,
            "created": ids(changes.created),
            "updated": ids(changes.updated),
            "destroyed": ids(changes.destroyed),
        });
        if kind == kernoid_mail::ObjectType::Mailbox {
            response["updatedProperties"] = Value::Null;
        }
        Ok(vec![(name.to_owned(), response)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointers_map_over_arrays() {
        let result = json!({ "ids": ["a", "b"], "list": [{ "threadId": "t1", "emailIds": ["e1", "e2"] }, { "threadId": "t2", "emailIds": ["e3"] }] });
        assert_eq!(pointer(&result, "/ids"), Some(json!(["a", "b"])));
        assert_eq!(pointer(&result, "/list/*/threadId"), Some(json!(["t1", "t2"])));
        assert_eq!(pointer(&result, "/list/*/emailIds"), Some(json!(["e1", "e2", "e3"])));
        assert_eq!(pointer(&result, "/list/1/threadId"), Some(json!("t2")));
        assert_eq!(pointer(&result, "/missing"), None);
    }
}
