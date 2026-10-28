// SPDX-License-Identifier: AGPL-3.0-or-later
//! The CalDAV and CardDAV server (RFC 0004, 8.1): one request in, one response out. Logging in is the caller's – it
//! hands over the account; this decides by the account's own homes and the levels shared with it.

use std::collections::HashMap;

use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use kernoid_groupware::{
    AddressBookUpdate, CalendarUpdate, Expect, Groupware, GroupwareError, Level, NewAddressBook, NewCalendar,
    PrincipalInfo, ScheduleRefusal, ical,
};
use uuid::Uuid;

use crate::{
    node::{Collection, Node},
    path::{self, Target},
    props::{Content, parse_sync_token, sync_token},
    proto::{
        Depth, RequestHeaders,
        parser::{DavParser, tokenizer::Tokenizer},
        schema::{
            Namespace,
            property::{CalDavProperty, DavProperty, DavValue, WebDavProperty},
            request::{DavPropertyValue, MkCol, MultiGet, PropFind, PropertyUpdate, Report},
            response::{
                BaseCondition, CalCondition, CardCondition, Condition, ErrorResponse, Href, List, MkColResponse,
                MultiStatus, PropStat, Response,
            },
        },
        types::dead_property::{DeadProperty, DeadPropertyTag},
    },
    query,
};

/// One DAV request of a logged-in account.
#[derive(Debug)]
pub struct DavRequest {
    pub method: Method,
    /// The request's path, percent-encoded as received.
    pub path: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub account: Uuid,
}

pub type DavResponse = http::Response<Vec<u8>>;

#[derive(Debug)]
pub(crate) enum Error {
    NotFound,
    Forbidden,
    Status(StatusCode),
    Condition(StatusCode, Condition),
    Groupware(GroupwareError),
    Other(String),
}

impl Error {
    pub(crate) fn other(error: impl std::fmt::Display) -> Self {
        Self::Other(error.to_string())
    }
}

impl From<crate::proto::parser::Error> for Error {
    fn from(_: crate::proto::parser::Error) -> Self {
        Self::Status(StatusCode::BAD_REQUEST)
    }
}

#[derive(Debug, Clone)]
pub struct Dav {
    pub(crate) groupware: Groupware,
}

/// What the server offers (`DAV` header of `OPTIONS`).
const COMPLIANCE: &str = "1, 3, access-control, calendar-access, calendar-schedule, calendar-auto-schedule, \
                          addressbook, extended-mkcol, calendarserver-principal-property-search";

fn xml(status: StatusCode, body: impl std::fmt::Display) -> DavResponse {
    let mut response = http::Response::new(body.to_string().into_bytes());
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/xml; charset=utf-8"));
    response
}

fn status(status: StatusCode) -> DavResponse {
    let mut response = http::Response::new(Vec::new());
    *response.status_mut() = status;
    response
}

fn condition(code: StatusCode, condition: impl Into<Condition>) -> DavResponse {
    let condition = condition.into();
    let namespace = match condition {
        Condition::Cal(_) => Namespace::CalDav,
        Condition::Card(_) => Namespace::CardDav,
        Condition::Base(_) => Namespace::Dav,
    };
    xml(code, ErrorResponse::new(condition).with_namespace(namespace))
}

/// The ETag header value of an object or collection.
fn etag(modseq: i64) -> HeaderValue {
    HeaderValue::from_str(&format!("\"{modseq}\"")).expect("digits")
}

/// `If-Match` / `If-None-Match: *` of a write (RFC 4918, 10.4; RFC 7232).
fn expect(headers: &HeaderMap) -> Expect {
    if headers.get(header::IF_NONE_MATCH).is_some_and(|value| value.as_bytes() == b"*") {
        return Expect::New;
    }
    match headers.get(header::IF_MATCH).and_then(|value| value.to_str().ok()) {
        Some("*") | None => Expect::Any,
        Some(value) => value
            .split(',')
            .find_map(|tag| tag.trim().trim_start_matches("W/").trim_matches('"').parse().ok())
            .map_or(Expect::Version(-1), Expect::Version),
    }
}

impl Dav {
    pub fn new(groupware: Groupware) -> Self {
        Self { groupware }
    }

    pub fn groupware(&self) -> &Groupware {
        &self.groupware
    }

    pub async fn handle(&self, request: DavRequest) -> DavResponse {
        let is_calendar_path = request.path.contains("/calendars/");
        match self.dispatch(&request).await {
            Ok(response) => response,
            Err(Error::NotFound) => status(StatusCode::NOT_FOUND),
            Err(Error::Forbidden) => condition(StatusCode::FORBIDDEN, BaseCondition::NeedPrivileges(List(vec![]))),
            Err(Error::Status(code)) => status(code),
            Err(Error::Condition(code, condition_)) => condition(code, condition_),
            Err(Error::Groupware(error)) => match error {
                GroupwareError::NotFound(_) => status(StatusCode::NOT_FOUND),
                GroupwareError::PreconditionFailed => status(StatusCode::PRECONDITION_FAILED),
                GroupwareError::Invalid(_) if is_calendar_path => {
                    condition(StatusCode::FORBIDDEN, CalCondition::ValidCalendarObjectResource)
                }
                GroupwareError::Invalid(_) => condition(StatusCode::FORBIDDEN, CardCondition::ValidAddressData),
                GroupwareError::TooLarge { limit } if is_calendar_path => {
                    condition(StatusCode::FORBIDDEN, CalCondition::MaxResourceSize(limit as u32))
                }
                GroupwareError::TooLarge { limit } => {
                    condition(StatusCode::FORBIDDEN, CardCondition::MaxResourceSize(limit as u32))
                }
                GroupwareError::OverQuota => {
                    condition(StatusCode::INSUFFICIENT_STORAGE, BaseCondition::QuotaNotExceeded)
                }
                GroupwareError::UidConflict(_) if is_calendar_path => {
                    condition(StatusCode::FORBIDDEN, CalCondition::NoUidConflict(Href(String::new())))
                }
                GroupwareError::UidConflict(_) => {
                    condition(StatusCode::FORBIDDEN, CardCondition::NoUidConflict(Href(String::new())))
                }
                GroupwareError::IsDefault | GroupwareError::NotEmpty => status(StatusCode::FORBIDDEN),
                GroupwareError::CannotCalculateChanges => {
                    condition(StatusCode::FORBIDDEN, BaseCondition::ValidSyncToken)
                }
                other => {
                    tracing::warn!(error = %other, "dav request failed");
                    status(StatusCode::INTERNAL_SERVER_ERROR)
                }
            },
            Err(Error::Other(error)) => {
                tracing::warn!(%error, "dav request failed");
                status(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }

    async fn dispatch(&self, request: &DavRequest) -> Result<DavResponse, Error> {
        let user = self.groupware.principal(request.account).await.map_err(|_| Error::Forbidden)?;
        let target = path::parse(&request.path).ok_or(Error::NotFound)?;
        let mut headers = RequestHeaders::new(&request.path);
        for (name, value) in &request.headers {
            if let Ok(value) = value.to_str() {
                headers.parse(name.as_str(), value);
            }
        }
        let body = &request.body;
        match request.method.as_str() {
            "OPTIONS" => Ok(self.options()),
            "PROPFIND" => {
                let node = self.resolve(&user, &target).await?;
                let propfind = PropFind::parse(&mut Tokenizer::new(body))?;
                self.propfind(&user, node, headers.depth, propfind).await
            }
            "REPORT" => {
                let node = self.resolve(&user, &target).await?;
                let report = Report::parse(&mut Tokenizer::new(body))?;
                self.report(&user, node, &headers, report).await
            }
            "GET" | "HEAD" => {
                let node = self.resolve(&user, &target).await?;
                self.get(node, request.method == Method::HEAD).await
            }
            "PUT" => self.put(&user, &target, &request.headers, body).await,
            "DELETE" => {
                let node = self.resolve(&user, &target).await?;
                self.delete(node, &request.headers).await
            }
            "MKCALENDAR" | "MKCOL" => {
                let mkcol = if body.is_empty() { None } else { Some(MkCol::parse(&mut Tokenizer::new(body))?) };
                self.mkcol(&user, &target, request.method.as_str() == "MKCALENDAR", mkcol).await
            }
            "PROPPATCH" => {
                let node = self.resolve(&user, &target).await?;
                let update = PropertyUpdate::parse(&mut Tokenizer::new(body))?;
                self.proppatch(&user, node, update).await
            }
            "COPY" | "MOVE" => {
                let node = self.resolve(&user, &target).await?;
                let destination = request
                    .headers
                    .get("destination")
                    .and_then(|value| value.to_str().ok())
                    .and_then(path::destination)
                    .ok_or(Error::Status(StatusCode::BAD_REQUEST))?;
                let overwrite = request.headers.get("overwrite").is_none_or(|value| value.as_bytes() != b"F");
                self.copy_move(&user, node, destination, overwrite, request.method.as_str() == "MOVE").await
            }
            "POST" => {
                let node = self.resolve(&user, &target).await?;
                self.post(&user, node, body).await
            }
            "LOCK" | "UNLOCK" | "ACL" => Err(Error::Status(StatusCode::METHOD_NOT_ALLOWED)),
            _ => Err(Error::Status(StatusCode::NOT_IMPLEMENTED)),
        }
    }

    fn options(&self) -> DavResponse {
        let mut response = status(StatusCode::OK);
        let headers = response.headers_mut();
        headers.insert("dav", HeaderValue::from_static(COMPLIANCE));
        headers.insert(
            header::ALLOW,
            HeaderValue::from_static(
                "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, MKCALENDAR, COPY, MOVE, REPORT, POST",
            ),
        );
        response
    }

    /// The children of a node for depth 1.
    async fn children(&self, user: &PrincipalInfo, node: &Node) -> Result<Vec<Node>, Error> {
        Ok(match node {
            Node::Root => vec![Node::Principals, Node::CalendarHome, Node::AddressbookHome],
            Node::Principals => vec![Node::Principal(user.clone())],
            Node::CalendarHome => {
                self.home_collections(user.id, true).await?.into_iter().map(Node::Collection).collect()
            }
            Node::AddressbookHome => {
                self.home_collections(user.id, false).await?.into_iter().map(Node::Collection).collect()
            }
            Node::Collection(collection @ Collection::Calendar { owner, info, .. }) => self
                .groupware
                .events(*owner, info.id)
                .await?
                .into_iter()
                .map(|event| Node::Event(collection.clone(), event))
                .collect(),
            Node::Collection(collection @ Collection::Addressbook { owner, info, .. }) => self
                .groupware
                .contacts(*owner, Some(info.id))
                .await?
                .into_iter()
                .map(|contact| Node::Contact(collection.clone(), contact))
                .collect(),
            _ => Vec::new(),
        })
    }

    /// The content of objects that a set of properties needs: calendar or address data.
    async fn contents(&self, nodes: &[Node], propfind: &PropFind) -> Result<HashMap<Uuid, Content>, Error> {
        let wants_data = match propfind {
            PropFind::Prop(props) | PropFind::AllProp(props) => props.iter().any(|prop| {
                matches!(
                    prop,
                    DavProperty::CalDav(CalDavProperty::CalendarData(_))
                        | DavProperty::CardDav(crate::proto::schema::property::CardDavProperty::AddressData { .. })
                )
            }),
            PropFind::PropName => false,
        };
        let mut contents = HashMap::new();
        if !wants_data {
            return Ok(contents);
        }
        let mut events: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        let mut contacts: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for node in nodes {
            match node {
                Node::Event(collection, event) => events.entry(collection.owner()).or_default().push(event.id),
                Node::Contact(collection, contact) => contacts.entry(collection.owner()).or_default().push(contact.id),
                _ => {}
            }
        }
        for (owner, ids) in events {
            for (event, text) in self.groupware.event_data(owner, &ids).await? {
                contents.insert(event.id, Content { text: Some(text), instances: None });
            }
        }
        for (owner, ids) in contacts {
            for (contact, text) in self.groupware.contact_data(owner, &ids).await? {
                contents.insert(contact.id, Content { text: Some(text), instances: None });
            }
        }
        Ok(contents)
    }

    async fn multistatus(
        &self,
        user: &PrincipalInfo,
        nodes: Vec<Node>,
        propfind: &PropFind,
        mut contents: HashMap<Uuid, Content>,
    ) -> Result<MultiStatus, Error> {
        let mut multistatus = MultiStatus::new(Vec::with_capacity(nodes.len()));
        set_namespaces(&mut multistatus, propfind);
        let mut instances_limit = ical::MAX_INSTANCES;
        for node in &nodes {
            let id = match node {
                Node::Event(_, event) => Some(event.id),
                Node::Contact(_, contact) => Some(contact.id),
                _ => None,
            };
            let content = id.and_then(|id| contents.remove(&id)).unwrap_or_default();
            multistatus.add_response(self.response(user, node, propfind, &content, &mut instances_limit).await?);
        }
        Ok(multistatus)
    }

    async fn propfind(
        &self,
        user: &PrincipalInfo,
        node: Node,
        depth: Depth,
        propfind: PropFind,
    ) -> Result<DavResponse, Error> {
        let mut nodes = vec![node.clone()];
        if node.is_collection() && !matches!(depth, Depth::Zero) {
            nodes.extend(self.children(user, &node).await?);
        }
        let contents = self.contents(&nodes, &propfind).await?;
        let multistatus = self.multistatus(user, nodes, &propfind, contents).await?;
        Ok(xml(StatusCode::MULTI_STATUS, multistatus))
    }

    async fn get(&self, node: Node, head: bool) -> Result<DavResponse, Error> {
        let (owner, text, modseq, content_type, schedule_tag) = match &node {
            Node::Event(collection, event) => {
                let (_, text) =
                    self.groupware.event_data(collection.owner(), &[event.id]).await?.pop().ok_or(Error::NotFound)?;
                (collection.owner(), text, event.modseq, "text/calendar; charset=utf-8", Some(event.schedule_tag))
            }
            Node::Contact(collection, contact) => {
                let (_, text) = self
                    .groupware
                    .contact_data(collection.owner(), &[contact.id])
                    .await?
                    .pop()
                    .ok_or(Error::NotFound)?;
                (collection.owner(), text, contact.modseq, "text/vcard; charset=utf-8", None)
            }
            _ => return Err(Error::Status(StatusCode::METHOD_NOT_ALLOWED)),
        };
        let _ = owner;
        let length = text.len();
        let mut response = http::Response::new(if head { Vec::new() } else { text.into_bytes() });
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        headers.insert(header::ETAG, etag(modseq));
        if head {
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
        }
        if let Some(tag) = schedule_tag {
            headers.insert("schedule-tag", etag(tag));
        }
        Ok(response)
    }

    async fn put(
        &self,
        user: &PrincipalInfo,
        target: &Target,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<DavResponse, Error> {
        let text = std::str::from_utf8(body).map_err(|_| match target {
            Target::CalendarObject(..) => {
                Error::Condition(StatusCode::FORBIDDEN, CalCondition::SupportedCalendarData.into())
            }
            _ => Error::Condition(StatusCode::FORBIDDEN, CardCondition::SupportedAddressData.into()),
        })?;
        let expect = expect(headers);
        let (status_code, modseq, schedule_tag, changed) = match target {
            Target::CalendarObject(home, segment, name) => {
                if *home != user.id {
                    return Err(Error::Forbidden);
                }
                let collection = self.calendar_collection(user.id, segment).await?;
                let Collection::Calendar { owner, info, level, .. } = &collection else {
                    return Err(Error::Status(StatusCode::METHOD_NOT_ALLOWED));
                };
                if *level < Level::Write {
                    return Err(Error::Forbidden);
                }
                if let Some(wanted) = headers.get("if-schedule-tag-match").and_then(|value| value.to_str().ok()) {
                    let current = self.groupware.event_by_name(*owner, info.id, name).await?;
                    if current.is_none_or(|event| format!("\"{}\"", event.schedule_tag) != wanted.trim()) {
                        return Err(Error::Status(StatusCode::PRECONDITION_FAILED));
                    }
                }
                // Scheduling (RFC 0004, 7): invitations, updates and answers go out by mail.
                let scheduled = match self.groupware.put_event_scheduled(*owner, info.id, name, text, expect).await? {
                    Ok(scheduled) => scheduled,
                    Err(ScheduleRefusal::OrganizerChange) => {
                        return Err(Error::Condition(
                            StatusCode::FORBIDDEN,
                            CalCondition::SameOrganizerInAllComponents.into(),
                        ));
                    }
                    Err(ScheduleRefusal::AttendeeChange) => {
                        return Err(Error::Condition(
                            StatusCode::FORBIDDEN,
                            CalCondition::AllowedAttendeeObjectChange.into(),
                        ));
                    }
                };
                let written = scheduled.written;
                let code = if written.created { StatusCode::CREATED } else { StatusCode::NO_CONTENT };
                (code, written.event.modseq, Some(written.event.schedule_tag), scheduled.changed)
            }
            Target::Contact(home, segment, name) => {
                if *home != user.id {
                    return Err(Error::Forbidden);
                }
                let collection = self.addressbook_collection(user.id, segment).await?;
                let Collection::Addressbook { owner, info, level, .. } = &collection else {
                    return Err(Error::Status(StatusCode::METHOD_NOT_ALLOWED));
                };
                if *level < Level::Write {
                    return Err(Error::Forbidden);
                }
                let (contact, created) = self.groupware.put_contact(*owner, info.id, name, text, expect).await?;
                let code = if created { StatusCode::CREATED } else { StatusCode::NO_CONTENT };
                (code, contact.modseq, None, false)
            }
            _ => return Err(Error::Status(StatusCode::METHOD_NOT_ALLOWED)),
        };
        let mut response = status(status_code);
        // Stored as sent, the ETag is that of what the client has; changed by scheduling, there is none, so that the
        // client fetches it again (RFC 4791, 5.3.4).
        if !changed {
            response.headers_mut().insert(header::ETAG, etag(modseq));
        }
        if let Some(tag) = schedule_tag {
            response.headers_mut().insert("schedule-tag", etag(tag));
        }
        Ok(response)
    }

    async fn delete(&self, node: Node, headers: &HeaderMap) -> Result<DavResponse, Error> {
        let expect = match expect(headers) {
            Expect::New => return Err(Error::Status(StatusCode::PRECONDITION_FAILED)),
            other => other,
        };
        match node {
            Node::Event(collection, event) => {
                if collection.level() < Level::Write {
                    return Err(Error::Forbidden);
                }
                // `Schedule-Reply: F` keeps an attendee's removal quiet (RFC 6638, 8.1).
                if headers.get("schedule-reply").is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"F")) {
                    self.groupware.destroy_event(collection.owner(), event.id, expect).await?;
                } else {
                    self.groupware.destroy_event_scheduled(collection.owner(), event.id, expect).await?;
                }
            }
            Node::Contact(collection, contact) => {
                if collection.level() < Level::Write {
                    return Err(Error::Forbidden);
                }
                self.groupware.destroy_contact(collection.owner(), contact.id, expect).await?;
            }
            Node::Collection(Collection::Calendar { owner, info, level, .. }) => {
                // Removing a collection someone shared would remove it for its owner (OPEN: leaving a share).
                if level < Level::Admin || owner != info.account {
                    return Err(Error::Forbidden);
                }
                self.groupware.destroy_calendar(owner, info.id, true).await?;
            }
            Node::Collection(Collection::Addressbook { owner, info, level, .. }) => {
                if level < Level::Admin || owner != info.account {
                    return Err(Error::Forbidden);
                }
                self.groupware.destroy_addressbook(owner, info.id, true).await?;
            }
            _ => return Err(Error::Forbidden),
        }
        Ok(status(StatusCode::NO_CONTENT))
    }

    async fn mkcol(
        &self,
        user: &PrincipalInfo,
        target: &Target,
        is_mkcalendar: bool,
        mkcol: Option<MkCol>,
    ) -> Result<DavResponse, Error> {
        let props = mkcol.as_ref().map(|mkcol| mkcol.props.clone()).unwrap_or_default();
        let wants_calendar = is_mkcalendar
            || props.iter().any(|prop| {
                matches!(&prop.property, DavProperty::WebDav(WebDavProperty::ResourceType))
                    && matches!(&prop.value, DavValue::ResourceTypes(types) if types.0.contains(&crate::proto::schema::property::ResourceType::Calendar))
            });
        match target {
            Target::Calendar(home, segment) if *home == user.id => {
                if !wants_calendar {
                    return Err(Error::Condition(StatusCode::FORBIDDEN, BaseCondition::ValidResourceType.into()));
                }
                if self.groupware.calendar_by_name(user.id, segment).await?.is_some() {
                    return Err(Error::Status(StatusCode::METHOD_NOT_ALLOWED));
                }
                let mut new =
                    NewCalendar { resource_name: Some(segment.clone()), name: segment.clone(), ..Default::default() };
                let mut dead = DeadProperty::default();
                for prop in &props {
                    apply_calendar_prop(prop, &mut new, &mut dead);
                }
                let id = self.groupware.create_calendar(user.id, new).await?;
                if !dead.0.is_empty() {
                    let value = serde_json::to_value(&dead).map_err(Error::other)?;
                    self.groupware.set_calendar_dead_properties(user.id, id, value).await?;
                }
            }
            Target::Addressbook(home, segment) if *home == user.id => {
                let wants_addressbook = props.iter().any(|prop| {
                    matches!(&prop.value, DavValue::ResourceTypes(types) if types.0.contains(&crate::proto::schema::property::ResourceType::AddressBook))
                });
                if is_mkcalendar || !wants_addressbook {
                    return Err(Error::Condition(StatusCode::FORBIDDEN, BaseCondition::ValidResourceType.into()));
                }
                if self.groupware.addressbook_by_name(user.id, segment).await?.is_some() {
                    return Err(Error::Status(StatusCode::METHOD_NOT_ALLOWED));
                }
                let mut new = NewAddressBook {
                    resource_name: Some(segment.clone()),
                    name: segment.clone(),
                    ..Default::default()
                };
                for prop in &props {
                    match (&prop.property, &prop.value) {
                        (DavProperty::WebDav(WebDavProperty::DisplayName), DavValue::String(name)) => {
                            new.name = name.clone();
                        }
                        (
                            DavProperty::CardDav(
                                crate::proto::schema::property::CardDavProperty::AddressbookDescription,
                            ),
                            DavValue::String(description),
                        ) => new.description = Some(description.clone()),
                        _ => {}
                    }
                }
                self.groupware.create_addressbook(user.id, new).await?;
            }
            Target::Calendar(..) | Target::Addressbook(..) => return Err(Error::Forbidden),
            _ => return Err(Error::Status(StatusCode::METHOD_NOT_ALLOWED)),
        }
        if is_mkcalendar || mkcol.is_none() {
            return Ok(status(StatusCode::CREATED));
        }
        let accepted: Vec<DavPropertyValue> =
            props.into_iter().map(|prop| DavPropertyValue::empty(prop.property)).collect();
        Ok(xml(StatusCode::CREATED, MkColResponse::new(vec![PropStat::new_list(accepted)])))
    }

    async fn proppatch(&self, user: &PrincipalInfo, node: Node, update: PropertyUpdate) -> Result<DavResponse, Error> {
        let href = node.href(user.id);
        let changed: Vec<DavPropertyValue> = update
            .set
            .iter()
            .map(|prop| DavPropertyValue::empty(prop.property.clone()))
            .chain(update.remove.iter().cloned().map(DavPropertyValue::empty))
            .collect();
        match node {
            Node::Collection(Collection::Calendar { owner, info, level, .. }) => {
                if level < Level::Admin {
                    return Err(Error::Forbidden);
                }
                let mut new = NewCalendar {
                    name: info.name.clone(),
                    description: info.description.clone(),
                    color: info.color.clone(),
                    sort_order: info.sort_order,
                    timezone: info.timezone.clone(),
                    ..Default::default()
                };
                let mut dead: DeadProperty = serde_json::from_value(info.dead_properties.clone()).unwrap_or_default();
                for prop in &update.set {
                    apply_calendar_prop(prop, &mut new, &mut dead);
                }
                for prop in &update.remove {
                    match prop {
                        DavProperty::CalDav(CalDavProperty::CalendarDescription) => new.description = None,
                        DavProperty::DeadProperty(tag) => {
                            dead.remove_element(tag);
                            if tag.name == "calendar-color" {
                                new.color = None;
                            }
                        }
                        _ => {}
                    }
                }
                let update = CalendarUpdate {
                    name: Some(new.name),
                    description: Some(new.description),
                    color: Some(new.color),
                    sort_order: Some(new.sort_order),
                    timezone: Some(new.timezone),
                    ..Default::default()
                };
                self.groupware.update_calendar(owner, info.id, update).await?;
                let value = serde_json::to_value(&dead).map_err(Error::other)?;
                self.groupware.set_calendar_dead_properties(owner, info.id, value).await?;
            }
            Node::Collection(Collection::Addressbook { owner, info, level, .. }) => {
                if level < Level::Admin {
                    return Err(Error::Forbidden);
                }
                let mut update_ = AddressBookUpdate::default();
                let mut dead: DeadProperty = serde_json::from_value(info.dead_properties.clone()).unwrap_or_default();
                for prop in &update.set {
                    match (&prop.property, &prop.value) {
                        (DavProperty::WebDav(WebDavProperty::DisplayName), DavValue::String(name)) => {
                            update_.name = Some(name.clone());
                        }
                        (
                            DavProperty::CardDav(
                                crate::proto::schema::property::CardDavProperty::AddressbookDescription,
                            ),
                            DavValue::String(description),
                        ) => update_.description = Some(Some(description.clone())),
                        (DavProperty::DeadProperty(tag), DavValue::DeadProperty(value)) => {
                            dead.remove_element(tag);
                            dead.add_element(tag.clone(), value.0.clone());
                        }
                        _ => {}
                    }
                }
                for prop in &update.remove {
                    match prop {
                        DavProperty::CardDav(
                            crate::proto::schema::property::CardDavProperty::AddressbookDescription,
                        ) => {
                            update_.description = Some(None);
                        }
                        DavProperty::DeadProperty(tag) => dead.remove_element(tag),
                        _ => {}
                    }
                }
                self.groupware.update_addressbook(owner, info.id, update_).await?;
                let value = serde_json::to_value(&dead).map_err(Error::other)?;
                self.groupware.set_addressbook_dead_properties(owner, info.id, value).await?;
            }
            _ => {
                let response =
                    Response::new_propstat(href, vec![PropStat::new_list(changed).with_status(StatusCode::FORBIDDEN)]);
                return Ok(xml(StatusCode::MULTI_STATUS, MultiStatus::new(vec![response])));
            }
        }
        let response = Response::new_propstat(href, vec![PropStat::new_list(changed)]);
        Ok(xml(StatusCode::MULTI_STATUS, MultiStatus::new(vec![response])))
    }

    async fn copy_move(
        &self,
        user: &PrincipalInfo,
        node: Node,
        destination: Target,
        overwrite: bool,
        is_move: bool,
    ) -> Result<DavResponse, Error> {
        let (from, to_segment, to_name, is_event) = match (&node, &destination) {
            (Node::Event(collection, _), Target::CalendarObject(home, segment, name)) if *home == user.id => {
                (collection, segment, name, true)
            }
            (Node::Contact(collection, _), Target::Contact(home, segment, name)) if *home == user.id => {
                (collection, segment, name, false)
            }
            _ => return Err(Error::Status(StatusCode::FORBIDDEN)),
        };
        let to = if is_event {
            self.calendar_collection(user.id, to_segment).await?
        } else {
            self.addressbook_collection(user.id, to_segment).await?
        };
        if to.level() < Level::Write || from.level() < if is_move { Level::Write } else { Level::Read } {
            return Err(Error::Forbidden);
        }
        let (to_owner, to_id) = (to.owner(), to.id().ok_or(Error::Forbidden)?);
        // Whether something is there already, and replacing it is allowed.
        let existing = if is_event {
            self.groupware.event_by_name(to_owner, to_id, to_name).await?.map(|event| event.id)
        } else {
            self.groupware.contact_by_name(to_owner, to_id, to_name).await?.map(|contact| contact.id)
        };
        if existing.is_some() && !overwrite {
            return Err(Error::Status(StatusCode::PRECONDITION_FAILED));
        }
        let same_store = from.owner() == to_owner;
        match &node {
            Node::Event(_, event) if is_move && same_store => {
                if let Some(existing) = existing.filter(|id| *id != event.id) {
                    self.groupware.destroy_event(to_owner, existing, Expect::Any).await?;
                }
                self.groupware.move_event(to_owner, event.id, to_id, Some(to_name)).await?;
            }
            Node::Contact(_, contact) if is_move && same_store => {
                if let Some(existing) = existing.filter(|id| *id != contact.id) {
                    self.groupware.destroy_contact(to_owner, existing, Expect::Any).await?;
                }
                self.groupware.move_contact(to_owner, contact.id, to_id, Some(to_name)).await?;
            }
            Node::Event(_, event) => {
                let (_, text) =
                    self.groupware.event_data(from.owner(), &[event.id]).await?.pop().ok_or(Error::NotFound)?;
                self.groupware.put_event(to_owner, to_id, to_name, &text, Expect::Any).await?;
                if is_move {
                    self.groupware.destroy_event(from.owner(), event.id, Expect::Any).await?;
                }
            }
            Node::Contact(_, contact) => {
                let (_, text) =
                    self.groupware.contact_data(from.owner(), &[contact.id]).await?.pop().ok_or(Error::NotFound)?;
                self.groupware.put_contact(to_owner, to_id, to_name, &text, Expect::Any).await?;
                if is_move {
                    self.groupware.destroy_contact(from.owner(), contact.id, Expect::Any).await?;
                }
            }
            _ => return Err(Error::Forbidden),
        }
        Ok(status(if existing.is_some() { StatusCode::NO_CONTENT } else { StatusCode::CREATED }))
    }

    async fn report(
        &self,
        user: &PrincipalInfo,
        node: Node,
        headers: &RequestHeaders<'_>,
        report: Report,
    ) -> Result<DavResponse, Error> {
        match report {
            Report::CalendarQuery(query) => {
                let Node::Collection(collection @ Collection::Calendar { owner, info, .. }) = &node else {
                    return Err(Error::Status(StatusCode::FORBIDDEN));
                };
                let default_tz =
                    query::parse_tz(&query.timezone).unwrap_or_else(|| ical::time_zone(info.timezone.as_deref()));
                let filter_range = query::filter_range(&query);
                let data_range = query::data_range(&query.properties, filter_range);
                let candidates = match filter_range {
                    Some(range) => {
                        self.groupware
                            .events_between(*owner, Some(info.id), timestamp(range.start), timestamp(range.end))
                            .await?
                    }
                    None => self.groupware.events(*owner, info.id).await?,
                };
                let ids: Vec<Uuid> = candidates.iter().map(|event| event.id).collect();
                let data: HashMap<Uuid, String> = self
                    .groupware
                    .event_data(*owner, &ids)
                    .await?
                    .into_iter()
                    .map(|(event, text)| (event.id, text))
                    .collect();
                let mut nodes = Vec::new();
                let mut contents = HashMap::new();
                for event in candidates {
                    let Some(text) = data.get(&event.id) else { continue };
                    let calcard::Entry::ICalendar(parsed) = calcard::Parser::new(text).entry() else { continue };
                    let instances = query::instances(&parsed, default_tz, data_range);
                    if !query::calendar_matches(&parsed, &query.filters, &instances, default_tz) {
                        continue;
                    }
                    contents.insert(event.id, Content { text: Some(text.clone()), instances: Some(instances) });
                    nodes.push(Node::Event(collection.clone(), event));
                }
                let multistatus = self.multistatus(user, nodes, &query.properties, contents).await?;
                Ok(xml(StatusCode::MULTI_STATUS, multistatus))
            }
            Report::AddressbookQuery(query) => {
                let Node::Collection(collection @ Collection::Addressbook { owner, info, .. }) = &node else {
                    return Err(Error::Status(StatusCode::FORBIDDEN));
                };
                let contacts = self.groupware.contacts(*owner, Some(info.id)).await?;
                let ids: Vec<Uuid> = contacts.iter().map(|contact| contact.id).collect();
                let data: HashMap<Uuid, String> = self
                    .groupware
                    .contact_data(*owner, &ids)
                    .await?
                    .into_iter()
                    .map(|(contact, text)| (contact.id, text))
                    .collect();
                let mut nodes = Vec::new();
                let mut contents = HashMap::new();
                let limit = query.limit.map_or(usize::MAX, |limit| limit as usize);
                for contact in contacts {
                    if nodes.len() >= limit {
                        break;
                    }
                    let Some(text) = data.get(&contact.id) else { continue };
                    let calcard::Entry::VCard(card) = calcard::Parser::new(text).entry() else { continue };
                    if !query::vcard_matches(&card, &query.filters) {
                        continue;
                    }
                    contents.insert(contact.id, Content { text: Some(text.clone()), instances: None });
                    nodes.push(Node::Contact(collection.clone(), contact));
                }
                let multistatus = self.multistatus(user, nodes, &query.properties, contents).await?;
                Ok(xml(StatusCode::MULTI_STATUS, multistatus))
            }
            Report::CalendarMultiGet(multiget) | Report::AddressbookMultiGet(multiget) => {
                self.multiget(user, multiget).await
            }
            Report::SyncCollection(sync) => {
                let Node::Collection(collection) = &node else { return Err(Error::Status(StatusCode::FORBIDDEN)) };
                let Some(id) = collection.id() else { return Err(Error::Status(StatusCode::FORBIDDEN)) };
                let since = match sync.sync_token.as_deref().filter(|token| !token.is_empty()) {
                    Some(token) => parse_sync_token(token)
                        .ok_or(Error::Condition(StatusCode::FORBIDDEN, BaseCondition::ValidSyncToken.into()))?,
                    None => 0,
                };
                let changes = self.groupware.sync(collection.owner(), id, since).await?;
                let mut nodes = Vec::new();
                let mut removed = Vec::new();
                for name in &changes.changed {
                    let found = match collection {
                        Collection::Calendar { owner, info, .. } => self
                            .groupware
                            .event_by_name(*owner, info.id, name)
                            .await?
                            .map(|event| Node::Event(collection.clone(), event)),
                        Collection::Addressbook { owner, info, .. } => self
                            .groupware
                            .contact_by_name(*owner, info.id, name)
                            .await?
                            .map(|contact| Node::Contact(collection.clone(), contact)),
                        _ => None,
                    };
                    match found {
                        Some(node) => nodes.push(node),
                        None => removed.push(name.clone()),
                    }
                }
                removed.extend(changes.removed);
                let contents = self.contents(&nodes, &sync.properties).await?;
                let mut multistatus = self.multistatus(user, nodes, &sync.properties, contents).await?;
                for name in removed {
                    multistatus.add_response(Response::new_status(
                        [format!("{}{}", collection.href(user.id), path::encode(&name))],
                        StatusCode::NOT_FOUND,
                    ));
                }
                multistatus.set_sync_token(sync_token(changes.token));
                Ok(xml(StatusCode::MULTI_STATUS, multistatus))
            }
            Report::FreeBusyQuery(freebusy) => {
                let Node::Collection(Collection::Calendar { owner, info, level, .. }) = &node else {
                    return Err(Error::Status(StatusCode::FORBIDDEN));
                };
                if *level < Level::Freebusy {
                    return Err(Error::Forbidden);
                }
                let range = freebusy.range.ok_or(Error::Status(StatusCode::BAD_REQUEST))?;
                let object = self.freebusy(*owner, Some(vec![info.id]), range, Vec::new()).await?;
                let mut response = http::Response::new(object.to_string().into_bytes());
                response
                    .headers_mut()
                    .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/calendar; charset=utf-8"));
                Ok(response)
            }
            Report::ExpandProperty(expand) => {
                // The properties asked for on the node itself; hrefs are not expanded further (OPEN).
                let props: Vec<DavProperty> = expand.properties.into_iter().map(|item| item.property).collect();
                let propfind = PropFind::Prop(props);
                let response = self.response(user, &node, &propfind, &Content::default(), &mut 0).await?;
                Ok(xml(StatusCode::MULTI_STATUS, MultiStatus::new(vec![response])))
            }
            Report::PrincipalPropertySearch(search) => {
                let text = search
                    .property_search
                    .iter()
                    .map(|search| search.match_.trim())
                    .find(|text| !text.is_empty())
                    .unwrap_or("");
                let principals = self.groupware.search_principals(user.tenant, text, 50).await?;
                let propfind = PropFind::Prop(search.properties);
                let nodes = principals.into_iter().map(Node::Principal).collect();
                let multistatus = self.multistatus(user, nodes, &propfind, HashMap::new()).await?;
                Ok(xml(StatusCode::MULTI_STATUS, multistatus))
            }
            Report::PrincipalMatch(principal_match) => {
                let propfind = PropFind::Prop(principal_match.properties);
                let multistatus =
                    self.multistatus(user, vec![Node::Principal(user.clone())], &propfind, HashMap::new()).await?;
                Ok(xml(StatusCode::MULTI_STATUS, multistatus))
            }
            Report::AclPrincipalPropSet(_) => Ok(xml(StatusCode::MULTI_STATUS, MultiStatus::new(Vec::new()))),
            Report::PrincipalSearchPropertySet => {
                use crate::proto::schema::{
                    property::PrincipalProperty,
                    response::{PrincipalSearchProperty, PrincipalSearchPropertySet},
                };
                let set = PrincipalSearchPropertySet::new(vec![
                    PrincipalSearchProperty::new(DavProperty::WebDav(WebDavProperty::DisplayName), "Name"),
                    PrincipalSearchProperty::new(
                        DavProperty::Principal(PrincipalProperty::CalendarUserAddressSet),
                        "Address",
                    ),
                ])
                .with_namespace(Namespace::CalDav);
                let _ = headers;
                Ok(xml(StatusCode::OK, set))
            }
        }
    }

    async fn multiget(&self, user: &PrincipalInfo, multiget: MultiGet) -> Result<DavResponse, Error> {
        let mut nodes = Vec::new();
        let mut missing = Vec::new();
        for href in &multiget.hrefs {
            let path = match href.find("://") {
                Some(_) => path::destination(href),
                None => path::parse(href),
            };
            let node = match path {
                Some(target @ (Target::CalendarObject(..) | Target::Contact(..))) => {
                    self.resolve(user, &target).await.ok()
                }
                _ => None,
            };
            match node {
                Some(node) => nodes.push(node),
                None => missing.push(href.clone()),
            }
        }
        let contents = self.contents(&nodes, &multiget.properties).await?;
        let mut multistatus = self.multistatus(user, nodes, &multiget.properties, contents).await?;
        for href in missing {
            multistatus.add_response(Response::new_status([href], StatusCode::NOT_FOUND));
        }
        Ok(xml(StatusCode::MULTI_STATUS, multistatus))
    }

    /// Free/busy of an account's calendars – `calendars`, or all – over `range` (RFC 4791, 7.10).
    pub(crate) async fn freebusy(
        &self,
        owner: Uuid,
        calendars: Option<Vec<Uuid>>,
        range: crate::proto::types::TimeRange,
        extra: Vec<calcard::icalendar::ICalendarEntry>,
    ) -> Result<calcard::icalendar::ICalendar, Error> {
        let zones: HashMap<Uuid, Option<String>> =
            self.groupware.calendars(owner).await?.into_iter().map(|info| (info.id, info.timezone)).collect();
        let calendars = calendars.unwrap_or_else(|| zones.keys().copied().collect());
        let mut busy = HashMap::new();
        for calendar in calendars {
            let candidates = self
                .groupware
                .events_between(owner, Some(calendar), timestamp(range.start), timestamp(range.end))
                .await?;
            let ids: Vec<Uuid> = candidates.iter().map(|event| event.id).collect();
            let tz = ical::time_zone(zones.get(&calendar).cloned().flatten().as_deref());
            for (_, text) in self.groupware.event_data(owner, &ids).await? {
                let calcard::Entry::ICalendar(parsed) = calcard::Parser::new(&text).entry() else { continue };
                let instances = query::instances(&parsed, tz, Some(range));
                query::busy_times(&parsed, &instances, &range, &mut busy);
            }
        }
        Ok(query::freebusy_object(&range, busy, extra))
    }

    async fn post(&self, user: &PrincipalInfo, node: Node, body: &[u8]) -> Result<DavResponse, Error> {
        match node {
            Node::Collection(Collection::Outbox { owner }) if owner == user.id => {
                crate::schedule::outbox_post(self, user, body).await
            }
            _ => Err(Error::Status(StatusCode::METHOD_NOT_ALLOWED)),
        }
    }
}

/// A Unix time as a date, for the store's time ranges; the open ends of a range stay open.
fn timestamp(value: i64) -> Option<chrono::DateTime<chrono::Utc>> {
    if value == i64::MIN || value == i64::MAX { None } else { chrono::DateTime::from_timestamp(value, 0) }
}

fn set_namespaces(multistatus: &mut MultiStatus, propfind: &PropFind) {
    if let PropFind::Prop(props) | PropFind::AllProp(props) = propfind {
        for prop in props {
            multistatus.set_namespace(prop.namespace());
        }
    }
    multistatus.set_namespace(Namespace::CalDav);
    multistatus.set_namespace(Namespace::CardDav);
    multistatus.set_namespace(Namespace::CalendarServer);
}

/// A property of `MKCALENDAR` or `PROPPATCH` on a calendar: the known ones change the calendar, the rest are kept
/// as dead properties. Apple's colour and order also set the calendar's own.
fn apply_calendar_prop(prop: &DavPropertyValue, new: &mut NewCalendar, dead: &mut DeadProperty) {
    match (&prop.property, &prop.value) {
        (DavProperty::WebDav(WebDavProperty::DisplayName), DavValue::String(name)) => new.name = name.clone(),
        (DavProperty::CalDav(CalDavProperty::CalendarDescription), DavValue::String(description)) => {
            new.description = Some(description.clone());
        }
        (DavProperty::CalDav(CalDavProperty::TimezoneId), DavValue::String(tz)) => new.timezone = Some(tz.clone()),
        (DavProperty::CalDav(CalDavProperty::CalendarTimezone), DavValue::ICalendar(ical)) => {
            if let Some(tz) = ical
                .components
                .iter()
                .find(|comp| comp.component_type == calcard::icalendar::ICalendarComponentType::VTimezone)
                .and_then(|comp| comp.property(&calcard::icalendar::ICalendarProperty::Tzid))
                .and_then(|entry| entry.values.first())
                .and_then(|value| value.as_text())
                .filter(|name| name.parse::<chrono_tz::Tz>().is_ok())
            {
                new.timezone = Some(tz.to_owned());
            }
        }
        (DavProperty::CalDav(CalDavProperty::SupportedCalendarComponentSet), DavValue::Components(components)) => {
            new.components = components.0.iter().map(|comp| comp.0.as_str().to_owned()).collect();
        }
        (DavProperty::DeadProperty(tag), DavValue::DeadProperty(value)) => {
            let text = value.0.iter().find_map(|item| match item {
                DeadPropertyTag::Text(text) => Some(text.trim().to_owned()),
                _ => None,
            });
            match (tag.name.as_str(), text) {
                ("calendar-color", Some(color)) => new.color = Some(color),
                ("calendar-order", Some(order)) => new.sort_order = order.parse().unwrap_or(new.sort_order),
                _ => {}
            }
            dead.remove_element(tag);
            dead.add_element(tag.clone(), value.0.clone());
        }
        _ => {}
    }
}
