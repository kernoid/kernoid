// SPDX-License-Identifier: AGPL-3.0-or-later
//! Properties of principals, homes, collections and objects for `PROPFIND` and reports (RFC 4918, 4791, 6352, 6638,
//! 3744, 5397, 6578), read-only ACLs included, with the values the clients of RFC 0004, 8.1 (Apple's Calendar and
//! Contacts, Thunderbird, DAVx⁵) read.

use calcard::{
    Entry, Parser,
    icalendar::{ICalendar, ICalendarComponentType},
    vcard::VCardVersion,
};
use http::StatusCode;
use kernoid_groupware::{Level, PrincipalInfo, ical};

use crate::{
    Dav, Error,
    node::{Collection, Node},
    path,
    proto::{
        schema::{
            Collation,
            property::{
                Ace, CalDavName, CalDavProperty, CalendarData, CardDavName, CardDavProperty, DavProperty,
                DavPropertyValue, DavValue, Privilege, PropertyName, ReportName, ResourceType, SupportedPrivilege,
                WebDavProperty,
            },
            request::PropFind,
            response::{Condition, PropStat, Response},
        },
        types::DeadProperties,
    },
    query::{self, Instance},
};

/// The content of an object, when a report or `PROPFIND` needs it: its text and, for calendar data with a time
/// range, its instances there.
#[derive(Debug, Default)]
pub(crate) struct Content {
    pub text: Option<String>,
    pub instances: Option<Vec<Instance>>,
}

/// The properties `allprop` lists besides the dead ones (RFC 4918, 9.1).
fn all_props(node: &Node) -> Vec<DavProperty> {
    let mut props = vec![
        DavProperty::WebDav(WebDavProperty::DisplayName),
        DavProperty::WebDav(WebDavProperty::ResourceType),
        DavProperty::WebDav(WebDavProperty::GetETag),
    ];
    if !node.is_collection() {
        props.push(DavProperty::WebDav(WebDavProperty::GetContentType));
        props.push(DavProperty::WebDav(WebDavProperty::GetContentLength));
    }
    props
}

/// What `propname` lists (RFC 4918, 9.1): the names of the properties a node has.
fn prop_names(node: &Node) -> Vec<DavProperty> {
    let mut props = all_props(node);
    props.extend([
        DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
        DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet),
        DavProperty::WebDav(WebDavProperty::SupportedReportSet),
        DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet),
        DavProperty::WebDav(WebDavProperty::Owner),
    ]);
    match node {
        Node::Principal(_) => props.extend([
            WebDavProperty::PrincipalUrl.into(),
            CalDavName::CalendarHomeSet.into(),
            CardDavName::AddressbookHomeSet.into(),
            CalDavName::CalendarUserAddressSet.into(),
            CalDavName::ScheduleInboxUrl.into(),
            CalDavName::ScheduleOutboxUrl.into(),
        ]),
        Node::Collection(Collection::Calendar { .. }) => props.extend([
            WebDavProperty::SyncToken.into(),
            DavProperty::GetCTag,
            CalDavName::CalendarDescription.into(),
            CalDavName::SupportedCalendarComponentSet.into(),
            CalDavName::SupportedCalendarData.into(),
            CalDavName::MaxResourceSize.into(),
        ]),
        Node::Collection(Collection::Addressbook { .. }) => props.extend([
            WebDavProperty::SyncToken.into(),
            DavProperty::GetCTag,
            CardDavName::AddressbookDescription.into(),
            CardDavName::SupportedAddressData.into(),
            CardDavName::MaxResourceSize.into(),
        ]),
        Node::Event(..) => props.push(CalDavName::ScheduleTag.into()),
        _ => {}
    }
    props
}

/// What the user may do on a node, as WebDAV privileges (RFC 3744, 5.4).
fn privileges(node: &Node) -> Vec<Privilege> {
    let collection = match node {
        Node::Collection(collection) | Node::Event(collection, _) | Node::Contact(collection, _) => collection,
        Node::CalendarHome | Node::AddressbookHome => {
            return vec![Privilege::Read, Privilege::ReadCurrentUserPrivilegeSet, Privilege::Bind, Privilege::Unbind];
        }
        _ => return vec![Privilege::Read, Privilege::ReadCurrentUserPrivilegeSet],
    };
    match collection {
        Collection::Inbox { .. } => scheduling_privileges(true),
        Collection::Outbox { .. } => scheduling_privileges(false),
        _ => {
            let is_calendar = collection.is_calendar();
            match collection.level() {
                Level::Admin => all_privileges(is_calendar),
                Level::Write => {
                    let mut privileges = vec![
                        Privilege::Read,
                        Privilege::ReadCurrentUserPrivilegeSet,
                        Privilege::Write,
                        Privilege::WriteContent,
                        Privilege::Bind,
                        Privilege::Unbind,
                    ];
                    if is_calendar {
                        privileges.push(Privilege::ReadFreeBusy);
                    }
                    privileges
                }
                Level::Read | Level::Rsvp => {
                    let mut privileges = vec![Privilege::Read, Privilege::ReadCurrentUserPrivilegeSet];
                    if is_calendar {
                        privileges.push(Privilege::ReadFreeBusy);
                    }
                    privileges
                }
                Level::Freebusy => vec![Privilege::ReadFreeBusy],
            }
        }
    }
}

/// What the owner of a collection may do: everything but changing the ACL, which is read-only (RFC 0004, 8.1).
fn all_privileges(is_calendar: bool) -> Vec<Privilege> {
    let mut privileges = vec![
        Privilege::Read,
        Privilege::ReadAcl,
        Privilege::ReadCurrentUserPrivilegeSet,
        Privilege::Write,
        Privilege::WriteProperties,
        Privilege::WriteContent,
        Privilege::Bind,
        Privilege::Unbind,
    ];
    if is_calendar {
        privileges.push(Privilege::ReadFreeBusy);
    }
    privileges
}

/// What the owner may do in their scheduling inbox or outbox (RFC 6638, 6.1).
fn scheduling_privileges(inbox: bool) -> Vec<Privilege> {
    let mut privileges = vec![Privilege::Read, Privilege::ReadCurrentUserPrivilegeSet];
    privileges.extend(match inbox {
        true => [
            Privilege::ScheduleDeliver,
            Privilege::ScheduleDeliverInvite,
            Privilege::ScheduleDeliverReply,
            Privilege::ScheduleQueryFreebusy,
        ],
        false => [
            Privilege::ScheduleSend,
            Privilege::ScheduleSendInvite,
            Privilege::ScheduleSendReply,
            Privilege::ScheduleSendFreebusy,
        ],
    });
    if inbox {
        privileges.push(Privilege::Unbind);
    }
    privileges
}

/// The privileges a collection supports, as their tree (RFC 3744, 5.3; RFC 4791, 6.1.1; RFC 6638, 6.1).
fn supported_privileges(collection: Option<&Collection>) -> SupportedPrivilege {
    let read = |is_calendar: bool| {
        let mut read = SupportedPrivilege::new(Privilege::Read, "Read").with([
            SupportedPrivilege::new(Privilege::ReadAcl, "Read the access control list"),
            SupportedPrivilege::new(Privilege::ReadCurrentUserPrivilegeSet, "Read one's own privileges"),
        ]);
        if is_calendar {
            read = read.with([SupportedPrivilege::new(Privilege::ReadFreeBusy, "Read free/busy")]);
        }
        read
    };
    let all = SupportedPrivilege { is_abstract: true, ..SupportedPrivilege::new(Privilege::All, "Everything") };
    match collection {
        Some(Collection::Inbox { .. }) => all.with([
            read(false),
            SupportedPrivilege::new(Privilege::ScheduleDeliver, "Deliver scheduling messages").with([
                SupportedPrivilege::new(Privilege::ScheduleDeliverInvite, "Deliver invitations"),
                SupportedPrivilege::new(Privilege::ScheduleDeliverReply, "Deliver replies"),
                SupportedPrivilege::new(Privilege::ScheduleQueryFreebusy, "Query free/busy"),
            ]),
            SupportedPrivilege::new(Privilege::Unbind, "Remove"),
        ]),
        Some(Collection::Outbox { .. }) => all.with([
            read(false),
            SupportedPrivilege::new(Privilege::ScheduleSend, "Send scheduling messages").with([
                SupportedPrivilege::new(Privilege::ScheduleSendInvite, "Send invitations"),
                SupportedPrivilege::new(Privilege::ScheduleSendReply, "Send replies"),
                SupportedPrivilege::new(Privilege::ScheduleSendFreebusy, "Ask for free/busy"),
            ]),
        ]),
        collection => all.with([
            read(collection.is_none_or(Collection::is_calendar)),
            SupportedPrivilege::new(Privilege::Write, "Write").with([
                SupportedPrivilege::new(Privilege::WriteProperties, "Write properties"),
                SupportedPrivilege::new(Privilege::WriteContent, "Write content"),
                SupportedPrivilege::new(Privilege::Bind, "Add"),
                SupportedPrivilege::new(Privilege::Unbind, "Remove"),
            ]),
            SupportedPrivilege::new(Privilege::WriteAcl, "Write the access control list"),
        ]),
    }
}

/// The reports of a principal, an address book or a calendar (`supported-report-set`).
fn reports(node: &Node) -> Vec<ReportName> {
    let mut reports = vec![
        ReportName::ExpandProperty,
        ReportName::PrincipalMatch,
        ReportName::PrincipalPropertySearch,
        ReportName::PrincipalSearchPropertySet,
        ReportName::AclPrincipalPropSet,
    ];
    match node {
        Node::Principal(_) | Node::Principals | Node::Root => {}
        Node::Collection(Collection::Addressbook { .. }) | Node::Contact(..) | Node::AddressbookHome => {
            reports.extend([ReportName::SyncCollection, ReportName::AddressbookQuery, ReportName::AddressbookMultiget]);
        }
        _ => reports.extend([
            ReportName::SyncCollection,
            ReportName::CalendarQuery,
            ReportName::CalendarMultiget,
            ReportName::FreeBusyQuery,
        ]),
    }
    reports
}

fn dead_properties(node: &Node) -> Option<DeadProperties> {
    let value = match node {
        Node::Collection(Collection::Calendar { info, .. }) => &info.dead_properties,
        Node::Collection(Collection::Addressbook { info, .. }) => &info.dead_properties,
        _ => return None,
    };
    Some(DeadProperties::from_stored(value))
}

/// The calendar data of an event as asked for, or `None` for too many instances.
fn calendar_data(text: &str, data: &CalendarData, content: &Content, instances_limit: &mut usize) -> Option<String> {
    if data.properties.is_empty() && data.expand.is_none() && data.limit_recurrence.is_none() {
        return Some(text.to_owned());
    }
    let Entry::ICalendar(ical) = Parser::new(text).entry() else { return Some(text.to_owned()) };
    let mut instances = match (&content.instances, data.expand.or(data.limit_recurrence)) {
        (Some(instances), _) => instances.clone(),
        (None, Some(range)) => query::instances(&ical, calcard::common::timezone::Tz::UTC, Some(range)),
        (None, None) => Vec::new(),
    };
    query::serialize_ical(&ical, data, &mut instances, instances_limit)
}

impl Dav {
    /// The response for one node: the properties found, and those not found with 404.
    pub(crate) async fn response(
        &self,
        user: &PrincipalInfo,
        node: &Node,
        propfind: &PropFind,
        content: &Content,
        instances_limit: &mut usize,
    ) -> Result<Response, Error> {
        let (props, names_only) = match propfind {
            PropFind::PropName => (prop_names(node), true),
            PropFind::AllProp(include) => {
                let mut props = all_props(node);
                props.extend(include.iter().cloned());
                if let Some(dead) = dead_properties(node) {
                    props.extend(
                        dead.0
                            .into_iter()
                            .map(|property| DavProperty::Dead(PropertyName { ns: property.ns, name: property.name })),
                    );
                }
                (props, false)
            }
            PropFind::Prop(props) => (props.clone(), false),
        };
        let mut found = Vec::with_capacity(props.len());
        let mut missing = Vec::new();
        for prop in props {
            if names_only {
                found.push(DavPropertyValue::empty(prop));
                continue;
            }
            match self.value(user, node, &prop, content, instances_limit).await? {
                Some(value) => found.push(DavPropertyValue::new(prop, value)),
                None => missing.push(DavPropertyValue::empty(prop)),
            }
        }
        let mut propstat = Vec::with_capacity(2);
        if !found.is_empty() {
            propstat.push(PropStat::new_list(found));
        }
        if !missing.is_empty() {
            propstat.push(PropStat::new_list(missing).with_status(StatusCode::NOT_FOUND));
        }
        Ok(Response::new_propstat(node.href(user.id), propstat))
    }

    /// One property's value on a node; `None` when the node does not have it.
    async fn value(
        &self,
        user: &PrincipalInfo,
        node: &Node,
        prop: &DavProperty,
        content: &Content,
        instances_limit: &mut usize,
    ) -> Result<Option<DavValue>, Error> {
        let collection = match node {
            Node::Collection(collection) | Node::Event(collection, _) | Node::Contact(collection, _) => {
                Some(collection)
            }
            _ => None,
        };
        let is_object = !node.is_collection();
        let etag = |modseq: i64| Some(DavValue::String(format!("\"{modseq}\"")));
        Ok(match prop {
            DavProperty::WebDav(property) => match property {
                WebDavProperty::ResourceType => Some(DavValue::ResourceTypes(match node {
                    Node::Principal(_) => vec![ResourceType::Collection, ResourceType::Principal],
                    Node::Collection(Collection::Calendar { .. }) => {
                        vec![ResourceType::Collection, ResourceType::Calendar]
                    }
                    Node::Collection(Collection::Inbox { .. }) => {
                        vec![ResourceType::Collection, ResourceType::ScheduleInbox]
                    }
                    Node::Collection(Collection::Outbox { .. }) => {
                        vec![ResourceType::Collection, ResourceType::ScheduleOutbox]
                    }
                    Node::Collection(Collection::Addressbook { .. }) => {
                        vec![ResourceType::Collection, ResourceType::AddressBook]
                    }
                    Node::Event(..) | Node::Contact(..) => vec![],
                    _ => vec![ResourceType::Collection],
                })),
                WebDavProperty::DisplayName => match node {
                    Node::Principal(principal) => Some(principal.display_name.clone().into()),
                    Node::Collection(Collection::Calendar { info, .. }) => Some(info.name.clone().into()),
                    Node::Collection(Collection::Addressbook { info, .. }) => Some(info.name.clone().into()),
                    Node::Collection(Collection::Inbox { .. }) => Some("Inbox".into()),
                    Node::Collection(Collection::Outbox { .. }) => Some("Outbox".into()),
                    _ => None,
                },
                WebDavProperty::GetETag => match node {
                    Node::Event(_, event) => etag(event.modseq),
                    Node::Contact(_, contact) => etag(contact.modseq),
                    Node::Collection(Collection::Calendar { info, .. }) => etag(info.modseq),
                    Node::Collection(Collection::Addressbook { info, .. }) => etag(info.modseq),
                    _ => None,
                },
                WebDavProperty::SyncToken => match collection {
                    Some(collection @ (Collection::Calendar { .. } | Collection::Addressbook { .. })) if !is_object => {
                        let state = self.groupware.state(collection.owner()).await?;
                        Some(sync_token(state).into())
                    }
                    _ => None,
                },
                WebDavProperty::GetContentType => match node {
                    Node::Event(_, event) => Some(
                        format!("text/calendar; charset=utf-8; component={}", event.component.to_lowercase()).into(),
                    ),
                    Node::Contact(..) => Some("text/vcard; charset=utf-8".into()),
                    _ => None,
                },
                WebDavProperty::GetContentLength => match node {
                    Node::Event(_, event) => Some((event.size as u64).into()),
                    Node::Contact(_, contact) => Some((contact.size as u64).into()),
                    _ => None,
                },
                WebDavProperty::CurrentUserPrincipal => Some(DavValue::href(path::principal(user.id))),
                WebDavProperty::PrincipalCollectionSet => Some(DavValue::href(format!("{}/principals/", path::BASE))),
                WebDavProperty::PrincipalUrl => match node {
                    Node::Principal(principal) => Some(DavValue::href(path::principal(principal.id))),
                    _ => None,
                },
                WebDavProperty::GroupMembership | WebDavProperty::GroupMemberSet | WebDavProperty::AlternateUriSet => {
                    match node {
                        Node::Principal(_) => Some(DavValue::Hrefs(Vec::new())),
                        _ => None,
                    }
                }
                WebDavProperty::Owner => match (node, collection) {
                    (Node::Principal(principal), _) => Some(DavValue::href(path::principal(principal.id))),
                    (_, Some(collection)) => Some(DavValue::href(path::principal(collection.owner()))),
                    (Node::CalendarHome | Node::AddressbookHome, _) => Some(DavValue::href(path::principal(user.id))),
                    _ => None,
                },
                WebDavProperty::Group => Some(DavValue::Empty),
                WebDavProperty::SupportedReportSet => Some(DavValue::Reports(reports(node))),
                WebDavProperty::CurrentUserPrivilegeSet => Some(DavValue::Privileges(privileges(node))),
                WebDavProperty::SupportedPrivilegeSet => {
                    Some(DavValue::SupportedPrivileges(vec![supported_privileges(collection)]))
                }
                WebDavProperty::Acl => collection.map(|collection| {
                    // Read-only (RFC 0004, 8.1): the owner has everything; sharing is changed elsewhere.
                    DavValue::Acl(vec![Ace {
                        principal: path::principal(collection.owner()),
                        grant: vec![Privilege::All],
                        protected: true,
                    }])
                }),
                WebDavProperty::AclRestrictions => Some(DavValue::AclRestrictions),
                WebDavProperty::InheritedAclSet => Some(DavValue::Empty),
                WebDavProperty::QuotaUsedBytes | WebDavProperty::QuotaAvailableBytes => match collection {
                    Some(collection) if !is_object => {
                        let (used, limit) =
                            self.groupware.mail().quota(collection.owner()).await.map_err(Error::other)?;
                        if *property == WebDavProperty::QuotaUsedBytes {
                            Some(used.into())
                        } else {
                            limit.map(|limit| limit.saturating_sub(used).into())
                        }
                    }
                    _ => None,
                },
                WebDavProperty::SupportedLock | WebDavProperty::LockDiscovery => Some(DavValue::Empty),
                WebDavProperty::CreationDate | WebDavProperty::GetLastModified | WebDavProperty::GetContentLanguage => {
                    None
                }
            },
            DavProperty::GetCTag => match node {
                Node::Collection(Collection::Calendar { info, .. }) => etag(info.modseq),
                Node::Collection(Collection::Addressbook { info, .. }) => etag(info.modseq),
                _ => None,
            },
            DavProperty::CalDav(CalDavProperty::Named(property)) => match (property, node) {
                (CalDavName::CalendarHomeSet, Node::Principal(principal)) => {
                    Some(DavValue::href(path::calendar_home(principal.id)))
                }
                (CalDavName::CalendarUserAddressSet, Node::Principal(principal)) => {
                    let mut hrefs: Vec<String> =
                        principal.addresses.iter().map(|address| format!("mailto:{address}")).collect();
                    hrefs.push(path::principal(principal.id));
                    Some(DavValue::Hrefs(hrefs))
                }
                (CalDavName::CalendarUserType, Node::Principal(_)) => Some("INDIVIDUAL".into()),
                (CalDavName::ScheduleInboxUrl, Node::Principal(principal)) => {
                    Some(DavValue::href(format!("{}inbox/", path::calendar_home(principal.id))))
                }
                (CalDavName::ScheduleOutboxUrl, Node::Principal(principal)) => {
                    Some(DavValue::href(format!("{}outbox/", path::calendar_home(principal.id))))
                }
                (CalDavName::CalendarDescription, Node::Collection(Collection::Calendar { info, .. })) => {
                    info.description.clone().map(Into::into)
                }
                (CalDavName::TimezoneId, Node::Collection(Collection::Calendar { info, .. })) => {
                    info.timezone.clone().map(Into::into)
                }
                (CalDavName::CalendarTimezone, Node::Collection(Collection::Calendar { info, .. })) => {
                    info.timezone.as_deref().and_then(vtimezone).map(DavValue::Data)
                }
                (CalDavName::SupportedCalendarComponentSet, Node::Collection(Collection::Calendar { info, .. })) => {
                    Some(DavValue::Components(
                        info.components
                            .iter()
                            .filter(|name| matches!(name.as_str(), "VEVENT" | "VTODO" | "VJOURNAL"))
                            .cloned()
                            .collect(),
                    ))
                }
                (
                    CalDavName::SupportedCalendarComponentSet,
                    Node::Collection(Collection::Inbox { .. } | Collection::Outbox { .. }),
                ) => {
                    Some(DavValue::Components(["VEVENT", "VTODO", "VJOURNAL", "VFREEBUSY"].map(str::to_owned).to_vec()))
                }
                (CalDavName::SupportedCalendarData, Node::Collection(Collection::Calendar { .. })) => {
                    Some(DavValue::SupportedCalendarData)
                }
                (CalDavName::SupportedCollationSet, Node::Collection(Collection::Calendar { .. })) => {
                    Some(collations())
                }
                (CalDavName::MaxResourceSize, Node::Collection(Collection::Calendar { .. })) => {
                    Some((ical::MAX_OBJECT_SIZE as u64).into())
                }
                (CalDavName::MaxInstances, Node::Collection(Collection::Calendar { .. })) => {
                    Some((ical::MAX_INSTANCES as u64).into())
                }
                (CalDavName::MinDateTime, Node::Collection(Collection::Calendar { .. })) => {
                    Some("00010101T000000Z".into())
                }
                (CalDavName::MaxDateTime, Node::Collection(Collection::Calendar { .. })) => {
                    Some("99991231T235959Z".into())
                }
                (CalDavName::ScheduleCalendarTransp, Node::Collection(Collection::Calendar { .. })) => {
                    Some(DavValue::Opaque(true))
                }
                (CalDavName::ScheduleDefaultCalendarUrl, Node::Collection(Collection::Inbox { owner })) => {
                    let default = self.groupware.default_calendar(*owner).await?;
                    Some(DavValue::href(format!(
                        "{}{}/",
                        path::calendar_home(user.id),
                        path::encode(&default.resource_name)
                    )))
                }
                (CalDavName::ScheduleTag, Node::Event(_, event)) => etag(event.schedule_tag),
                _ => None,
            },
            DavProperty::CalDav(CalDavProperty::CalendarData(data)) => match (node, &content.text) {
                (Node::Event(..), Some(text)) => match calendar_data(text, data, content, instances_limit) {
                    Some(text) => Some(DavValue::Data(text)),
                    None => return Err(Error::Condition(StatusCode::FORBIDDEN, Condition::MaxInstances)),
                },
                _ => None,
            },
            DavProperty::CardDav(CardDavProperty::Named(property)) => match (property, node) {
                (CardDavName::AddressbookHomeSet, Node::Principal(principal)) => {
                    Some(DavValue::href(path::addressbook_home(principal.id)))
                }
                (CardDavName::AddressbookDescription, Node::Collection(Collection::Addressbook { info, .. })) => {
                    info.description.clone().map(Into::into)
                }
                (CardDavName::SupportedAddressData, Node::Collection(Collection::Addressbook { .. })) => {
                    Some(DavValue::SupportedAddressData)
                }
                (CardDavName::SupportedCollationSet, Node::Collection(Collection::Addressbook { .. })) => {
                    Some(collations())
                }
                (CardDavName::MaxResourceSize, Node::Collection(Collection::Addressbook { .. })) => {
                    Some((ical::MAX_OBJECT_SIZE as u64).into())
                }
                _ => None,
            },
            DavProperty::CardDav(CardDavProperty::AddressData(data)) => match (node, &content.text) {
                (Node::Contact(..), Some(text)) => Some(DavValue::Data(match Parser::new(text).entry() {
                    Entry::VCard(card) => {
                        let stored = card.version().unwrap_or(VCardVersion::V4_0);
                        let version = data.version.unwrap_or(stored);
                        if data.properties.is_empty() && version == stored {
                            text.to_owned()
                        } else {
                            query::serialize_vcard(&card, &data.properties, version)
                        }
                    }
                    _ => text.to_owned(),
                })),
                _ => None,
            },
            DavProperty::Dead(name) => {
                let stored = dead_properties(node).and_then(|dead| dead.get(&name.ns, &name.name).cloned());
                match stored {
                    Some(property) => Some(DavValue::Xml(property.xml)),
                    // Colours and order set through JMAP or the web app show in Apple's properties as well.
                    None => match (name.name.as_str(), node) {
                        ("calendar-color", Node::Collection(Collection::Calendar { info, .. })) => {
                            info.color.clone().map(DavValue::String)
                        }
                        ("calendar-order", Node::Collection(Collection::Calendar { info, .. })) => {
                            Some(DavValue::String(info.sort_order.to_string()))
                        }
                        _ => None,
                    },
                }
            }
        })
    }
}

fn collations() -> DavValue {
    DavValue::Collations(vec![Collation::AsciiCasemap, Collation::UnicodeCasemap])
}

/// A calendar with only the time zone a calendar names (`calendar-timezone`, RFC 4791, 5.2.2), its rules from a year
/// back to ten years ahead.
fn vtimezone(name: &str) -> Option<String> {
    use calcard::icalendar::{ICalendarComponent, ICalendarEntry, ICalendarProperty, ICalendarValue};
    let text = |property, value: &str| ICalendarEntry {
        name: property,
        params: vec![],
        values: smallvec::smallvec![ICalendarValue::Text(value.into())],
    };
    let mut ical = ICalendar {
        components: vec![ICalendarComponent {
            component_type: ICalendarComponentType::VCalendar,
            entries: vec![text(ICalendarProperty::Version, "2.0"), text(ICalendarProperty::Prodid, crate::PROD_ID)],
            component_ids: vec![],
        }],
    };
    let now = jiff::Timestamp::now().as_second();
    ical.add_timezone(name, now - 366 * 86_400, now + 10 * 366 * 86_400)?;
    Some(ical.to_string())
}

/// The sync token of a collection: the owner's state (RFC 0004, 8.1).
pub(crate) fn sync_token(state: i64) -> String {
    format!("urn:kernoid:sync:{state}")
}

/// The state a sync token names; `None` if it is not kernoid's.
pub(crate) fn parse_sync_token(token: &str) -> Option<i64> {
    token.strip_prefix("urn:kernoid:sync:")?.parse().ok()
}
