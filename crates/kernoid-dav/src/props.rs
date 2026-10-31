// SPDX-License-Identifier: AGPL-3.0-or-later
//! Properties of principals, homes, collections and objects for `PROPFIND` and reports (RFC 4918, 4791, 6352, 6638,
//! 3744, 5397, 6578), read-only ACLs included. Which value each property has follows what Stalwart answers
//! (`crates/dav/src/common/propfind.rs`, v0.16.27), so that the same clients work.

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
        requests::NsDeadProperty,
        schema::{
            Collation, Namespace,
            property::{
                CalDavProperty, CardDavProperty, Comp, DavProperty, DavValue, PrincipalProperty, Privilege, ReportSet,
                ResourceType, SupportedCollation, WebDavProperty,
            },
            request::{DavPropertyValue, PropFind},
            response::{Ace, AclRestrictions, GrantDeny, Href, Principal, PropStat, Response, SupportedPrivilege},
        },
        types::dead_property::DeadProperty,
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
            DavProperty::Principal(PrincipalProperty::PrincipalURL),
            DavProperty::Principal(PrincipalProperty::CalendarHomeSet),
            DavProperty::Principal(PrincipalProperty::AddressbookHomeSet),
            DavProperty::Principal(PrincipalProperty::CalendarUserAddressSet),
            DavProperty::Principal(PrincipalProperty::ScheduleInboxURL),
            DavProperty::Principal(PrincipalProperty::ScheduleOutboxURL),
        ]),
        Node::Collection(Collection::Calendar { .. }) => props.extend([
            DavProperty::WebDav(WebDavProperty::SyncToken),
            DavProperty::WebDav(WebDavProperty::GetCTag),
            DavProperty::CalDav(CalDavProperty::CalendarDescription),
            DavProperty::CalDav(CalDavProperty::SupportedCalendarComponentSet),
            DavProperty::CalDav(CalDavProperty::SupportedCalendarData),
            DavProperty::CalDav(CalDavProperty::MaxResourceSize),
        ]),
        Node::Collection(Collection::Addressbook { .. }) => props.extend([
            DavProperty::WebDav(WebDavProperty::SyncToken),
            DavProperty::WebDav(WebDavProperty::GetCTag),
            DavProperty::CardDav(CardDavProperty::AddressbookDescription),
            DavProperty::CardDav(CardDavProperty::SupportedAddressData),
            DavProperty::CardDav(CardDavProperty::MaxResourceSize),
        ]),
        Node::Event(..) => props.push(DavProperty::CalDav(CalDavProperty::ScheduleTag)),
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
        Collection::Inbox { .. } => Privilege::scheduling(true, true),
        Collection::Outbox { .. } => Privilege::scheduling(false, true),
        _ => {
            let is_calendar = collection.is_calendar();
            match collection.level() {
                Level::Admin => Privilege::all(is_calendar),
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

fn dead_properties(node: &Node) -> Option<DeadProperty> {
    let value = match node {
        Node::Collection(Collection::Calendar { info, .. }) => &info.dead_properties,
        Node::Collection(Collection::Addressbook { info, .. }) => &info.dead_properties,
        _ => return None,
    };
    serde_json::from_value(value.clone()).ok()
}

/// The calendar data of an event as asked for, or `None` for too many instances.
fn calendar_data(
    text: &str,
    data: &crate::proto::schema::property::CalendarData,
    content: &Content,
    instances_limit: &mut usize,
) -> Option<String> {
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
                    let mut depth = 0;
                    for tag in &dead.0 {
                        match tag {
                            crate::proto::types::dead_property::DeadPropertyTag::ElementStart(start) => {
                                if depth == 0 {
                                    props.push(DavProperty::DeadProperty(start.clone()));
                                }
                                depth += 1;
                            }
                            crate::proto::types::dead_property::DeadPropertyTag::ElementEnd => depth -= 1,
                            _ => {}
                        }
                    }
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
        Ok(match prop {
            DavProperty::WebDav(property) => match property {
                WebDavProperty::ResourceType => Some(
                    match node {
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
                    }
                    .into(),
                ),
                WebDavProperty::DisplayName => match node {
                    Node::Principal(principal) => Some(principal.display_name.clone().into()),
                    Node::Collection(Collection::Calendar { info, .. }) => Some(info.name.clone().into()),
                    Node::Collection(Collection::Addressbook { info, .. }) => Some(info.name.clone().into()),
                    Node::Collection(Collection::Inbox { .. }) => Some("Inbox".into()),
                    Node::Collection(Collection::Outbox { .. }) => Some("Outbox".into()),
                    _ => None,
                },
                WebDavProperty::GetETag => match node {
                    Node::Event(_, event) => Some(format!("\"{}\"", event.modseq).into()),
                    Node::Contact(_, contact) => Some(format!("\"{}\"", contact.modseq).into()),
                    Node::Collection(Collection::Calendar { info, .. }) => Some(format!("\"{}\"", info.modseq).into()),
                    Node::Collection(Collection::Addressbook { info, .. }) => {
                        Some(format!("\"{}\"", info.modseq).into())
                    }
                    _ => None,
                },
                WebDavProperty::GetCTag => match node {
                    Node::Collection(Collection::Calendar { info, .. }) => Some(format!("\"{}\"", info.modseq).into()),
                    Node::Collection(Collection::Addressbook { info, .. }) => {
                        Some(format!("\"{}\"", info.modseq).into())
                    }
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
                WebDavProperty::CurrentUserPrincipal => Some(vec![Href(path::principal(user.id))].into()),
                WebDavProperty::PrincipalCollectionSet => {
                    Some(vec![Href(format!("{}/principals/", path::BASE))].into())
                }
                WebDavProperty::Owner => match (node, collection) {
                    (Node::Principal(principal), _) => Some(vec![Href(path::principal(principal.id))].into()),
                    (_, Some(collection)) => Some(vec![Href(path::principal(collection.owner()))].into()),
                    (Node::CalendarHome | Node::AddressbookHome, _) => {
                        Some(vec![Href(path::principal(user.id))].into())
                    }
                    _ => None,
                },
                WebDavProperty::Group => Some(DavValue::Null),
                WebDavProperty::SupportedReportSet => Some(
                    match node {
                        Node::Principal(_) | Node::Principals | Node::Root => ReportSet::principal(),
                        Node::Collection(Collection::Addressbook { .. })
                        | Node::Contact(..)
                        | Node::AddressbookHome => ReportSet::addressbook(),
                        _ => ReportSet::calendar(),
                    }
                    .into(),
                ),
                WebDavProperty::CurrentUserPrivilegeSet => Some(privileges(node).into()),
                WebDavProperty::SupportedPrivilegeSet => Some(
                    vec![match collection {
                        Some(Collection::Inbox { .. }) => SupportedPrivilege::all_scheduling_privileges(true),
                        Some(Collection::Outbox { .. }) => SupportedPrivilege::all_scheduling_privileges(false),
                        Some(collection) => SupportedPrivilege::all_privileges(collection.is_calendar()),
                        None => SupportedPrivilege::all_privileges(true),
                    }]
                    .into(),
                ),
                WebDavProperty::Acl => collection.map(|collection| {
                    // Read-only (RFC 0004, 8.1): the owner has everything; sharing is changed elsewhere.
                    vec![
                        Ace::new(
                            Principal::Href(Href(path::principal(collection.owner()))),
                            GrantDeny::grant(Privilege::all(collection.is_calendar())),
                        )
                        .with_protected(),
                    ]
                    .into()
                }),
                WebDavProperty::AclRestrictions => {
                    Some(AclRestrictions::default().with_no_invert().with_grant_only().into())
                }
                WebDavProperty::InheritedAclSet => Some(DavValue::Null),
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
                WebDavProperty::SupportedLock | WebDavProperty::LockDiscovery => Some(DavValue::Null),
                WebDavProperty::CreationDate | WebDavProperty::GetLastModified | WebDavProperty::GetContentLanguage => {
                    None
                }
            },
            DavProperty::Principal(property) => {
                let Node::Principal(principal) = node else { return Ok(None) };
                match property {
                    PrincipalProperty::PrincipalURL => Some(vec![Href(path::principal(principal.id))].into()),
                    PrincipalProperty::CalendarHomeSet => Some(vec![Href(path::calendar_home(principal.id))].into()),
                    PrincipalProperty::AddressbookHomeSet => {
                        Some(vec![Href(path::addressbook_home(principal.id))].into())
                    }
                    PrincipalProperty::CalendarUserAddressSet => {
                        let mut hrefs: Vec<Href> =
                            principal.addresses.iter().map(|address| Href(format!("mailto:{address}"))).collect();
                        hrefs.push(Href(path::principal(principal.id)));
                        Some(hrefs.into())
                    }
                    PrincipalProperty::CalendarUserType => Some("INDIVIDUAL".into()),
                    PrincipalProperty::ScheduleInboxURL => {
                        Some(vec![Href(format!("{}inbox/", path::calendar_home(principal.id)))].into())
                    }
                    PrincipalProperty::ScheduleOutboxURL => {
                        Some(vec![Href(format!("{}outbox/", path::calendar_home(principal.id)))].into())
                    }
                    PrincipalProperty::GroupMembership
                    | PrincipalProperty::GroupMemberSet
                    | PrincipalProperty::AlternateURISet => Some(Vec::<Href>::new().into()),
                    PrincipalProperty::PrincipalAddress => None,
                }
            }
            DavProperty::CalDav(property) => match (property, node) {
                (CalDavProperty::CalendarDescription, Node::Collection(Collection::Calendar { info, .. })) => {
                    info.description.clone().map(Into::into)
                }
                (CalDavProperty::TimezoneId, Node::Collection(Collection::Calendar { info, .. })) => {
                    info.timezone.clone().map(Into::into)
                }
                (CalDavProperty::CalendarTimezone, Node::Collection(Collection::Calendar { info, .. })) => {
                    info.timezone.as_deref().and_then(vtimezone).map(DavValue::CData)
                }
                (
                    CalDavProperty::SupportedCalendarComponentSet,
                    Node::Collection(Collection::Calendar { info, .. }),
                ) => Some(
                    info.components
                        .iter()
                        .filter_map(|name| match name.as_str() {
                            "VEVENT" => Some(Comp(ICalendarComponentType::VEvent)),
                            "VTODO" => Some(Comp(ICalendarComponentType::VTodo)),
                            "VJOURNAL" => Some(Comp(ICalendarComponentType::VJournal)),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .into(),
                ),
                (
                    CalDavProperty::SupportedCalendarComponentSet,
                    Node::Collection(Collection::Inbox { .. } | Collection::Outbox { .. }),
                ) => Some(DavValue::all_calendar_components()),
                (CalDavProperty::SupportedCalendarData, Node::Collection(Collection::Calendar { .. })) => {
                    Some(DavValue::SupportedCalendarData)
                }
                (CalDavProperty::SupportedCollationSet, Node::Collection(Collection::Calendar { .. })) => {
                    Some(collations(Namespace::CalDav))
                }
                (CalDavProperty::MaxResourceSize, Node::Collection(Collection::Calendar { .. })) => {
                    Some((ical::MAX_OBJECT_SIZE as u64).into())
                }
                (CalDavProperty::MaxInstances, Node::Collection(Collection::Calendar { .. })) => {
                    Some((ical::MAX_INSTANCES as u64).into())
                }
                (CalDavProperty::MinDateTime, Node::Collection(Collection::Calendar { .. })) => {
                    Some("0001-01-01T00:00:00Z".into())
                }
                (CalDavProperty::MaxDateTime, Node::Collection(Collection::Calendar { .. })) => {
                    Some("9999-12-31T23:59:59Z".into())
                }
                (CalDavProperty::ScheduleCalendarTransp, Node::Collection(Collection::Calendar { .. })) => {
                    Some(DeadProperty::single_with_ns(Namespace::CalDav, "opaque").into())
                }
                (CalDavProperty::ScheduleDefaultCalendarURL, Node::Collection(Collection::Inbox { owner })) => {
                    let default = self.groupware.default_calendar(*owner).await?;
                    Some(
                        vec![Href(format!(
                            "{}{}/",
                            path::calendar_home(user.id),
                            path::encode(&default.resource_name)
                        ))]
                        .into(),
                    )
                }
                (CalDavProperty::ScheduleTag, Node::Event(_, event)) => {
                    Some(format!("\"{}\"", event.schedule_tag).into())
                }
                (CalDavProperty::CalendarData(data), Node::Event(..)) => match &content.text {
                    Some(text) => match calendar_data(text, data, content, instances_limit) {
                        Some(text) => Some(DavValue::CData(text)),
                        None => {
                            return Err(Error::Condition(
                                StatusCode::FORBIDDEN,
                                crate::proto::schema::response::CalCondition::MaxInstances.into(),
                            ));
                        }
                    },
                    None => None,
                },
                _ => None,
            },
            DavProperty::CardDav(property) => match (property, node) {
                (CardDavProperty::AddressbookDescription, Node::Collection(Collection::Addressbook { info, .. })) => {
                    info.description.clone().map(Into::into)
                }
                (CardDavProperty::SupportedAddressData, Node::Collection(Collection::Addressbook { .. })) => {
                    Some(DavValue::SupportedAddressData)
                }
                (CardDavProperty::SupportedCollationSet, Node::Collection(Collection::Addressbook { .. })) => {
                    Some(collations(Namespace::CardDav))
                }
                (CardDavProperty::MaxResourceSize, Node::Collection(Collection::Addressbook { .. })) => {
                    Some((ical::MAX_OBJECT_SIZE as u64).into())
                }
                (CardDavProperty::AddressData { properties, version }, Node::Contact(..)) => {
                    content.text.as_deref().map(|text| match Parser::new(text).entry() {
                        Entry::VCard(card) => {
                            let version = version.unwrap_or_else(|| card.version().unwrap_or(VCardVersion::V4_0));
                            if properties.is_empty() && version == card.version().unwrap_or(VCardVersion::V4_0) {
                                DavValue::CData(text.to_owned())
                            } else {
                                DavValue::CData(query::serialize_vcard(&card, properties, version))
                            }
                        }
                        _ => DavValue::CData(text.to_owned()),
                    })
                }
                _ => None,
            },
            DavProperty::DeadProperty(tag) => {
                let stored = dead_properties(node).and_then(|dead| dead.find_tag(&tag.name));
                match stored {
                    Some(value) => Some(value.into()),
                    // Colours and order set through JMAP or the web app show in Apple's properties as well.
                    None => match (tag.name.as_str(), node) {
                        ("calendar-color", Node::Collection(Collection::Calendar { info, .. })) => {
                            info.color.clone().map(|color| {
                                DeadProperty(vec![crate::proto::types::dead_property::DeadPropertyTag::Text(color)])
                                    .into()
                            })
                        }
                        ("calendar-order", Node::Collection(Collection::Calendar { info, .. })) => Some(
                            DeadProperty(vec![crate::proto::types::dead_property::DeadPropertyTag::Text(
                                info.sort_order.to_string(),
                            )])
                            .into(),
                        ),
                        _ => None,
                    },
                }
            }
        })
    }
}

fn collations(namespace: Namespace) -> DavValue {
    vec![
        SupportedCollation { collation: Collation::AsciiCasemap, namespace },
        SupportedCollation { collation: Collation::UnicodeCasemap, namespace },
    ]
    .into()
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
    let now = chrono::Utc::now().timestamp();
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
