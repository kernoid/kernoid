// SPDX-License-Identifier: AGPL-3.0-or-later
//! Properties – their names, the values kernoid gives them and the values clients set – and the elements inside values:
//! resource types, privileges and ACLs (RFC 3744), reports, locks (RFC 4918, 15), `calendar-data` (RFC 4791, 9.6) and
//! `address-data` (RFC 6352, 10.4).

use kernoid_pim::vcard::Version as VCardVersion;
use quick_xml::escape::escape;

use super::{Collation, Namespace};
use crate::proto::{
    Depth, Error,
    names::{ICalendarComponentType, ICalendarProperty, VCardProperty},
    types::TimeRange,
    xml::{Element, Writer},
};

/// Declares a set of properties of one namespace with their names.
macro_rules! properties {
    ($(#[$meta:meta])* $kind:ident { $($variant:ident = $name:literal,)* }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $kind {
            $($variant,)*
        }

        impl $kind {
            pub const ALL: &'static [$kind] = &[$($kind::$variant,)*];

            pub fn name(self) -> &'static str {
                match self {
                    $($kind::$variant => $name,)*
                }
            }

            pub fn from_name(name: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|property| property.name() == name)
            }
        }
    };
}

properties! {
    /// Properties in `DAV:` (RFC 4918, 15; RFC 3744, 4 and 5; RFC 4331; RFC 5397; RFC 6578).
    WebDavProperty {
        CreationDate = "creationdate",
        DisplayName = "displayname",
        GetContentLanguage = "getcontentlanguage",
        GetContentLength = "getcontentlength",
        GetContentType = "getcontenttype",
        GetETag = "getetag",
        GetLastModified = "getlastmodified",
        ResourceType = "resourcetype",
        LockDiscovery = "lockdiscovery",
        SupportedLock = "supportedlock",
        CurrentUserPrincipal = "current-user-principal",
        PrincipalCollectionSet = "principal-collection-set",
        PrincipalUrl = "principal-URL",
        AlternateUriSet = "alternate-URI-set",
        GroupMemberSet = "group-member-set",
        GroupMembership = "group-membership",
        Owner = "owner",
        Group = "group",
        SupportedPrivilegeSet = "supported-privilege-set",
        CurrentUserPrivilegeSet = "current-user-privilege-set",
        Acl = "acl",
        AclRestrictions = "acl-restrictions",
        InheritedAclSet = "inherited-acl-set",
        SupportedReportSet = "supported-report-set",
        SyncToken = "sync-token",
        QuotaAvailableBytes = "quota-available-bytes",
        QuotaUsedBytes = "quota-used-bytes",
    }
}

properties! {
    /// Properties in CalDAV's namespace without a value of their own in requests (RFC 4791, 5.2 and 6.2; RFC 6638;
    /// RFC 7809).
    CalDavName {
        CalendarDescription = "calendar-description",
        CalendarTimezone = "calendar-timezone",
        TimezoneId = "calendar-timezone-id",
        SupportedCalendarComponentSet = "supported-calendar-component-set",
        SupportedCalendarData = "supported-calendar-data",
        SupportedCollationSet = "supported-collation-set",
        MaxResourceSize = "max-resource-size",
        MinDateTime = "min-date-time",
        MaxDateTime = "max-date-time",
        MaxInstances = "max-instances",
        MaxAttendeesPerInstance = "max-attendees-per-instance",
        CalendarHomeSet = "calendar-home-set",
        CalendarUserAddressSet = "calendar-user-address-set",
        CalendarUserType = "calendar-user-type",
        ScheduleInboxUrl = "schedule-inbox-URL",
        ScheduleOutboxUrl = "schedule-outbox-URL",
        ScheduleDefaultCalendarUrl = "schedule-default-calendar-URL",
        ScheduleCalendarTransp = "schedule-calendar-transp",
        ScheduleTag = "schedule-tag",
    }
}

properties! {
    /// Properties in CardDAV's namespace without a value of their own in requests (RFC 6352, 6.2 and 7.1).
    CardDavName {
        AddressbookDescription = "addressbook-description",
        SupportedAddressData = "supported-address-data",
        SupportedCollationSet = "supported-collation-set",
        MaxResourceSize = "max-resource-size",
        AddressbookHomeSet = "addressbook-home-set",
        PrincipalAddress = "principal-address",
    }
}

/// A property in CalDAV's namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalDavProperty {
    Named(CalDavName),
    /// `calendar-data`, with what of the data is asked for.
    CalendarData(CalendarData),
}

/// A property in CardDAV's namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardDavProperty {
    Named(CardDavName),
    /// `address-data`, with what of the data is asked for.
    AddressData(AddressData),
}

/// The name of a property kernoid does not know.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PropertyName {
    pub ns: String,
    pub name: String,
}

/// A property, by name – with what is asked of `calendar-data` and `address-data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DavProperty {
    WebDav(WebDavProperty),
    CalDav(CalDavProperty),
    CardDav(CardDavProperty),
    /// `getctag` (Apple's calendar server namespace), which some clients still read.
    GetCTag,
    /// Any other property: a dead property, if a client set it.
    Dead(PropertyName),
}

impl From<WebDavProperty> for DavProperty {
    fn from(property: WebDavProperty) -> Self {
        Self::WebDav(property)
    }
}

impl From<CalDavName> for DavProperty {
    fn from(property: CalDavName) -> Self {
        Self::CalDav(CalDavProperty::Named(property))
    }
}

impl From<CardDavName> for DavProperty {
    fn from(property: CardDavName) -> Self {
        Self::CardDav(CardDavProperty::Named(property))
    }
}

impl DavProperty {
    /// The property an element names.
    pub fn from_element(element: &Element) -> Result<Self, Error> {
        let dead = || Self::Dead(PropertyName { ns: element.ns.clone(), name: element.name.clone() });
        Ok(match Namespace::from_uri(&element.ns) {
            Some(Namespace::Dav) => WebDavProperty::from_name(&element.name).map_or_else(dead, Self::WebDav),
            Some(Namespace::CalDav) if element.name == "calendar-data" => {
                Self::CalDav(CalDavProperty::CalendarData(CalendarData::from_element(element)?))
            }
            Some(Namespace::CalDav) => CalDavName::from_name(&element.name).map_or_else(dead, Self::from),
            Some(Namespace::CardDav) if element.name == "address-data" => {
                Self::CardDav(CardDavProperty::AddressData(AddressData::from_element(element)?))
            }
            Some(Namespace::CardDav) => CardDavName::from_name(&element.name).map_or_else(dead, Self::from),
            Some(Namespace::CalendarServer) if element.name == "getctag" => Self::GetCTag,
            _ => dead(),
        })
    }

    /// The namespace and name of the property.
    pub fn qualified_name(&self) -> (&str, &str) {
        match self {
            Self::WebDav(property) => (Namespace::Dav.uri(), property.name()),
            Self::CalDav(CalDavProperty::Named(property)) => (Namespace::CalDav.uri(), property.name()),
            Self::CalDav(CalDavProperty::CalendarData(_)) => (Namespace::CalDav.uri(), "calendar-data"),
            Self::CardDav(CardDavProperty::Named(property)) => (Namespace::CardDav.uri(), property.name()),
            Self::CardDav(CardDavProperty::AddressData(_)) => (Namespace::CardDav.uri(), "address-data"),
            Self::GetCTag => (Namespace::CalendarServer.uri(), "getctag"),
            Self::Dead(name) => (&name.ns, &name.name),
        }
    }

    /// Whether this is the property `name` of `ns`.
    pub fn is(&self, ns: &str, name: &str) -> bool {
        self.qualified_name() == (ns, name)
    }
}

/// A resource type (`resourcetype`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceType {
    Collection,
    Principal,
    Calendar,
    ScheduleInbox,
    ScheduleOutbox,
    AddressBook,
}

impl ResourceType {
    const ALL: [ResourceType; 6] = [
        Self::Collection,
        Self::Principal,
        Self::Calendar,
        Self::ScheduleInbox,
        Self::ScheduleOutbox,
        Self::AddressBook,
    ];

    pub fn qualified_name(self) -> (Namespace, &'static str) {
        match self {
            Self::Collection => (Namespace::Dav, "collection"),
            Self::Principal => (Namespace::Dav, "principal"),
            Self::Calendar => (Namespace::CalDav, "calendar"),
            Self::ScheduleInbox => (Namespace::CalDav, "schedule-inbox"),
            Self::ScheduleOutbox => (Namespace::CalDav, "schedule-outbox"),
            Self::AddressBook => (Namespace::CardDav, "addressbook"),
        }
    }

    fn from_element(element: &Element) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| {
            let (ns, name) = kind.qualified_name();
            element.is(ns, name)
        })
    }
}

/// A privilege (RFC 3744, 3; CalDAV's `read-free-busy`, RFC 4791, 6.1.1; scheduling's, RFC 6638, 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Privilege {
    All,
    Read,
    Write,
    WriteProperties,
    WriteContent,
    Unlock,
    ReadAcl,
    ReadCurrentUserPrivilegeSet,
    WriteAcl,
    Bind,
    Unbind,
    ReadFreeBusy,
    ScheduleDeliver,
    ScheduleDeliverInvite,
    ScheduleDeliverReply,
    ScheduleQueryFreebusy,
    ScheduleSend,
    ScheduleSendInvite,
    ScheduleSendReply,
    ScheduleSendFreebusy,
}

impl Privilege {
    pub fn qualified_name(self) -> (Namespace, &'static str) {
        match self {
            Self::All => (Namespace::Dav, "all"),
            Self::Read => (Namespace::Dav, "read"),
            Self::Write => (Namespace::Dav, "write"),
            Self::WriteProperties => (Namespace::Dav, "write-properties"),
            Self::WriteContent => (Namespace::Dav, "write-content"),
            Self::Unlock => (Namespace::Dav, "unlock"),
            Self::ReadAcl => (Namespace::Dav, "read-acl"),
            Self::ReadCurrentUserPrivilegeSet => (Namespace::Dav, "read-current-user-privilege-set"),
            Self::WriteAcl => (Namespace::Dav, "write-acl"),
            Self::Bind => (Namespace::Dav, "bind"),
            Self::Unbind => (Namespace::Dav, "unbind"),
            Self::ReadFreeBusy => (Namespace::CalDav, "read-free-busy"),
            Self::ScheduleDeliver => (Namespace::CalDav, "schedule-deliver"),
            Self::ScheduleDeliverInvite => (Namespace::CalDav, "schedule-deliver-invite"),
            Self::ScheduleDeliverReply => (Namespace::CalDav, "schedule-deliver-reply"),
            Self::ScheduleQueryFreebusy => (Namespace::CalDav, "schedule-query-freebusy"),
            Self::ScheduleSend => (Namespace::CalDav, "schedule-send"),
            Self::ScheduleSendInvite => (Namespace::CalDav, "schedule-send-invite"),
            Self::ScheduleSendReply => (Namespace::CalDav, "schedule-send-reply"),
            Self::ScheduleSendFreebusy => (Namespace::CalDav, "schedule-send-freebusy"),
        }
    }

    fn write(self, writer: &mut Writer) {
        let (ns, name) = self.qualified_name();
        writer.open(Namespace::Dav, "privilege");
        writer.empty(ns, name);
        writer.close(Namespace::Dav, "privilege");
    }
}

/// One privilege of `supported-privilege-set`, with those it aggregates (RFC 3744, 5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedPrivilege {
    pub privilege: Privilege,
    pub is_abstract: bool,
    pub description: &'static str,
    pub children: Vec<SupportedPrivilege>,
}

impl SupportedPrivilege {
    pub fn new(privilege: Privilege, description: &'static str) -> Self {
        Self { privilege, is_abstract: false, description, children: Vec::new() }
    }

    pub fn with(mut self, children: impl IntoIterator<Item = SupportedPrivilege>) -> Self {
        self.children.extend(children);
        self
    }

    fn write(&self, writer: &mut Writer) {
        writer.open(Namespace::Dav, "supported-privilege");
        self.privilege.write(writer);
        if self.is_abstract {
            writer.empty(Namespace::Dav, "abstract");
        }
        writer.start_tag(Namespace::Dav, "description").attr("xml:lang", "en").end_start();
        writer.text(self.description);
        writer.close(Namespace::Dav, "description");
        for child in &self.children {
            child.write(writer);
        }
        writer.close(Namespace::Dav, "supported-privilege");
    }
}

/// An access control entry that grants (RFC 3744, 5.5) – kernoid's ACLs are read-only and grant only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    /// The principal's URL.
    pub principal: String,
    pub grant: Vec<Privilege>,
    pub protected: bool,
}

/// A report (RFC 3253, 3.1.5 `supported-report-set`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReportName {
    CalendarQuery,
    CalendarMultiget,
    FreeBusyQuery,
    AddressbookQuery,
    AddressbookMultiget,
    SyncCollection,
    ExpandProperty,
    PrincipalMatch,
    PrincipalPropertySearch,
    PrincipalSearchPropertySet,
    AclPrincipalPropSet,
}

impl ReportName {
    pub fn qualified_name(self) -> (Namespace, &'static str) {
        match self {
            Self::CalendarQuery => (Namespace::CalDav, "calendar-query"),
            Self::CalendarMultiget => (Namespace::CalDav, "calendar-multiget"),
            Self::FreeBusyQuery => (Namespace::CalDav, "free-busy-query"),
            Self::AddressbookQuery => (Namespace::CardDav, "addressbook-query"),
            Self::AddressbookMultiget => (Namespace::CardDav, "addressbook-multiget"),
            Self::SyncCollection => (Namespace::Dav, "sync-collection"),
            Self::ExpandProperty => (Namespace::Dav, "expand-property"),
            Self::PrincipalMatch => (Namespace::Dav, "principal-match"),
            Self::PrincipalPropertySearch => (Namespace::Dav, "principal-property-search"),
            Self::PrincipalSearchPropertySet => (Namespace::Dav, "principal-search-property-set"),
            Self::AclPrincipalPropSet => (Namespace::Dav, "acl-principal-prop-set"),
        }
    }
}

/// The scope of a write lock (RFC 4918, 14.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum LockScope {
    #[default]
    Exclusive,
    Shared,
}

impl LockScope {
    fn name(self) -> &'static str {
        match self {
            Self::Exclusive => "exclusive",
            Self::Shared => "shared",
        }
    }
}

/// A lock as `lockdiscovery` shows it (RFC 4918, 14.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveLock {
    /// The URL of the locked resource (`lockroot`).
    pub root: String,
    pub scope: LockScope,
    pub depth: Depth,
    /// Seconds left; `None` for infinite.
    pub timeout: Option<u64>,
    /// The `owner` the client gave, as XML.
    pub owner: Option<String>,
    /// Shown only to the one who took the lock.
    pub token: Option<String>,
}

impl ActiveLock {
    fn write(&self, writer: &mut Writer) {
        writer.open(Namespace::Dav, "activelock");
        write_lock_kind(writer, self.scope);
        writer.text_element(Namespace::Dav, "depth", self.depth.as_str());
        if let Some(owner) = &self.owner {
            writer.open(Namespace::Dav, "owner");
            writer.raw(owner);
            writer.close(Namespace::Dav, "owner");
        }
        let timeout = self.timeout.map_or_else(|| "Infinite".to_owned(), |seconds| format!("Second-{seconds}"));
        writer.text_element(Namespace::Dav, "timeout", &timeout);
        if let Some(token) = &self.token {
            writer.open(Namespace::Dav, "locktoken");
            writer.text_element(Namespace::Dav, "href", token);
            writer.close(Namespace::Dav, "locktoken");
        }
        writer.open(Namespace::Dav, "lockroot");
        writer.text_element(Namespace::Dav, "href", &self.root);
        writer.close(Namespace::Dav, "lockroot");
        writer.close(Namespace::Dav, "activelock");
    }
}

/// `locktype` (always `write`) and `lockscope`.
fn write_lock_kind(writer: &mut Writer, scope: LockScope) {
    writer.open(Namespace::Dav, "lockscope");
    writer.empty(Namespace::Dav, scope.name());
    writer.close(Namespace::Dav, "lockscope");
    writer.open(Namespace::Dav, "locktype");
    writer.empty(Namespace::Dav, "write");
    writer.close(Namespace::Dav, "locktype");
}

/// A property of the calendar data asked for: of a component (or any), one property (or all), with or without value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarDataProperty {
    pub component: Option<ICalendarComponentType>,
    pub name: Option<ICalendarProperty>,
    pub no_value: bool,
}

/// What a `calendar-data` element asks for (RFC 4791, 9.6): no properties listed means all of them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CalendarData {
    pub properties: Vec<CalendarDataProperty>,
    pub expand: Option<TimeRange>,
    pub limit_recurrence: Option<TimeRange>,
    pub limit_freebusy: Option<TimeRange>,
}

impl CalendarData {
    fn from_element(element: &Element) -> Result<Self, Error> {
        let mut data = Self::default();
        for child in element.elements() {
            if child.is(Namespace::CalDav, "comp") {
                comp(child, &mut data.properties)?;
            } else if child.is(Namespace::CalDav, "expand") {
                data.expand = Some(TimeRange::from_element(child)?);
            } else if child.is(Namespace::CalDav, "limit-recurrence-set") {
                data.limit_recurrence = Some(TimeRange::from_element(child)?);
            } else if child.is(Namespace::CalDav, "limit-freebusy-set") {
                data.limit_freebusy = Some(TimeRange::from_element(child)?);
            }
        }
        // Every component with all its properties is all of the data.
        if data.properties.iter().all(|property| property.name.is_none()) {
            data.properties.clear();
        }
        Ok(data)
    }
}

/// One `comp` of `calendar-data`, with those below it. A component that lists no properties has all of them.
fn comp(element: &Element, out: &mut Vec<CalendarDataProperty>) -> Result<(), Error> {
    let component = component_name(element.attr("name").ok_or(Error::Invalid("comp needs a name"))?);
    let mut listed = false;
    for child in element.elements() {
        if child.is(Namespace::CalDav, "allprop") {
            out.push(CalendarDataProperty { component: Some(component.clone()), name: None, no_value: false });
            listed = true;
        } else if child.is(Namespace::CalDav, "prop") {
            let name = child.attr("name").ok_or(Error::Invalid("prop needs a name"))?;
            out.push(CalendarDataProperty {
                component: Some(component.clone()),
                name: Some(ical_property(name)),
                no_value: child.attr("novalue").is_some_and(|value| value.trim() == "yes"),
            });
            listed = true;
        } else if child.is(Namespace::CalDav, "comp") {
            comp(child, out)?;
        }
    }
    if !listed {
        out.push(CalendarDataProperty { component: Some(component), name: None, no_value: false });
    }
    Ok(())
}

/// A property of the vCard data asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardDavPropertyName {
    pub name: VCardProperty,
    pub group: Option<String>,
    pub no_value: bool,
}

/// What an `address-data` element asks for (RFC 6352, 10.4): no properties listed means all, no version the stored one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AddressData {
    pub properties: Vec<CardDavPropertyName>,
    pub version: Option<VCardVersion>,
}

impl AddressData {
    fn from_element(element: &Element) -> Result<Self, Error> {
        let mut data = Self {
            version: element.attr("version").and_then(|v| VCardVersion::try_parse(v.trim())),
            ..Self::default()
        };
        for child in element.children_named(Namespace::CardDav, "prop") {
            let name = child.attr("name").ok_or(Error::Invalid("prop needs a name"))?;
            let (group, name) = vcard_name(name);
            data.properties.push(CardDavPropertyName {
                name,
                group,
                no_value: child.attr("novalue").is_some_and(|value| value.trim() == "yes"),
            });
        }
        Ok(data)
    }
}

/// An iCalendar component by name; unknown names are kept.
pub(crate) fn component_name(name: &str) -> ICalendarComponentType {
    ICalendarComponentType::new(name)
}

/// An iCalendar property by name; unknown names are kept.
pub(crate) fn ical_property(name: &str) -> ICalendarProperty {
    ICalendarProperty::new(name)
}

/// A vCard property by name, maybe with a group (`item1.EMAIL`).
pub(crate) fn vcard_name(name: &str) -> (Option<String>, VCardProperty) {
    let name = name.trim();
    let (group, name) = match name.rsplit_once('.') {
        Some((group, name)) => (Some(group.to_owned()), name),
        None => (None, name),
    };
    (group, VCardProperty::new(name))
}

/// A property's value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DavValue {
    /// No value: an empty element – for the names of `propname`, for properties not found, for those set.
    #[default]
    Empty,
    String(String),
    Number(u64),
    /// `creationdate` (RFC 3339), in seconds since 1970.
    CreationDate(i64),
    /// `getlastmodified` (an HTTP date), in seconds since 1970.
    HttpDate(i64),
    Hrefs(Vec<String>),
    ResourceTypes(Vec<ResourceType>),
    /// `supported-calendar-component-set`: component names.
    Components(Vec<String>),
    SupportedCalendarData,
    SupportedAddressData,
    /// `supported-collation-set`, in the property's namespace.
    Collations(Vec<Collation>),
    Reports(Vec<ReportName>),
    Privileges(Vec<Privilege>),
    SupportedPrivileges(Vec<SupportedPrivilege>),
    Acl(Vec<Ace>),
    /// `acl-restrictions`: kernoid grants only and never inverts.
    AclRestrictions,
    /// `supportedlock`: exclusive and shared write locks.
    SupportedLocks,
    Locks(Vec<ActiveLock>),
    /// `schedule-calendar-transp`: `opaque` or (false) `transparent`.
    Opaque(bool),
    /// Text of another format – calendar or address data, a time zone – escaped as text.
    Data(String),
    /// XML as a client set it ([`Element::inner_xml`]): dead properties.
    Xml(String),
}

impl From<String> for DavValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for DavValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<u64> for DavValue {
    fn from(value: u64) -> Self {
        Self::Number(value)
    }
}

impl DavValue {
    pub fn href(href: impl Into<String>) -> Self {
        Self::Hrefs(vec![href.into()])
    }
}

/// A property with its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DavPropertyValue {
    pub property: DavProperty,
    pub value: DavValue,
}

impl DavPropertyValue {
    pub fn new(property: impl Into<DavProperty>, value: impl Into<DavValue>) -> Self {
        Self { property: property.into(), value: value.into() }
    }

    pub fn empty(property: impl Into<DavProperty>) -> Self {
        Self { property: property.into(), value: DavValue::Empty }
    }

    /// A property a client sets (`PROPPATCH`, `MKCOL`, `MKCALENDAR`): what kernoid knows by its kind of value, the
    /// rest as XML.
    pub fn from_element(element: &Element) -> Result<Self, Error> {
        let property = DavProperty::from_element(element)?;
        let value = match &property {
            DavProperty::WebDav(WebDavProperty::ResourceType) => {
                DavValue::ResourceTypes(element.elements().filter_map(ResourceType::from_element).collect())
            }
            DavProperty::CalDav(CalDavProperty::Named(CalDavName::SupportedCalendarComponentSet)) => {
                DavValue::Components(
                    element
                        .children_named(Namespace::CalDav, "comp")
                        .filter_map(|comp| comp.attr("name"))
                        .map(|name| name.trim().to_ascii_uppercase())
                        .collect(),
                )
            }
            DavProperty::CalDav(CalDavProperty::Named(CalDavName::CalendarTimezone)) => DavValue::Data(element.text()),
            DavProperty::CalDav(CalDavProperty::Named(CalDavName::ScheduleCalendarTransp)) => {
                DavValue::Opaque(element.child(Namespace::CalDav, "transparent").is_none())
            }
            DavProperty::Dead(_) => DavValue::Xml(element.inner_xml()),
            _ => DavValue::String(element.text()),
        };
        Ok(Self { property, value })
    }

    pub(crate) fn write(&self, writer: &mut Writer) {
        let (ns, name) = self.property.qualified_name();
        let Some(known) = Namespace::from_uri(ns).filter(|_| !matches!(self.property, DavProperty::Dead(_))) else {
            let inner = match &self.value {
                DavValue::Xml(xml) => xml.clone(),
                DavValue::String(text) | DavValue::Data(text) => escape(text.as_str()).into_owned(),
                DavValue::Number(number) => number.to_string(),
                _ => String::new(),
            };
            writer.foreign(ns, name, Some(&inner));
            return;
        };
        if self.value == DavValue::Empty {
            writer.empty(known, name);
            return;
        }
        writer.open(known, name);
        write_value(writer, known, &self.value);
        writer.close(known, name);
    }
}

fn write_value(writer: &mut Writer, ns: Namespace, value: &DavValue) {
    match value {
        DavValue::Empty => {}
        DavValue::String(text) | DavValue::Data(text) => writer.text(text),
        DavValue::Number(number) => writer.text(&number.to_string()),
        DavValue::CreationDate(seconds) => {
            let date = jiff::Timestamp::from_second(*seconds).unwrap_or(jiff::Timestamp::UNIX_EPOCH);
            writer.text(&date.strftime("%Y-%m-%dT%H:%M:%SZ").to_string());
        }
        DavValue::HttpDate(seconds) => {
            let date = jiff::Timestamp::from_second(*seconds).unwrap_or(jiff::Timestamp::UNIX_EPOCH);
            let text =
                jiff::fmt::rfc2822::DateTimePrinter::new().timestamp_to_rfc9110_string(&date).unwrap_or_default();
            writer.text(&text);
        }
        DavValue::Hrefs(hrefs) => {
            for href in hrefs {
                writer.text_element(Namespace::Dav, "href", href);
            }
        }
        DavValue::ResourceTypes(types) => {
            for kind in types {
                let (ns, name) = kind.qualified_name();
                writer.empty(ns, name);
            }
        }
        DavValue::Components(names) => {
            for name in names {
                writer.start_tag(Namespace::CalDav, "comp").attr("name", name).end_empty();
            }
        }
        DavValue::SupportedCalendarData => {
            writer
                .start_tag(Namespace::CalDav, "calendar-data")
                .attr("content-type", "text/calendar")
                .attr("version", "2.0")
                .end_empty();
        }
        DavValue::SupportedAddressData => {
            for version in ["3.0", "4.0"] {
                writer
                    .start_tag(Namespace::CardDav, "address-data-type")
                    .attr("content-type", "text/vcard")
                    .attr("version", version)
                    .end_empty();
            }
        }
        DavValue::Collations(collations) => {
            for collation in collations {
                writer.text_element(ns, "supported-collation", collation.as_str());
            }
        }
        DavValue::Reports(reports) => {
            for report in reports {
                let (ns, name) = report.qualified_name();
                writer.open(Namespace::Dav, "supported-report");
                writer.open(Namespace::Dav, "report");
                writer.empty(ns, name);
                writer.close(Namespace::Dav, "report");
                writer.close(Namespace::Dav, "supported-report");
            }
        }
        DavValue::Privileges(privileges) => {
            for privilege in privileges {
                privilege.write(writer);
            }
        }
        DavValue::SupportedPrivileges(privileges) => {
            for privilege in privileges {
                privilege.write(writer);
            }
        }
        DavValue::Acl(aces) => {
            for ace in aces {
                writer.open(Namespace::Dav, "ace");
                writer.open(Namespace::Dav, "principal");
                writer.text_element(Namespace::Dav, "href", &ace.principal);
                writer.close(Namespace::Dav, "principal");
                writer.open(Namespace::Dav, "grant");
                for privilege in &ace.grant {
                    privilege.write(writer);
                }
                writer.close(Namespace::Dav, "grant");
                if ace.protected {
                    writer.empty(Namespace::Dav, "protected");
                }
                writer.close(Namespace::Dav, "ace");
            }
        }
        DavValue::AclRestrictions => {
            writer.empty(Namespace::Dav, "grant-only");
            writer.empty(Namespace::Dav, "no-invert");
        }
        DavValue::SupportedLocks => {
            for scope in [LockScope::Exclusive, LockScope::Shared] {
                writer.open(Namespace::Dav, "lockentry");
                write_lock_kind(writer, scope);
                writer.close(Namespace::Dav, "lockentry");
            }
        }
        DavValue::Locks(locks) => {
            for lock in locks {
                lock.write(writer);
            }
        }
        DavValue::Opaque(opaque) => writer.empty(Namespace::CalDav, if *opaque { "opaque" } else { "transparent" }),
        DavValue::Xml(xml) => writer.raw(xml),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::xml::parse;

    fn written(value: DavPropertyValue) -> String {
        let mut writer = Writer::new();
        writer.open(Namespace::Dav, "prop");
        value.write(&mut writer);
        writer.close(Namespace::Dav, "prop");
        let out = writer.finish();
        parse(out.as_bytes()).expect("well-formed");
        out.split_once("<D:prop")
            .and_then(|(_, rest)| rest.split_once('>'))
            .map(|(_, rest)| rest.trim_end_matches("</D:prop>").to_owned())
            .unwrap()
    }

    #[test]
    fn names_of_known_and_dead_properties() {
        let root = parse(
            br#"<D:prop xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:CS="http://calendarserver.org/ns/"
                xmlns:A="http://apple.com/ns/ical/"><D:principal-URL/><C:schedule-inbox-URL/><CS:getctag/>
                <A:calendar-color/><D:nonsense/><plain/></D:prop>"#,
        )
        .unwrap();
        let props: Vec<_> = root.elements().map(|element| DavProperty::from_element(element).unwrap()).collect();
        assert_eq!(props[0], DavProperty::WebDav(WebDavProperty::PrincipalUrl));
        assert_eq!(props[1], CalDavName::ScheduleInboxUrl.into());
        assert_eq!(props[2], DavProperty::GetCTag);
        assert!(props[3].is("http://apple.com/ns/ical/", "calendar-color"));
        assert!(props[4].is("DAV:", "nonsense"));
        assert!(props[5].is("", "plain"));
    }

    #[test]
    fn calendar_and_address_data_requests() {
        let element = parse(
            br#"<C:calendar-data xmlns:C="urn:ietf:params:xml:ns:caldav"><C:comp name="VCALENDAR"><C:allprop/>
                <C:comp name="VEVENT"><C:prop name="SUMMARY"/><C:prop name="dtstart" novalue="yes"/></C:comp></C:comp>
                <C:expand start="20261201T000000Z" end="20261215T000000Z"/></C:calendar-data>"#,
        )
        .unwrap();
        let DavProperty::CalDav(CalDavProperty::CalendarData(data)) = DavProperty::from_element(&element).unwrap()
        else {
            panic!()
        };
        assert_eq!(data.expand.unwrap().start, 1_796_083_200);
        assert_eq!(data.properties.len(), 3);
        assert_eq!(data.properties[2].name, Some(ICalendarProperty::new("DTSTART")));
        assert!(data.properties[2].no_value);
        assert_eq!(data.properties[1].component, Some(ICalendarComponentType::new("VEVENT")));

        let all = parse(br#"<C:calendar-data xmlns:C="urn:ietf:params:xml:ns:caldav"><C:comp name="VCALENDAR"><C:allprop/><C:comp name="VEVENT"><C:allprop/></C:comp></C:comp></C:calendar-data>"#).unwrap();
        let DavProperty::CalDav(CalDavProperty::CalendarData(data)) = DavProperty::from_element(&all).unwrap() else {
            panic!()
        };
        assert!(data.properties.is_empty());

        let element = parse(
            br#"<C:address-data xmlns:C="urn:ietf:params:xml:ns:carddav" version="3.0"><C:prop name="FN"/><C:prop name="item1.EMAIL" novalue="yes"/></C:address-data>"#,
        )
        .unwrap();
        let DavProperty::CardDav(CardDavProperty::AddressData(data)) = DavProperty::from_element(&element).unwrap()
        else {
            panic!()
        };
        assert_eq!(data.version, Some(VCardVersion::V3_0));
        assert_eq!(data.properties[0].name, VCardProperty::new("FN"));
        assert_eq!(
            data.properties[1],
            CardDavPropertyName { name: VCardProperty::new("EMAIL"), group: Some("item1".into()), no_value: true }
        );
    }

    #[test]
    fn values_clients_set() {
        let root = parse(
            br#"<D:prop xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:x="urn:x"><D:resourcetype><D:collection/><C:calendar/><x:other/></D:resourcetype>
                <C:supported-calendar-component-set><C:comp name="vevent"/><C:comp name="VTODO"/></C:supported-calendar-component-set>
                <D:displayname>Work &amp; more</D:displayname><x:thing><x:a>1</x:a></x:thing></D:prop>"#,
        )
        .unwrap();
        let values: Vec<_> = root.elements().map(|element| DavPropertyValue::from_element(element).unwrap()).collect();
        assert_eq!(values[0].value, DavValue::ResourceTypes(vec![ResourceType::Collection, ResourceType::Calendar]));
        assert_eq!(values[1].value, DavValue::Components(vec!["VEVENT".into(), "VTODO".into()]));
        assert_eq!(values[2].value, DavValue::String("Work & more".into()));
        assert_eq!(values[3].value, DavValue::Xml(r#"<a xmlns="urn:x">1</a>"#.into()));
    }

    #[test]
    fn values_are_written() {
        assert_eq!(
            written(DavPropertyValue::new(
                WebDavProperty::ResourceType,
                DavValue::ResourceTypes(vec![ResourceType::Collection, ResourceType::Calendar])
            )),
            "<D:resourcetype><D:collection/><C:calendar/></D:resourcetype>"
        );
        assert_eq!(written(DavPropertyValue::empty(WebDavProperty::GetETag)), "<D:getetag/>");
        assert_eq!(
            written(DavPropertyValue::new(WebDavProperty::GetLastModified, DavValue::HttpDate(1_796_083_200))),
            "<D:getlastmodified>Tue, 01 Dec 2026 00:00:00 GMT</D:getlastmodified>"
        );
        assert_eq!(
            written(DavPropertyValue::new(WebDavProperty::CreationDate, DavValue::CreationDate(1_796_083_200))),
            "<D:creationdate>2026-12-01T00:00:00Z</D:creationdate>"
        );
        assert_eq!(
            written(DavPropertyValue::new(
                CalDavName::SupportedCollationSet,
                DavValue::Collations(vec![Collation::AsciiCasemap])
            )),
            "<C:supported-collation-set><C:supported-collation>i;ascii-casemap</C:supported-collation></C:supported-collation-set>"
        );
        assert_eq!(
            written(DavPropertyValue::new(
                WebDavProperty::CurrentUserPrivilegeSet,
                DavValue::Privileges(vec![Privilege::Read, Privilege::ReadFreeBusy])
            )),
            "<D:current-user-privilege-set><D:privilege><D:read/></D:privilege><D:privilege><C:read-free-busy/></D:privilege></D:current-user-privilege-set>"
        );
        assert_eq!(
            written(DavPropertyValue::new(
                WebDavProperty::SupportedReportSet,
                DavValue::Reports(vec![ReportName::SyncCollection])
            )),
            "<D:supported-report-set><D:supported-report><D:report><D:sync-collection/></D:report></D:supported-report></D:supported-report-set>"
        );
        let dead = DavProperty::Dead(PropertyName { ns: "urn:x".into(), name: "thing".into() });
        assert_eq!(
            written(DavPropertyValue::new(dead.clone(), DavValue::Xml("<a xmlns=\"urn:x\">1</a>".into()))),
            "<x:thing xmlns:x=\"urn:x\"><a xmlns=\"urn:x\">1</a></x:thing>"
        );
        assert_eq!(written(DavPropertyValue::empty(dead)), "<x:thing xmlns:x=\"urn:x\"/>");
        let lock = ActiveLock {
            root: "/webdav/a".into(),
            scope: LockScope::Exclusive,
            depth: Depth::Zero,
            timeout: Some(60),
            owner: Some("<D:href xmlns:D=\"DAV:\">me</D:href>".into()),
            token: Some("opaquelocktoken:1".into()),
        };
        assert_eq!(
            written(DavPropertyValue::new(WebDavProperty::LockDiscovery, DavValue::Locks(vec![lock]))),
            "<D:lockdiscovery><D:activelock><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype>\
             <D:depth>0</D:depth><D:owner><D:href xmlns:D=\"DAV:\">me</D:href></D:owner><D:timeout>Second-60</D:timeout>\
             <D:locktoken><D:href>opaquelocktoken:1</D:href></D:locktoken><D:lockroot><D:href>/webdav/a</D:href></D:lockroot>\
             </D:activelock></D:lockdiscovery>"
        );
    }
}
