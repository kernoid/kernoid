// SPDX-License-Identifier: AGPL-3.0-or-later
//! Request bodies: `PROPFIND` (RFC 4918, 9.1), `PROPPATCH` (9.2), extended `MKCOL` (RFC 5689) and `MKCALENDAR` (RFC
//! 4791, 5.3.1), `LOCK` (RFC 4918, 9.10) and the reports – CalDAV's (RFC 4791, 7), CardDAV's (RFC 6352, 8),
//! `sync-collection` (RFC 6578), `expand-property` (RFC 3253, 3.8) and the principal reports (RFC 3744, 9).
//!
//! Elements a request does not need are skipped, so that extensions do not fail it; a missing element it needs, or a
//! value that cannot be read, does.

use super::{
    Namespace, TextMatch,
    property::{DavProperty, DavPropertyValue, LockScope, component_name, ical_property, vcard_name},
};
use crate::proto::{
    Error,
    names::{ICalendarComponentType, ICalendarParameterName, ICalendarProperty, VCardParameterName, VCardProperty},
    types::TimeRange,
    xml::{self, Element},
};

/// Reads a body whose root must be `name` in `ns`.
fn root(body: &[u8], ns: Namespace, name: &'static str) -> Result<Element, Error> {
    let root = xml::parse(body)?;
    match root.is(ns, name) {
        true => Ok(root),
        false => Err(Error::Invalid(name)),
    }
}

/// The properties a `prop` element names.
fn prop_names(prop: &Element) -> Result<Vec<DavProperty>, Error> {
    prop.elements().map(DavProperty::from_element).collect()
}

/// The values a `prop` element holds.
fn prop_values(prop: &Element) -> Result<Vec<DavPropertyValue>, Error> {
    prop.elements().map(DavPropertyValue::from_element).collect()
}

/// What a `PROPFIND` – or a report – asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropFind {
    /// The names of all properties.
    PropName,
    /// All properties, with those of `include` that `allprop` leaves out.
    AllProp(Vec<DavProperty>),
    /// The properties listed.
    Prop(Vec<DavProperty>),
}

impl PropFind {
    /// A `PROPFIND` body; an empty body asks for all properties (RFC 4918, 9.1).
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        if body.iter().all(u8::is_ascii_whitespace) {
            return Ok(Self::AllProp(Vec::new()));
        }
        let root = root(body, Namespace::Dav, "propfind")?;
        Ok(Self::from_children(&root)?.unwrap_or(Self::AllProp(Vec::new())))
    }

    /// The `prop`, `allprop` (with `include`) or `propname` among an element's children.
    fn from_children(element: &Element) -> Result<Option<Self>, Error> {
        if let Some(prop) = element.child(Namespace::Dav, "prop") {
            return Ok(Some(Self::Prop(prop_names(prop)?)));
        }
        if element.child(Namespace::Dav, "propname").is_some() {
            return Ok(Some(Self::PropName));
        }
        if element.child(Namespace::Dav, "allprop").is_some() {
            let include = match element.child(Namespace::Dav, "include") {
                Some(include) => prop_names(include)?,
                None => Vec::new(),
            };
            return Ok(Some(Self::AllProp(include)));
        }
        Ok(None)
    }

    /// What a report asks for; without any of the three, only the hrefs (an empty list).
    fn in_report(element: &Element) -> Result<Self, Error> {
        Ok(Self::from_children(element)?.unwrap_or(Self::Prop(Vec::new())))
    }

    /// The properties named, if any.
    pub fn properties(&self) -> &[DavProperty] {
        match self {
            Self::PropName => &[],
            Self::AllProp(properties) | Self::Prop(properties) => properties,
        }
    }
}

/// A `PROPPATCH`: properties to set and to remove, each in the order sent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PropertyUpdate {
    pub set: Vec<DavPropertyValue>,
    pub remove: Vec<DavProperty>,
}

impl PropertyUpdate {
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let root = root(body, Namespace::Dav, "propertyupdate")?;
        let mut update = Self::default();
        for instruction in root.elements() {
            let Some(prop) = instruction.child(Namespace::Dav, "prop") else { continue };
            if instruction.is(Namespace::Dav, "set") {
                update.set.extend(prop_values(prop)?);
            } else if instruction.is(Namespace::Dav, "remove") {
                update.remove.extend(prop_names(prop)?);
            }
        }
        Ok(update)
    }
}

/// An extended `MKCOL` or a `MKCALENDAR`: the properties the new collection gets.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MkCol {
    pub props: Vec<DavPropertyValue>,
}

impl MkCol {
    /// A body of `mkcol` (RFC 5689) or `mkcalendar` (RFC 4791).
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let root = xml::parse(body)?;
        if !root.is(Namespace::Dav, "mkcol") && !root.is(Namespace::CalDav, "mkcalendar") {
            return Err(Error::Invalid("mkcol"));
        }
        let mut mkcol = Self::default();
        for set in root.children_named(Namespace::Dav, "set") {
            for prop in set.children_named(Namespace::Dav, "prop") {
                mkcol.props.extend(prop_values(prop)?);
            }
        }
        Ok(mkcol)
    }
}

/// A `LOCK` asking for a new lock.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LockInfo {
    pub scope: LockScope,
    /// The `owner` element's content, as XML.
    pub owner: Option<String>,
}

impl LockInfo {
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let root = root(body, Namespace::Dav, "lockinfo")?;
        let scope = root.child(Namespace::Dav, "lockscope").ok_or(Error::Invalid("lockscope"))?;
        let scope = if scope.child(Namespace::Dav, "shared").is_some() {
            LockScope::Shared
        } else if scope.child(Namespace::Dav, "exclusive").is_some() {
            LockScope::Exclusive
        } else {
            return Err(Error::Invalid("lockscope"));
        };
        let write = root.child(Namespace::Dav, "locktype").and_then(|kind| kind.child(Namespace::Dav, "write"));
        if write.is_none() {
            return Err(Error::Invalid("locktype"));
        }
        let owner = root.child(Namespace::Dav, "owner").map(Element::inner_xml);
        Ok(Self { scope, owner })
    }
}

/// How a filter tests (RFC 4791, 9.7; RFC 6352, 10.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterOp {
    /// Present (a filter with nothing more).
    Exists,
    /// `is-not-defined`.
    Undefined,
    TextMatch(TextMatch),
    TimeRange(TimeRange),
}

/// One test of a query's filter, flattened: every filter element is one item, with the components (`C`) it is nested
/// in, its property (`P`) and parameter (`R`). `AnyOf` and `AllOf` say how the items after them combine (the filter's
/// `test`; CalDAV's filters are all of).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter<C, P, R> {
    AnyOf,
    AllOf,
    Component { comp: C, op: FilterOp },
    Property { comp: C, prop: P, op: FilterOp },
    Parameter { comp: C, prop: P, param: R, op: FilterOp },
}

/// A vCard property in a filter, maybe with a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VCardPropertyWithGroup {
    pub name: VCardProperty,
    pub group: Option<String>,
}

/// The time zone of a `calendar-query`: `timezone` (the text of a `VCALENDAR` with its `VTIMEZONE`) or `timezone-id`
/// (RFC 7809).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Timezone {
    Name(String),
    Id(String),
    #[default]
    None,
}

/// What a filter element tests: `is-not-defined`, a `time-range`, its `text-match`es, or that it is there.
fn ops(element: &Element, ns: Namespace) -> Result<Vec<FilterOp>, Error> {
    if element.child(ns, "is-not-defined").is_some() {
        return Ok(vec![FilterOp::Undefined]);
    }
    if let Some(range) = element.child(ns, "time-range") {
        return Ok(vec![FilterOp::TimeRange(TimeRange::from_element(range)?)]);
    }
    element
        .children_named(ns, "text-match")
        .map(|text| TextMatch::from_element(text).map(FilterOp::TextMatch))
        .collect()
}

type CalendarFilter = Filter<Vec<ICalendarComponentType>, ICalendarProperty, ICalendarParameterName>;
type AddressbookFilter = Filter<(), VCardPropertyWithGroup, VCardParameterName>;

/// A `comp-filter` and everything in it.
fn comp_filter(
    element: &Element,
    path: &mut Vec<ICalendarComponentType>,
    out: &mut Vec<CalendarFilter>,
) -> Result<(), Error> {
    path.push(component_name(element.attr("name").ok_or(Error::Invalid("comp-filter needs a name"))?));
    let op = ops(element, Namespace::CalDav)?.pop().unwrap_or(FilterOp::Exists);
    let undefined = op == FilterOp::Undefined;
    out.push(Filter::Component { comp: path.clone(), op });
    if !undefined {
        for child in element.elements() {
            if child.is(Namespace::CalDav, "comp-filter") {
                comp_filter(child, path, out)?;
            } else if child.is(Namespace::CalDav, "prop-filter") {
                let prop = ical_property(child.attr("name").ok_or(Error::Invalid("prop-filter needs a name"))?);
                let ops = ops(child, Namespace::CalDav)?;
                let params: Vec<_> = child.children_named(Namespace::CalDav, "param-filter").collect();
                if ops.is_empty() && params.is_empty() {
                    out.push(Filter::Property { comp: path.clone(), prop: prop.clone(), op: FilterOp::Exists });
                }
                for op in ops {
                    out.push(Filter::Property { comp: path.clone(), prop: prop.clone(), op });
                }
                for param in params {
                    let name = param.attr("name").ok_or(Error::Invalid("param-filter needs a name"))?;
                    let param_name = ICalendarParameterName::new(name);
                    let op = ops_of_param(param, Namespace::CalDav)?;
                    out.push(Filter::Parameter { comp: path.clone(), prop: prop.clone(), param: param_name, op });
                }
            }
        }
    }
    path.pop();
    Ok(())
}

fn ops_of_param(element: &Element, ns: Namespace) -> Result<FilterOp, Error> {
    Ok(ops(element, ns)?.into_iter().next().unwrap_or(FilterOp::Exists))
}

fn calendar_filters(filter: Option<&Element>) -> Result<Vec<CalendarFilter>, Error> {
    let mut out = Vec::new();
    if let Some(filter) = filter {
        for comp in filter.children_named(Namespace::CalDav, "comp-filter") {
            comp_filter(comp, &mut Vec::new(), &mut out)?;
        }
    }
    Ok(out)
}

fn addressbook_filters(filter: Option<&Element>) -> Result<Vec<AddressbookFilter>, Error> {
    let mut out = Vec::new();
    let Some(filter) = filter else { return Ok(out) };
    let props: Vec<_> = filter.children_named(Namespace::CardDav, "prop-filter").collect();
    if props.is_empty() {
        return Ok(out);
    }
    out.push(match filter.attr("test").map(str::trim) {
        Some("allof") => Filter::AllOf,
        _ => Filter::AnyOf,
    });
    for prop in props {
        let (group, name) = vcard_name(prop.attr("name").ok_or(Error::Invalid("prop-filter needs a name"))?);
        let prop_name = VCardPropertyWithGroup { name, group };
        // Each prop-filter's own test (RFC 6352, 10.5.1), before its conditions.
        out.push(match prop.attr("test").map(str::trim) {
            Some("allof") => Filter::AllOf,
            _ => Filter::AnyOf,
        });
        let ops = ops(prop, Namespace::CardDav)?;
        let params: Vec<_> = prop.children_named(Namespace::CardDav, "param-filter").collect();
        if ops.is_empty() && params.is_empty() {
            out.push(Filter::Property { comp: (), prop: prop_name.clone(), op: FilterOp::Exists });
        }
        for op in ops {
            out.push(Filter::Property { comp: (), prop: prop_name.clone(), op });
        }
        for param in params {
            let name = param.attr("name").ok_or(Error::Invalid("param-filter needs a name"))?;
            let param_name = VCardParameterName::new(name);
            let op = ops_of_param(param, Namespace::CardDav)?;
            out.push(Filter::Parameter { comp: (), prop: prop_name.clone(), param: param_name, op });
        }
    }
    Ok(out)
}

/// A `calendar-query` (RFC 4791, 7.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarQuery {
    pub properties: PropFind,
    pub filters: Vec<CalendarFilter>,
    pub timezone: Timezone,
}

/// An `addressbook-query` (RFC 6352, 8.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressbookQuery {
    pub properties: PropFind,
    pub filters: Vec<AddressbookFilter>,
    /// `limit`/`nresults`.
    pub limit: Option<u32>,
}

/// A `calendar-multiget` or `addressbook-multiget` (RFC 4791, 7.9; RFC 6352, 8.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiGet {
    pub properties: PropFind,
    pub hrefs: Vec<String>,
}

/// A `sync-collection` (RFC 6578, 3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCollection {
    /// Empty or absent for the first sync.
    pub sync_token: Option<String>,
    /// `sync-level` `infinite` (else `1`).
    pub infinite: bool,
    pub limit: Option<u32>,
    pub properties: PropFind,
}

/// A `principal-property-search` (RFC 3744, 9.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalPropertySearch {
    /// Each `property-search`: the properties to search and the text.
    pub searches: Vec<(Vec<DavProperty>, String)>,
    /// `test="anyof"`.
    pub any_of: bool,
    pub properties: Vec<DavProperty>,
}

/// A report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Report {
    CalendarQuery(CalendarQuery),
    CalendarMultiGet(MultiGet),
    FreeBusyQuery {
        range: Option<TimeRange>,
    },
    AddressbookQuery(AddressbookQuery),
    AddressbookMultiGet(MultiGet),
    SyncCollection(SyncCollection),
    /// `expand-property`: the properties of the first level (RFC 3253, 3.8).
    ExpandProperty {
        properties: Vec<DavProperty>,
    },
    PrincipalPropertySearch(PrincipalPropertySearch),
    PrincipalMatch {
        properties: Vec<DavProperty>,
    },
    AclPrincipalPropSet {
        properties: Vec<DavProperty>,
    },
    PrincipalSearchPropertySet,
}

fn limit(element: &Element, ns: Namespace) -> Result<Option<u32>, Error> {
    element
        .child(ns, "limit")
        .and_then(|limit| limit.child(ns, "nresults"))
        .map(|count| count.text().trim().parse().map_err(|_| Error::Invalid("nresults")))
        .transpose()
}

fn named_properties(element: &Element) -> Result<Vec<DavProperty>, Error> {
    Ok(match element.child(Namespace::Dav, "prop") {
        Some(prop) => prop_names(prop)?,
        None => Vec::new(),
    })
}

impl Report {
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let root = xml::parse(body)?;
        let hrefs = |root: &Element| {
            root.children_named(Namespace::Dav, "href").map(|href| href.text().trim().to_owned()).collect()
        };
        Ok(match (Namespace::from_uri(&root.ns), root.name.as_str()) {
            (Some(Namespace::CalDav), "calendar-query") => {
                let timezone = if let Some(id) = root.child(Namespace::CalDav, "timezone-id") {
                    Timezone::Id(id.text().trim().to_owned())
                } else if let Some(text) = root
                    .child(Namespace::CalDav, "timezone")
                    .map(|zone| zone.text())
                    .filter(|text| !text.trim().is_empty())
                {
                    Timezone::Name(text)
                } else {
                    Timezone::None
                };
                Self::CalendarQuery(CalendarQuery {
                    properties: PropFind::in_report(&root)?,
                    filters: calendar_filters(root.child(Namespace::CalDav, "filter"))?,
                    timezone,
                })
            }
            (Some(Namespace::CalDav), "calendar-multiget") => {
                Self::CalendarMultiGet(MultiGet { properties: PropFind::in_report(&root)?, hrefs: hrefs(&root) })
            }
            (Some(Namespace::CalDav), "free-busy-query") => Self::FreeBusyQuery {
                range: root.child(Namespace::CalDav, "time-range").map(TimeRange::from_element).transpose()?,
            },
            (Some(Namespace::CardDav), "addressbook-query") => Self::AddressbookQuery(AddressbookQuery {
                properties: PropFind::in_report(&root)?,
                filters: addressbook_filters(root.child(Namespace::CardDav, "filter"))?,
                limit: limit(&root, Namespace::CardDav)?,
            }),
            (Some(Namespace::CardDav), "addressbook-multiget") => {
                Self::AddressbookMultiGet(MultiGet { properties: PropFind::in_report(&root)?, hrefs: hrefs(&root) })
            }
            (Some(Namespace::Dav), "sync-collection") => Self::SyncCollection(SyncCollection {
                sync_token: root
                    .child(Namespace::Dav, "sync-token")
                    .map(|token| token.text().trim().to_owned())
                    .filter(|token| !token.is_empty()),
                infinite: root
                    .child(Namespace::Dav, "sync-level")
                    .is_some_and(|level| level.text().trim().eq_ignore_ascii_case("infinite")),
                limit: limit(&root, Namespace::Dav)?,
                properties: PropFind::in_report(&root)?,
            }),
            (Some(Namespace::Dav), "expand-property") => Self::ExpandProperty {
                properties: root
                    .children_named(Namespace::Dav, "property")
                    .map(|property| {
                        let name = property.attr("name").ok_or(Error::Invalid("property needs a name"))?;
                        let ns = property.attr("namespace").unwrap_or("DAV:");
                        DavProperty::from_element(&Element {
                            ns: ns.to_owned(),
                            name: name.to_owned(),
                            ..Element::default()
                        })
                    })
                    .collect::<Result<_, _>>()?,
            },
            (Some(Namespace::Dav), "principal-property-search") => {
                let searches = root
                    .children_named(Namespace::Dav, "property-search")
                    .map(|search| {
                        Ok((
                            named_properties(search)?,
                            search.child(Namespace::Dav, "match").map(Element::text).unwrap_or_default(),
                        ))
                    })
                    .collect::<Result<_, Error>>()?;
                Self::PrincipalPropertySearch(PrincipalPropertySearch {
                    searches,
                    any_of: root.attr("test").is_some_and(|test| test.trim() == "anyof"),
                    properties: named_properties(&root)?,
                })
            }
            (Some(Namespace::Dav), "principal-match") => Self::PrincipalMatch { properties: named_properties(&root)? },
            (Some(Namespace::Dav), "acl-principal-prop-set") => {
                Self::AclPrincipalPropSet { properties: named_properties(&root)? }
            }
            (Some(Namespace::Dav), "principal-search-property-set") => Self::PrincipalSearchPropertySet,
            _ => return Err(Error::UnsupportedReport),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::schema::{
        Collation, MatchType,
        property::{CalDavName, CalDavProperty, DavValue, WebDavProperty},
    };

    #[test]
    fn propfind_bodies() {
        assert_eq!(PropFind::parse(b"").unwrap(), PropFind::AllProp(vec![]));
        assert_eq!(PropFind::parse(b"  \r\n").unwrap(), PropFind::AllProp(vec![]));
        assert_eq!(PropFind::parse(br#"<propfind xmlns="DAV:"><propname/></propfind>"#).unwrap(), PropFind::PropName);
        assert_eq!(
            PropFind::parse(br#"<propfind xmlns="DAV:"><allprop/><include><sync-token/></include></propfind>"#)
                .unwrap(),
            PropFind::AllProp(vec![WebDavProperty::SyncToken.into()])
        );
        // As macOS Finder sends it.
        let finder = br#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
<D:prop>
<D:getlastmodified/>
<D:getcontentlength/>
<D:creationdate/>
<D:resourcetype/>
</D:prop>
</D:propfind>"#;
        let PropFind::Prop(props) = PropFind::parse(finder).unwrap() else { panic!() };
        assert_eq!(props.len(), 4);
        assert_eq!(props[3], WebDavProperty::ResourceType.into());
        // Windows sends properties of its own namespace.
        let windows = br#"<?xml version="1.0" encoding="utf-8" ?><D:propfind xmlns:D="DAV:"><D:prop xmlns:Z="urn:schemas-microsoft-com:"><Z:Win32FileAttributes/><D:getetag/></D:prop></D:propfind>"#;
        let PropFind::Prop(props) = PropFind::parse(windows).unwrap() else { panic!() };
        assert!(props[0].is("urn:schemas-microsoft-com:", "Win32FileAttributes"));
        assert!(PropFind::parse(br#"<propertyupdate xmlns="DAV:"/>"#).is_err());
        assert!(PropFind::parse(b"<propfind").is_err());
    }

    #[test]
    fn proppatch_mkcol_and_lock_bodies() {
        let update = PropertyUpdate::parse(
            br#"<D:propertyupdate xmlns:D="DAV:" xmlns:A="http://apple.com/ns/ical/"><D:set><D:prop><D:displayname>Home</D:displayname>
                <A:calendar-color>#FF0000FF</A:calendar-color></D:prop></D:set><D:remove><D:prop><A:calendar-order/></D:prop></D:remove></D:propertyupdate>"#,
        )
        .unwrap();
        assert_eq!(update.set[0].value, DavValue::String("Home".into()));
        assert_eq!(update.set[1].value, DavValue::Xml("#FF0000FF".into()));
        assert!(update.remove[0].is("http://apple.com/ns/ical/", "calendar-order"));

        let mkcol = MkCol::parse(
            br#"<C:mkcalendar xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:set><D:prop>
                <C:calendar-timezone>BEGIN:VCALENDAR&#13;
END:VCALENDAR</C:calendar-timezone><C:calendar-description>d</C:calendar-description></D:prop></D:set></C:mkcalendar>"#,
        )
        .unwrap();
        assert_eq!(mkcol.props[0].value, DavValue::Data("BEGIN:VCALENDAR\r\nEND:VCALENDAR".into()));
        assert_eq!(mkcol.props[1].property, CalDavName::CalendarDescription.into());
        assert!(MkCol::parse(br#"<D:mkcol xmlns:D="DAV:"><D:set><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:set></D:mkcol>"#).is_ok());
        assert!(MkCol::parse(br#"<D:propfind xmlns:D="DAV:"/>"#).is_err());

        let lock = LockInfo::parse(
            br#"<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:shared/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner><D:href>http://example.org/~me</D:href></D:owner></D:lockinfo>"#,
        )
        .unwrap();
        assert_eq!(lock.scope, LockScope::Shared);
        assert_eq!(lock.owner.as_deref(), Some(r#"<href xmlns="DAV:">http://example.org/~me</href>"#));
        assert!(
            LockInfo::parse(br#"<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope></D:lockinfo>"#)
                .is_err()
        );
    }

    #[test]
    fn calendar_queries() {
        let report = Report::parse(
            br#"<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
              <D:prop><D:getetag/><C:calendar-data/></D:prop>
              <C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT">
                <C:time-range start="20261201T000000Z" end="20261215T000000Z"/>
                <C:prop-filter name="SUMMARY"><C:text-match negate-condition="yes">x</C:text-match></C:prop-filter>
                <C:prop-filter name="ATTENDEE"><C:param-filter name="PARTSTAT"><C:text-match>NEEDS-ACTION</C:text-match></C:param-filter></C:prop-filter>
                <C:prop-filter name="DESCRIPTION"><C:is-not-defined/></C:prop-filter>
              </C:comp-filter><C:comp-filter name="VTODO"><C:is-not-defined/></C:comp-filter></C:comp-filter></C:filter>
              <C:timezone>BEGIN:VCALENDAR
BEGIN:VTIMEZONE
TZID:Europe/Berlin
END:VTIMEZONE
END:VCALENDAR</C:timezone>
            </C:calendar-query>"#,
        )
        .unwrap();
        let Report::CalendarQuery(query) = report else { panic!() };
        assert!(
            matches!(&query.timezone, Timezone::Name(text) if text.contains("TZID:Europe/Berlin")),
            "{:?}",
            query.timezone
        );
        let PropFind::Prop(props) = &query.properties else { panic!() };
        assert!(matches!(props[1], DavProperty::CalDav(CalDavProperty::CalendarData(_))));
        let event = vec![ICalendarComponentType::new("VCALENDAR"), ICalendarComponentType::new("VEVENT")];
        assert_eq!(
            query.filters,
            vec![
                Filter::Component { comp: vec![ICalendarComponentType::new("VCALENDAR")], op: FilterOp::Exists },
                Filter::Component {
                    comp: event.clone(),
                    op: FilterOp::TimeRange(TimeRange::new(1_796_083_200, 1_797_292_800))
                },
                Filter::Property {
                    comp: event.clone(),
                    prop: ICalendarProperty::new("SUMMARY"),
                    op: FilterOp::TextMatch(TextMatch { text: "x".into(), negate: true, ..TextMatch::default() }),
                },
                Filter::Parameter {
                    comp: event.clone(),
                    prop: ICalendarProperty::new("ATTENDEE"),
                    param: ICalendarParameterName::new("PARTSTAT"),
                    op: FilterOp::TextMatch(TextMatch { text: "NEEDS-ACTION".into(), ..TextMatch::default() }),
                },
                Filter::Property { comp: event, prop: ICalendarProperty::new("DESCRIPTION"), op: FilterOp::Undefined },
                Filter::Component {
                    comp: vec![ICalendarComponentType::new("VCALENDAR"), ICalendarComponentType::new("VTODO")],
                    op: FilterOp::Undefined
                },
            ]
        );
        let Report::CalendarQuery(query) = Report::parse(
            br#"<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><C:timezone-id>Europe/Vienna</C:timezone-id></C:calendar-query>"#,
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(
            (query.timezone, query.properties, query.filters),
            (Timezone::Id("Europe/Vienna".into()), PropFind::Prop(vec![]), vec![])
        );
        let bad_collation = br#"<C:calendar-query xmlns:C="urn:ietf:params:xml:ns:caldav"><C:filter><C:comp-filter name="VCALENDAR"><C:prop-filter name="UID"><C:text-match collation="i;nope">x</C:text-match></C:prop-filter></C:comp-filter></C:filter></C:calendar-query>"#;
        assert_eq!(Report::parse(bad_collation), Err(Error::UnsupportedCollation));
    }

    #[test]
    fn addressbook_queries() {
        let Report::AddressbookQuery(query) = Report::parse(
            br#"<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
              <D:prop><D:getetag/></D:prop>
              <C:filter test="allof"><C:prop-filter name="EMAIL"><C:text-match collation="i;unicode-casemap" match-type="starts-with">carol</C:text-match></C:prop-filter>
              <C:prop-filter name="item1.TEL"><C:param-filter name="TYPE"/></C:prop-filter></C:filter>
              <C:limit><C:nresults>10</C:nresults></C:limit>
            </C:addressbook-query>"#,
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(query.limit, Some(10));
        assert_eq!(query.filters[0], Filter::AllOf);
        assert_eq!(query.filters[1], Filter::AnyOf);
        assert_eq!(
            query.filters[2],
            Filter::Property {
                comp: (),
                prop: VCardPropertyWithGroup { name: VCardProperty::new("EMAIL"), group: None },
                op: FilterOp::TextMatch(TextMatch {
                    text: "carol".into(),
                    match_type: MatchType::StartsWith,
                    collation: Collation::UnicodeCasemap,
                    negate: false
                }),
            }
        );
        assert_eq!(query.filters[3], Filter::AnyOf);
        assert_eq!(
            query.filters[4],
            Filter::Parameter {
                comp: (),
                prop: VCardPropertyWithGroup { name: VCardProperty::new("TEL"), group: Some("item1".into()) },
                param: VCardParameterName::new("TYPE"),
                op: FilterOp::Exists,
            }
        );
        let Report::AddressbookQuery(all) = Report::parse(br#"<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav"><D:prop><D:getetag/></D:prop><C:filter/></C:addressbook-query>"#).unwrap() else {
            panic!()
        };
        assert!(all.filters.is_empty());
    }

    #[test]
    fn other_reports() {
        let Report::CalendarMultiGet(multiget) = Report::parse(
            br#"<C:calendar-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><D:getetag/></D:prop><D:href>/a.ics</D:href><D:href> /b.ics </D:href></C:calendar-multiget>"#,
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(multiget.hrefs, ["/a.ics", "/b.ics"]);
        let Report::SyncCollection(sync) = Report::parse(
            br#"<D:sync-collection xmlns:D="DAV:"><D:sync-token/><D:sync-level>1</D:sync-level><D:prop><D:getetag/></D:prop></D:sync-collection>"#,
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(
            (sync.sync_token, sync.infinite, sync.properties),
            (None, false, PropFind::Prop(vec![WebDavProperty::GetETag.into()]))
        );
        let Report::SyncCollection(sync) = Report::parse(
            br#"<sync-collection xmlns="DAV:"><sync-token>urn:kernoid:sync:5</sync-token><sync-level>infinite</sync-level><limit><nresults>3</nresults></limit><prop/></sync-collection>"#,
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(
            (sync.sync_token.as_deref(), sync.infinite, sync.limit),
            (Some("urn:kernoid:sync:5"), true, Some(3))
        );
        assert_eq!(
            Report::parse(br#"<C:free-busy-query xmlns:C="urn:ietf:params:xml:ns:caldav"><C:time-range start="20261207T000000Z" end="20261208T000000Z"/></C:free-busy-query>"#).unwrap(),
            Report::FreeBusyQuery { range: Some(TimeRange::new(1_796_601_600, 1_796_688_000)) }
        );
        assert_eq!(
            Report::parse(br#"<D:expand-property xmlns:D="DAV:"><D:property name="current-user-principal"/><D:property name="calendar-home-set" namespace="urn:ietf:params:xml:ns:caldav"><D:property name="displayname"/></D:property></D:expand-property>"#).unwrap(),
            Report::ExpandProperty { properties: vec![WebDavProperty::CurrentUserPrincipal.into(), CalDavName::CalendarHomeSet.into()] }
        );
        let Report::PrincipalPropertySearch(search) = Report::parse(
            br#"<D:principal-property-search xmlns:D="DAV:" test="anyof"><D:property-search><D:prop><D:displayname/></D:prop><D:match>ali</D:match></D:property-search><D:prop><D:displayname/></D:prop></D:principal-property-search>"#,
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(search.searches, vec![(vec![WebDavProperty::DisplayName.into()], "ali".to_owned())]);
        assert!(search.any_of && search.properties.len() == 1);
        assert_eq!(
            Report::parse(br#"<D:principal-search-property-set xmlns:D="DAV:"/>"#).unwrap(),
            Report::PrincipalSearchPropertySet
        );
        assert!(matches!(
            Report::parse(
                br#"<D:principal-match xmlns:D="DAV:"><D:self/><D:prop><D:displayname/></D:prop></D:principal-match>"#
            )
            .unwrap(),
            Report::PrincipalMatch { .. }
        ));
        assert_eq!(Report::parse(br#"<D:version-tree xmlns:D="DAV:"/>"#), Err(Error::UnsupportedReport));
    }
}
