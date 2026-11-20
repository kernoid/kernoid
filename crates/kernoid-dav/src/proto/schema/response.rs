// SPDX-License-Identifier: AGPL-3.0-or-later
//! Response bodies: `multistatus` (RFC 4918, 13; with `sync-token`, RFC 6578), error bodies with the precondition that
//! failed (RFC 4918, 16; CalDAV's and CardDAV's, RFC 4791, 5.3.2.1 and 9; RFC 6352, 6.3.2.1; RFC 6638, 3.2.4),
//! `mkcol-response` (RFC 5689), a `LOCK`'s `prop`, the scheduling outbox's `schedule-response` (RFC 6638, 10.2) and
//! `principal-search-property-set` (RFC 3744, 9.5). Each writes a whole document through [`Display`].

use std::fmt::{self, Display};

use http::StatusCode;

use super::{
    Namespace,
    property::{DavProperty, DavPropertyValue},
};
use crate::proto::xml::Writer;

/// `HTTP/1.1 <code> <reason>`.
fn status_line(status: StatusCode) -> String {
    format!("HTTP/1.1 {} {}", status.as_u16(), status.canonical_reason().unwrap_or(""))
}

/// A precondition or postcondition that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// `need-privileges` (RFC 3744, 7.1.1).
    NeedPrivileges,
    /// `quota-not-exceeded` (RFC 4331, 6).
    QuotaNotExceeded,
    /// `valid-sync-token` (RFC 6578, 3.2).
    ValidSyncToken,
    /// `valid-resourcetype` (RFC 5689, 3).
    ValidResourceType,
    /// `lock-token-submitted` (RFC 4918, 16), with the URLs locked.
    LockTokenSubmitted(Vec<String>),
    /// `supported-report` (RFC 3253, 3.6).
    SupportedReport,
    /// `supported-collation` of CalDAV (true) or CardDAV.
    SupportedCollation(bool),
    ValidCalendarData,
    ValidCalendarObjectResource,
    SupportedCalendarData,
    SupportedCalendarComponent,
    /// `max-resource-size` of CalDAV (true) or CardDAV.
    MaxResourceSize(bool),
    MaxInstances,
    /// `no-uid-conflict` of CalDAV (true) or CardDAV, with the URL of the resource that has the UID, if it may be
    /// shown.
    NoUidConflict(bool, Option<String>),
    SameOrganizerInAllComponents,
    AllowedOrganizerObjectChange,
    AllowedAttendeeObjectChange,
    ValidSchedulingMessage,
    ValidOrganizer,
    ValidAddressData,
    SupportedAddressData,
}

impl Condition {
    pub fn qualified_name(&self) -> (Namespace, &'static str) {
        let card = |is_calendar: bool| if is_calendar { Namespace::CalDav } else { Namespace::CardDav };
        match self {
            Self::NeedPrivileges => (Namespace::Dav, "need-privileges"),
            Self::QuotaNotExceeded => (Namespace::Dav, "quota-not-exceeded"),
            Self::ValidSyncToken => (Namespace::Dav, "valid-sync-token"),
            Self::ValidResourceType => (Namespace::Dav, "valid-resourcetype"),
            Self::LockTokenSubmitted(_) => (Namespace::Dav, "lock-token-submitted"),
            Self::SupportedReport => (Namespace::Dav, "supported-report"),
            Self::SupportedCollation(is_calendar) => (card(*is_calendar), "supported-collation"),
            Self::ValidCalendarData => (Namespace::CalDav, "valid-calendar-data"),
            Self::ValidCalendarObjectResource => (Namespace::CalDav, "valid-calendar-object-resource"),
            Self::SupportedCalendarData => (Namespace::CalDav, "supported-calendar-data"),
            Self::SupportedCalendarComponent => (Namespace::CalDav, "supported-calendar-component"),
            Self::MaxResourceSize(is_calendar) => (card(*is_calendar), "max-resource-size"),
            Self::MaxInstances => (Namespace::CalDav, "max-instances"),
            Self::NoUidConflict(is_calendar, _) => (card(*is_calendar), "no-uid-conflict"),
            Self::SameOrganizerInAllComponents => (Namespace::CalDav, "same-organizer-in-all-components"),
            Self::AllowedOrganizerObjectChange => (Namespace::CalDav, "allowed-organizer-scheduling-object-change"),
            Self::AllowedAttendeeObjectChange => (Namespace::CalDav, "allowed-attendee-scheduling-object-change"),
            Self::ValidSchedulingMessage => (Namespace::CalDav, "valid-scheduling-message"),
            Self::ValidOrganizer => (Namespace::CalDav, "valid-organizer"),
            Self::ValidAddressData => (Namespace::CardDav, "valid-address-data"),
            Self::SupportedAddressData => (Namespace::CardDav, "supported-address-data"),
        }
    }

    fn write(&self, writer: &mut Writer) {
        let (ns, name) = self.qualified_name();
        let hrefs: &[String] = match self {
            Self::LockTokenSubmitted(hrefs) => hrefs,
            Self::NoUidConflict(_, Some(href)) => std::slice::from_ref(href),
            _ => &[],
        };
        if hrefs.is_empty() {
            writer.empty(ns, name);
        } else {
            writer.open(ns, name);
            for href in hrefs {
                writer.text_element(Namespace::Dav, "href", href);
            }
            writer.close(ns, name);
        }
    }
}

/// An error body: `<D:error>` with the condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorResponse(pub Condition);

impl Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut writer = Writer::new();
        writer.open(Namespace::Dav, "error");
        self.0.write(&mut writer);
        writer.close(Namespace::Dav, "error");
        f.write_str(&writer.finish())
    }
}

/// Properties with one status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropStat {
    pub props: Vec<DavPropertyValue>,
    pub status: StatusCode,
    pub error: Option<Condition>,
}

impl PropStat {
    /// Properties found (`200 OK`).
    pub fn new_list(props: Vec<DavPropertyValue>) -> Self {
        Self { props, status: StatusCode::OK, error: None }
    }

    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    fn write(&self, writer: &mut Writer) {
        writer.open(Namespace::Dav, "propstat");
        writer.open(Namespace::Dav, "prop");
        for prop in &self.props {
            prop.write(writer);
        }
        writer.close(Namespace::Dav, "prop");
        writer.text_element(Namespace::Dav, "status", &status_line(self.status));
        if let Some(error) = &self.error {
            writer.open(Namespace::Dav, "error");
            error.write(writer);
            writer.close(Namespace::Dav, "error");
        }
        writer.close(Namespace::Dav, "propstat");
    }
}

/// What a `response` says: properties by status, or one status for its hrefs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseBody {
    PropStat(Vec<PropStat>),
    Status(StatusCode),
}

/// One `response` of a multi-status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub hrefs: Vec<String>,
    pub body: ResponseBody,
    pub error: Option<Condition>,
}

impl Response {
    pub fn new_propstat(href: impl Into<String>, propstat: Vec<PropStat>) -> Self {
        Self { hrefs: vec![href.into()], body: ResponseBody::PropStat(propstat), error: None }
    }

    pub fn new_status(hrefs: impl IntoIterator<Item = impl Into<String>>, status: StatusCode) -> Self {
        Self { hrefs: hrefs.into_iter().map(Into::into).collect(), body: ResponseBody::Status(status), error: None }
    }

    pub fn with_error(mut self, error: Condition) -> Self {
        self.error = Some(error);
        self
    }

    fn write(&self, writer: &mut Writer) {
        writer.open(Namespace::Dav, "response");
        for href in &self.hrefs {
            writer.text_element(Namespace::Dav, "href", href);
        }
        match &self.body {
            // A response needs a propstat or a status: nothing asked for is a 200 without properties.
            ResponseBody::PropStat(propstat) if propstat.is_empty() => {
                writer.text_element(Namespace::Dav, "status", &status_line(StatusCode::OK));
            }
            ResponseBody::PropStat(propstat) => {
                for propstat in propstat {
                    propstat.write(writer);
                }
            }
            ResponseBody::Status(status) => writer.text_element(Namespace::Dav, "status", &status_line(*status)),
        }
        if let Some(error) = &self.error {
            writer.open(Namespace::Dav, "error");
            error.write(writer);
            writer.close(Namespace::Dav, "error");
        }
        writer.close(Namespace::Dav, "response");
    }
}

/// A `multistatus`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MultiStatus {
    pub responses: Vec<Response>,
    pub sync_token: Option<String>,
}

impl MultiStatus {
    pub fn new(responses: Vec<Response>) -> Self {
        Self { responses, sync_token: None }
    }

    pub fn add_response(&mut self, response: Response) {
        self.responses.push(response);
    }

    pub fn set_sync_token(&mut self, token: impl Into<String>) {
        self.sync_token = Some(token.into());
    }
}

impl Display for MultiStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut writer = Writer::new();
        writer.open(Namespace::Dav, "multistatus");
        for response in &self.responses {
            response.write(&mut writer);
        }
        if let Some(token) = &self.sync_token {
            writer.text_element(Namespace::Dav, "sync-token", token);
        }
        writer.close(Namespace::Dav, "multistatus");
        f.write_str(&writer.finish())
    }
}

/// The answer to an extended `MKCOL` (RFC 5689, 3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MkColResponse(pub Vec<PropStat>);

impl Display for MkColResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut writer = Writer::new();
        writer.open(Namespace::Dav, "mkcol-response");
        for propstat in &self.0 {
            propstat.write(&mut writer);
        }
        writer.close(Namespace::Dav, "mkcol-response");
        f.write_str(&writer.finish())
    }
}

/// A `prop` document – the answer to `LOCK` (RFC 4918, 9.10.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropResponse(pub Vec<DavPropertyValue>);

impl Display for PropResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut writer = Writer::new();
        writer.open(Namespace::Dav, "prop");
        for prop in &self.0 {
            prop.write(&mut writer);
        }
        writer.close(Namespace::Dav, "prop");
        f.write_str(&writer.finish())
    }
}

/// One recipient of a scheduling request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleResponseItem {
    pub recipient: String,
    pub request_status: String,
    pub calendar_data: Option<String>,
}

/// The outbox's answer to a `POST` (RFC 6638, 10.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScheduleResponse(pub Vec<ScheduleResponseItem>);

impl Display for ScheduleResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut writer = Writer::new();
        writer.open(Namespace::CalDav, "schedule-response");
        for item in &self.0 {
            writer.open(Namespace::CalDav, "response");
            writer.open(Namespace::CalDav, "recipient");
            writer.text_element(Namespace::Dav, "href", &item.recipient);
            writer.close(Namespace::CalDav, "recipient");
            writer.text_element(Namespace::CalDav, "request-status", &item.request_status);
            if let Some(data) = &item.calendar_data {
                writer.text_element(Namespace::CalDav, "calendar-data", data);
            }
            writer.close(Namespace::CalDav, "response");
        }
        writer.close(Namespace::CalDav, "schedule-response");
        f.write_str(&writer.finish())
    }
}

/// The properties principals can be searched by, each with a description (RFC 3744, 9.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalSearchPropertySet(pub Vec<(DavProperty, &'static str)>);

impl Display for PrincipalSearchPropertySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut writer = Writer::new();
        writer.open(Namespace::Dav, "principal-search-property-set");
        for (property, description) in &self.0 {
            writer.open(Namespace::Dav, "principal-search-property");
            writer.open(Namespace::Dav, "prop");
            DavPropertyValue::empty(property.clone()).write(&mut writer);
            writer.close(Namespace::Dav, "prop");
            writer.start_tag(Namespace::Dav, "description").attr("xml:lang", "en").end_start();
            writer.text(description);
            writer.close(Namespace::Dav, "description");
            writer.close(Namespace::Dav, "principal-search-property");
        }
        writer.close(Namespace::Dav, "principal-search-property-set");
        f.write_str(&writer.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        schema::property::{CalDavName, DavValue, WebDavProperty},
        xml::parse,
    };

    /// The document without its declaration and the root's namespace declarations.
    fn body(document: impl Display) -> String {
        let text = document.to_string();
        parse(text.as_bytes()).expect("well-formed");
        assert_eq!(text.matches("<?xml").count(), 1);
        let declarations: String =
            Namespace::ALL.iter().map(|ns| format!(" xmlns:{}=\"{}\"", ns.prefix(), ns.uri())).collect();
        text.split_once('\n').unwrap().1.replacen(&declarations, "", 1)
    }

    #[test]
    fn multistatus_with_propstat_status_and_token() {
        let mut multistatus = MultiStatus::new(vec![Response::new_propstat(
            "/dav/a/",
            vec![
                PropStat::new_list(vec![DavPropertyValue::new(WebDavProperty::DisplayName, "A & B")]),
                PropStat::new_list(vec![DavPropertyValue::empty(CalDavName::CalendarDescription)])
                    .with_status(StatusCode::NOT_FOUND),
            ],
        )]);
        multistatus.add_response(Response::new_status(["/dav/gone.ics"], StatusCode::NOT_FOUND));
        multistatus.add_response(Response::new_propstat("/dav/b/", vec![]));
        multistatus.set_sync_token("urn:kernoid:sync:7");
        assert_eq!(
            body(&multistatus),
            "<D:multistatus><D:response><D:href>/dav/a/</D:href><D:propstat><D:prop><D:displayname>A &amp; B</D:displayname>\
             </D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat><D:propstat><D:prop><C:calendar-description/></D:prop>\
             <D:status>HTTP/1.1 404 Not Found</D:status></D:propstat></D:response><D:response><D:href>/dav/gone.ics</D:href>\
             <D:status>HTTP/1.1 404 Not Found</D:status></D:response><D:response><D:href>/dav/b/</D:href><D:status>HTTP/1.1 200 OK\
             </D:status></D:response><D:sync-token>urn:kernoid:sync:7</D:sync-token></D:multistatus>"
        );
    }

    #[test]
    fn error_bodies() {
        assert_eq!(body(ErrorResponse(Condition::ValidSyncToken)), "<D:error><D:valid-sync-token/></D:error>");
        assert_eq!(
            body(ErrorResponse(Condition::NoUidConflict(true, Some("/dav/calendars/a/b/c.ics".into())))),
            "<D:error><C:no-uid-conflict><D:href>/dav/calendars/a/b/c.ics</D:href></C:no-uid-conflict></D:error>"
        );
        assert_eq!(
            body(ErrorResponse(Condition::NoUidConflict(false, None))),
            "<D:error><CARD:no-uid-conflict/></D:error>"
        );
        assert_eq!(
            body(ErrorResponse(Condition::AllowedAttendeeObjectChange)),
            "<D:error><C:allowed-attendee-scheduling-object-change/></D:error>"
        );
    }

    #[test]
    fn other_documents() {
        assert_eq!(
            body(MkColResponse(vec![PropStat::new_list(vec![DavPropertyValue::empty(WebDavProperty::DisplayName)])])),
            "<D:mkcol-response><D:propstat><D:prop><D:displayname/></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:mkcol-response>"
        );
        assert_eq!(
            body(PropResponse(vec![DavPropertyValue::new(WebDavProperty::LockDiscovery, DavValue::Locks(vec![]))])),
            "<D:prop><D:lockdiscovery></D:lockdiscovery></D:prop>"
        );
        let schedule = ScheduleResponse(vec![ScheduleResponseItem {
            recipient: "mailto:a@b".into(),
            request_status: "2.0;Success".into(),
            calendar_data: Some("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".into()),
        }]);
        assert_eq!(
            body(schedule),
            "<C:schedule-response><C:response><C:recipient><D:href>mailto:a@b</D:href></C:recipient><C:request-status>2.0;Success\
             </C:request-status><C:calendar-data>BEGIN:VCALENDAR&#13;\nEND:VCALENDAR&#13;\n</C:calendar-data></C:response></C:schedule-response>"
        );
        assert_eq!(
            body(PrincipalSearchPropertySet(vec![(WebDavProperty::DisplayName.into(), "Name")])),
            "<D:principal-search-property-set><D:principal-search-property><D:prop><D:displayname/></D:prop><D:description \
             xml:lang=\"en\">Name</D:description></D:principal-search-property></D:principal-search-property-set>"
        );
    }
}
