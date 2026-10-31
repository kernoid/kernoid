// SPDX-License-Identifier: AGPL-3.0-or-later
//! The scheduling outbox (RFC 6638, 5): free/busy requests for accounts of the same tenant whose calendars the asking
//! account may see free/busy of (RFC 0004, 7 and 9). Invitations are sent when events are stored, not posted here.

use std::borrow::Cow;

use calcard::{
    Entry, Parser,
    icalendar::{ICalendarComponentType, ICalendarEntry, ICalendarProperty, ICalendarValue},
};
use http::{HeaderValue, StatusCode, header};
use kernoid_groupware::{Level, PrincipalInfo};

use crate::{
    Dav, Error,
    proto::{
        schema::response::{CalCondition, Href, ScheduleResponse, ScheduleResponseItem},
        types::TimeRange,
    },
    server::DavResponse,
};

/// Answers a `VFREEBUSY` request posted to the outbox.
pub(crate) async fn outbox_post(dav: &Dav, user: &PrincipalInfo, body: &[u8]) -> Result<DavResponse, Error> {
    let invalid = || Error::Condition(StatusCode::BAD_REQUEST, CalCondition::ValidSchedulingMessage.into());
    let text = std::str::from_utf8(body).map_err(|_| invalid())?;
    let Entry::ICalendar(ical) = Parser::new(text).entry() else { return Err(invalid()) };
    let method = ical
        .components
        .first()
        .and_then(|root| root.property(&ICalendarProperty::Method))
        .and_then(|entry| entry.values.first())
        .and_then(|value| value.as_text())
        .unwrap_or_default();
    let request = ical
        .components
        .iter()
        .find(|comp| comp.component_type == ICalendarComponentType::VFreebusy)
        .filter(|_| method.eq_ignore_ascii_case("REQUEST"))
        .ok_or_else(invalid)?;
    let organizer = request
        .property(&ICalendarProperty::Organizer)
        .and_then(|entry| entry.calendar_address())
        .map(|address| address.to_lowercase());
    if organizer.is_none_or(|organizer| !user.addresses.contains(&organizer)) {
        return Err(Error::Condition(StatusCode::FORBIDDEN, CalCondition::ValidOrganizer.into()));
    }
    let time = |property| {
        request.property(&property).and_then(|entry| match entry.values.first() {
            Some(ICalendarValue::PartialDateTime(date)) => {
                date.to_date_time().and_then(|date| date.to_date_time_with_tz(calcard::common::timezone::Tz::UTC))
            }
            _ => None,
        })
    };
    let (Some(start), Some(end)) = (time(ICalendarProperty::Dtstart), time(ICalendarProperty::Dtend)) else {
        return Err(invalid());
    };
    let range = TimeRange::new(start.timestamp(), end.timestamp());
    let uid = request.uid().unwrap_or_default().to_owned();

    let mut response = ScheduleResponse::default();
    for attendee in request.properties(&ICalendarProperty::Attendee) {
        let Some(address) = attendee.calendar_address() else { continue };
        let address = address.to_lowercase();
        let mut item = ScheduleResponseItem {
            recipient: Href(format!("mailto:{address}")),
            request_status: Cow::Borrowed("3.7;Invalid calendar user"),
            calendar_data: None,
        };
        if let Some(account) = dav.groupware.account_by_address(user.tenant, &address).await? {
            let calendars = if account == user.id {
                None
            } else {
                let access = dav.groupware.access(user.id, account).await?;
                Some(
                    access
                        .collections
                        .iter()
                        .filter(|(_, level)| **level >= Level::Freebusy)
                        .map(|(id, _)| *id)
                        .collect::<Vec<_>>(),
                )
            };
            match calendars {
                Some(calendars) if calendars.is_empty() => {
                    item.request_status = Cow::Borrowed("3.8;No authority");
                }
                calendars => {
                    let calendars = match calendars {
                        Some(shared) => {
                            let own: Vec<_> =
                                dav.groupware.calendars(account).await?.into_iter().map(|c| c.id).collect();
                            Some(shared.into_iter().filter(|id| own.contains(id)).collect())
                        }
                        None => None,
                    };
                    let extra = vec![
                        ICalendarEntry {
                            name: ICalendarProperty::Uid,
                            params: vec![],
                            values: smallvec::smallvec![ICalendarValue::Text(uid.clone())],
                        },
                        attendee.clone(),
                        request.property(&ICalendarProperty::Organizer).cloned().expect("checked"),
                    ];
                    let mut object = dav.freebusy(account, calendars, range, extra).await?;
                    if let Some(root) = object.components.first_mut() {
                        root.entries.push(ICalendarEntry {
                            name: ICalendarProperty::Method,
                            params: vec![],
                            values: smallvec::smallvec![ICalendarValue::Text("REPLY".into())],
                        });
                    }
                    item.request_status = Cow::Borrowed("2.0;Success");
                    item.calendar_data = Some(object.to_string());
                }
            }
        }
        response.items.0.push(item);
    }
    let mut http = http::Response::new(response.to_string().into_bytes());
    http.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/xml; charset=utf-8"));
    Ok(http)
}
