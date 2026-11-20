// SPDX-License-Identifier: AGPL-3.0-or-later
//! The scheduling outbox (RFC 6638, 5): free/busy requests for accounts of the same tenant whose calendars the asking
//! account may see free/busy of (RFC 0004, 7 and 9). Invitations are sent when events are stored, not posted here.

use std::borrow::Cow;

use http::{HeaderValue, StatusCode, header};
use kernoid_groupware::{Level, PrincipalInfo};
use kernoid_pim::{Property, ical, tz::Zones};

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
    let ical = ical::parse(text).map_err(|_| invalid())?;
    let method = ical.method().unwrap_or_default();
    let request = ical.components("VFREEBUSY").next().filter(|_| method == "REQUEST").ok_or_else(invalid)?;
    let organizer = request.property("ORGANIZER").and_then(Property::address).map(|address| address.to_lowercase());
    if organizer.is_none_or(|organizer| !user.addresses.contains(&organizer)) {
        return Err(Error::Condition(StatusCode::FORBIDDEN, CalCondition::ValidOrganizer.into()));
    }
    let zones = Zones::of(&ical);
    let time = |name: &str| {
        request
            .property(name)
            .and_then(Property::time_value)
            .map(|time| time.resolve(&zones, &jiff::tz::TimeZone::UTC).as_second())
    };
    let (Some(start), Some(end)) = (time("DTSTART"), time("DTEND")) else {
        return Err(invalid());
    };
    let range = TimeRange::new(start, end);
    let uid = request.uid().unwrap_or_default();

    let mut response = ScheduleResponse::default();
    for attendee in request.properties("ATTENDEE") {
        let Some(address) = attendee.address() else { continue };
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
                        Property::text("UID", &uid),
                        attendee.clone(),
                        request.property("ORGANIZER").cloned().expect("checked"),
                    ];
                    let mut object = dav.freebusy(account, calendars, range, extra).await?;
                    object.properties.push(Property::new("METHOD", "REPLY"));
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
