// SPDX-License-Identifier: AGPL-3.0-or-later
//! Scheduling (RFC 0004, 7): implicit scheduling as RFC 6638 describes it, with iTIP messages (RFC 5546) – pure
//! functions over kernoid-pim's components; `itip.rs` applies them to the store, `send.rs` sends the messages.
//!
//! - **The organizer** stores an object with attendees: `REQUEST` to the attendees (grouped by the components each
//!   attends), `CANCEL` to those taken off, again `REQUEST` when anything but the attendees' answers changed. A change
//!   of the instances' times raises `SEQUENCE` and asks the attendees anew (`PARTSTAT=NEEDS-ACTION`). Sent attendees
//!   get `SCHEDULE-STATUS=1.1`.
//! - **An attendee** changes their own `PARTSTAT` (on the series or an instance, or by an `EXDATE`): `REPLY` to the
//!   organizer. Moving the organizer's times or changing the organizer is refused (RFC 6638, 3.2.2.1).
//! - **Received** messages change the recipient's copy: `REQUEST` creates or replaces it (keeping the own answer of
//!   the same `SEQUENCE` and the own alarms), `ADD` adds instances, `CANCEL` cancels it or leaves instances out,
//!   `REPLY` sets the attendee's answer in the organizer's copy, `REFRESH` is answered with a `REQUEST`. `COUNTER`
//!   and `DECLINECOUNTER` are not handled (OPEN), nor are the other attendees told of a reply (OPEN).
//!
//! Attendees and organizers with a `SCHEDULE-AGENT` other than `SERVER` are left to their clients.

use jiff::{Timestamp, tz::TimeZone};
use kernoid_pim::{Component, Property, expand, time, tz::Zones};

/// Why nothing was scheduled, or a change was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItipError {
    /// No organizer or no attendees: not a scheduling object.
    NoSchedulingInfo,
    /// The account attends, but does not organize, and nothing of its own changed.
    NotOrganizer,
    NotOrganizerNorAttendee,
    /// A client schedules this object itself (`SCHEDULE-AGENT=CLIENT`).
    OtherSchedulingAgent,
    NothingToSend,
    /// An attendee's change of the organizer.
    OrganizerMismatch,
    /// An attendee's change of what the organizer decides (a property).
    CannotModifyProperty(String),
    /// An attendee's change of the instances.
    CannotModifyInstance,
    /// A message from someone who may not send it.
    SenderNotAllowed,
    /// Not an iTIP message kernoid reads.
    Invalid(String),
}

/// What a message says, for its email.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItipSummary {
    Invite,
    Update,
    Cancel,
    /// An answer, with the participation status (`ACCEPTED`, `DECLINED`, …).
    Rsvp {
        part_stat: String,
    },
}

impl ItipSummary {
    /// The iTIP method.
    pub fn method(&self) -> &str {
        match self {
            ItipSummary::Invite | ItipSummary::Update => "REQUEST",
            ItipSummary::Cancel => "CANCEL",
            ItipSummary::Rsvp { .. } => "REPLY",
        }
    }
}

/// A message to send.
#[derive(Debug, Clone)]
pub struct ItipMessage {
    pub from: String,
    pub to: Vec<String>,
    pub summary: ItipSummary,
    pub message: Component,
}

/// What a received message does.
#[derive(Debug)]
pub enum Received {
    /// The calendar object, created or changed.
    Store(Component),
    /// A message to send in turn.
    Send(ItipMessage),
    Nothing,
}

fn lower(address: &str) -> String {
    address.trim().to_lowercase()
}

fn is_own(address: &str, addresses: &[String]) -> bool {
    addresses.iter().any(|own| own.eq_ignore_ascii_case(address.trim()))
}

/// Whether the server schedules for this organizer or attendee.
fn server_agent(property: &Property) -> bool {
    property.param("SCHEDULE-AGENT").is_none_or(|agent| agent.eq_ignore_ascii_case("SERVER"))
}

/// The series of an object, else its first component.
fn main_component(ical: &Component) -> Option<&Component> {
    ical.schedulable().find(|c| c.property("RECURRENCE-ID").is_none()).or_else(|| ical.schedulable().next())
}

fn organizer(ical: &Component) -> Option<&Property> {
    main_component(ical)?.property("ORGANIZER")
}

fn organizer_address(ical: &Component) -> Option<String> {
    organizer(ical).and_then(Property::address).map(|address| lower(&address))
}

/// The account's address among a component's attendees.
fn own_attendee<'a>(component: &'a Component, addresses: &[String]) -> Option<&'a Property> {
    component.properties("ATTENDEE").find(|attendee| attendee.address().is_some_and(|a| is_own(&a, addresses)))
}

fn recurrence_key(component: &Component) -> Option<String> {
    component.property("RECURRENCE-ID").map(|id| id.value.trim().to_owned())
}

fn now_stamp() -> Property {
    Property::new(
        "DTSTAMP",
        format!("{}Z", time::format_local(TimeZone::UTC.to_datetime(Timestamp::now())).replace(['-', ':'], "")),
    )
}

/// A `VCALENDAR` for a message: the method and the time zones of the object.
fn envelope(method: &str, source: &Component) -> Component {
    let mut calendar = Component::calendar(crate::PROD_ID);
    calendar.properties.push(Property::new("METHOD", method));
    calendar.components.extend(source.components("VTIMEZONE").cloned());
    calendar
}

/// A component as it goes out: without alarms and the scheduling parameters, stamped now.
fn outgoing(component: &Component) -> Component {
    let mut out = component.clone();
    out.components.retain(|inner| !inner.is("VALARM"));
    for property in out.properties.iter_mut().filter(|p| p.is("ATTENDEE") || p.is("ORGANIZER")) {
        for param in ["SCHEDULE-AGENT", "SCHEDULE-STATUS", "SCHEDULE-FORCE-SEND"] {
            property.remove_param(param);
        }
    }
    out.set(now_stamp());
    out
}

/// The attendees the server sends to: not the account, scheduled by the server.
fn recipients(component: &Component, addresses: &[String]) -> Vec<String> {
    component
        .properties("ATTENDEE")
        .filter(|attendee| server_agent(attendee))
        .filter_map(Property::address)
        .map(|address| lower(&address))
        .filter(|address| !is_own(address, addresses) && address.contains('@'))
        .collect()
}

/// `REQUEST`s to every attendee of the object, one message per set of components the same attendees attend; marks
/// them sent.
fn requests(ical: &mut Component, addresses: &[String], from: &str, summary: ItipSummary) -> Vec<ItipMessage> {
    let parts: Vec<usize> =
        ical.components.iter().enumerate().filter(|(_, c)| c.is_schedulable()).map(|(index, _)| index).collect();
    let mut groups: Vec<(Vec<usize>, Vec<String>)> = Vec::new();
    let mut everyone: Vec<String> = Vec::new();
    for index in &parts {
        for address in recipients(&ical.components[*index], addresses) {
            if !everyone.contains(&address) {
                everyone.push(address);
            }
        }
    }
    for address in everyone {
        let attends: Vec<usize> = parts
            .iter()
            .copied()
            .filter(|index| recipients(&ical.components[*index], addresses).contains(&address))
            .collect();
        match groups.iter_mut().find(|(set, _)| *set == attends) {
            Some((_, to)) => to.push(address),
            None => groups.push((attends, vec![address])),
        }
    }
    let mut messages = Vec::new();
    for (set, to) in groups {
        let mut message = envelope("REQUEST", ical);
        message.components.extend(set.iter().map(|index| outgoing(&ical.components[*index])));
        messages.push(ItipMessage { from: from.to_owned(), to, summary: summary.clone(), message });
    }
    for index in parts {
        let sent = recipients(&ical.components[index], addresses);
        for attendee in ical.components[index].properties.iter_mut().filter(|p| p.is("ATTENDEE")) {
            if attendee.address().is_some_and(|a| sent.contains(&lower(&a))) {
                attendee.set_param("SCHEDULE-STATUS", "1.1");
                attendee.remove_param("SCHEDULE-FORCE-SEND");
            }
        }
    }
    messages
}

/// The account's own address of the organizer, if it organizes the object.
fn own_organizer(ical: &Component, addresses: &[String]) -> Option<String> {
    organizer_address(ical).filter(|address| is_own(address, addresses))
}

fn has_attendees(ical: &Component) -> bool {
    ical.schedulable().any(|component| component.property("ATTENDEE").is_some())
}

/// What an organizer's or attendee's new object sends (CalDAV `PUT` of a new resource, JMAP create).
pub fn create(ical: &mut Component, addresses: &[String]) -> Result<Vec<ItipMessage>, ItipError> {
    if organizer(ical).is_none() || !has_attendees(ical) {
        return Err(ItipError::NoSchedulingInfo);
    }
    let Some(from) = own_organizer(ical, addresses) else {
        let attends = ical.schedulable().any(|component| own_attendee(component, addresses).is_some());
        return Err(if attends { ItipError::NotOrganizer } else { ItipError::NotOrganizerNorAttendee });
    };
    if !organizer(ical).is_some_and(server_agent) {
        return Err(ItipError::OtherSchedulingAgent);
    }
    let messages = requests(ical, addresses, &from, ItipSummary::Invite);
    if messages.is_empty() {
        return Err(ItipError::NothingToSend);
    }
    Ok(messages)
}

/// The instances of an object as (start, end), to tell whether its times changed.
fn instance_times(ical: &Component) -> Vec<(Timestamp, Timestamp)> {
    expand::expand(ical, &TimeZone::UTC, None, crate::ical::MAX_INSTANCES)
        .instances
        .into_iter()
        .map(|instance| (instance.start, instance.end))
        .collect()
}

/// A component's content as the organizer decides it: what attendees' answers, stamps and alarms do not change.
/// A property compared: its name, its parameters and its value.
type Compared = (String, Vec<(String, Vec<String>)>, String);

fn content(component: &Component) -> Vec<Compared> {
    const IGNORED: [&str; 7] =
        ["DTSTAMP", "LAST-MODIFIED", "SEQUENCE", "ATTENDEE", "X-MOZ-GENERATION", "X-MOZ-LASTACK", "X-MOZ-SNOOZE-TIME"];
    let mut out: Vec<_> = component
        .properties
        .iter()
        .filter(|p| !IGNORED.iter().any(|name| p.is(name)))
        .map(|p| {
            let params = p
                .params
                .iter()
                .filter(|param| !param.name.starts_with("SCHEDULE-"))
                .map(|param| (param.name.clone(), param.values.clone()))
                .collect();
            (p.name.clone(), params, p.value.clone())
        })
        .collect();
    out.sort();
    out
}

fn attendee_set(component: &Component) -> Vec<String> {
    let mut out: Vec<String> =
        component.properties("ATTENDEE").filter_map(Property::address).map(|address| lower(&address)).collect();
    out.sort();
    out.dedup();
    out
}

fn sequence(ical: &Component) -> i64 {
    ical.schedulable().filter_map(|c| c.property("SEQUENCE").and_then(Property::integer)).max().unwrap_or(0)
}

/// What a change of an object sends (CalDAV `PUT` over a resource, JMAP update).
pub fn update(ical: &mut Component, old: &Component, addresses: &[String]) -> Result<Vec<ItipMessage>, ItipError> {
    let old_organizer = organizer_address(old);
    if old_organizer.is_none() && organizer(ical).is_none() {
        return Err(ItipError::NoSchedulingInfo);
    }
    match own_organizer(old, addresses) {
        Some(from) => organizer_update(ical, old, addresses, &from),
        None if old_organizer.is_none() => create(ical, addresses),
        None => attendee_update(ical, old, addresses),
    }
}

fn organizer_update(
    ical: &mut Component,
    old: &Component,
    addresses: &[String],
    from: &str,
) -> Result<Vec<ItipMessage>, ItipError> {
    if own_organizer(ical, addresses).is_none() {
        return Err(ItipError::OrganizerMismatch);
    }
    if !organizer(ical).is_some_and(server_agent) {
        return Err(ItipError::OtherSchedulingAgent);
    }
    let mut messages = Vec::new();
    // Attendees taken off: cancelled.
    let now: Vec<String> = ical.schedulable().flat_map(|c| recipients(c, addresses)).collect();
    let mut removed: Vec<String> =
        old.schedulable().flat_map(|c| recipients(c, addresses)).filter(|address| !now.contains(address)).collect();
    removed.sort();
    removed.dedup();
    if !removed.is_empty() {
        let mut message = cancel_message(old, sequence(ical).max(sequence(old) + 1));
        message.to = removed;
        message.from = from.to_owned();
        messages.push(message);
    }
    let times_changed = instance_times(ical) != instance_times(old);
    let changed = times_changed || {
        let content_of = |calendar: &Component| -> Vec<_> {
            let mut parts: Vec<_> =
                calendar.schedulable().map(|c| (recurrence_key(c), content(c), attendee_set(c))).collect();
            parts.sort();
            parts
        };
        content_of(ical) != content_of(old)
    };
    if changed {
        if times_changed {
            let next = sequence(old) + 1;
            for component in ical.schedulable_mut() {
                if component.property("SEQUENCE").and_then(Property::integer).unwrap_or(0) < next {
                    component.set(Property::new("SEQUENCE", next.to_string()));
                }
                for attendee in component.properties.iter_mut().filter(|p| p.is("ATTENDEE")) {
                    if attendee.address().is_some_and(|a| !is_own(&a, addresses)) && server_agent(attendee) {
                        attendee.set_param("PARTSTAT", "NEEDS-ACTION");
                        attendee.set_param("RSVP", "TRUE");
                    }
                }
            }
        }
        // New attendees get an invitation, the others the update – both are REQUESTs.
        let known: Vec<String> = old.schedulable().flat_map(|c| recipients(c, addresses)).collect();
        let summary = if known.is_empty() { ItipSummary::Invite } else { ItipSummary::Update };
        messages.extend(requests(ical, addresses, from, summary));
    }
    if messages.is_empty() {
        return Err(ItipError::NothingToSend);
    }
    Ok(messages)
}

/// The component of a calendar for a recurrence id (`None`: the series).
fn component_for<'a>(ical: &'a Component, key: &Option<String>) -> Option<&'a Component> {
    ical.schedulable().find(|c| recurrence_key(c) == *key)
}

fn part_stat(attendee: Option<&Property>) -> String {
    attendee.and_then(|a| a.param("PARTSTAT")).unwrap_or("NEEDS-ACTION").to_ascii_uppercase()
}

fn attendee_update(ical: &mut Component, old: &Component, addresses: &[String]) -> Result<Vec<ItipMessage>, ItipError> {
    let Some(old_main) = main_component(old) else { return Err(ItipError::NoSchedulingInfo) };
    let Some(me) = old.schedulable().find_map(|c| own_attendee(c, addresses)).and_then(Property::address) else {
        return Err(ItipError::NotOrganizerNorAttendee);
    };
    if organizer_address(ical) != organizer_address(old) {
        return Err(ItipError::OrganizerMismatch);
    }
    if !organizer(old).is_some_and(server_agent) {
        return Err(ItipError::OtherSchedulingAgent);
    }
    // The organizer's times stay: no instance added or moved (an attendee may leave instances out).
    let old_times = instance_times(old);
    if instance_times(ical).iter().any(|time| !old_times.contains(time)) {
        return Err(ItipError::CannotModifyInstance);
    }
    if attendee_set(main_component(ical).ok_or(ItipError::NoSchedulingInfo)?) != attendee_set(old_main) {
        return Err(ItipError::CannotModifyProperty("ATTENDEE".into()));
    }
    // What the attendee answered anew.
    let mut answers: Vec<(Component, String)> = Vec::new();
    for component in ical.schedulable() {
        let key = recurrence_key(component);
        let before = component_for(old, &key).or(Some(old_main)).and_then(|c| own_attendee(c, addresses));
        let after = own_attendee(component, addresses);
        if after.is_none() {
            continue;
        }
        let (before_stat, after_stat) = (part_stat(before), part_stat(after));
        let same_delegation = before.map(|b| b.param("DELEGATED-TO")) == after.map(|a| a.param("DELEGATED-TO"));
        if before_stat != after_stat || !same_delegation {
            answers.push((reply_component(component, after.expect("checked")), after_stat));
        }
    }
    // Instances left out by an EXDATE: declined.
    if let Some(main) = main_component(ical).filter(|c| c.property("RECURRENCE-ID").is_none()) {
        let known: Vec<String> = old_main.properties("EXDATE").map(|p| p.value.clone()).collect();
        for exdate in main.properties("EXDATE").filter(|p| !known.contains(&p.value)) {
            for time in exdate.time_values() {
                let mut component = reply_component(main, own_attendee(main, addresses).expect("an attendee"));
                let id = Property::time("RECURRENCE-ID", &time);
                component.set(Property::time("DTSTART", &time));
                component.remove("DTEND");
                component.remove("DURATION");
                component.properties.insert(1, id);
                if let Some(attendee) = component.property_mut("ATTENDEE") {
                    attendee.set_param("PARTSTAT", "DECLINED");
                }
                answers.push((component, "DECLINED".into()));
            }
        }
    }
    if answers.is_empty() {
        return Err(ItipError::NothingToSend);
    }
    let to = organizer_address(old).ok_or(ItipError::NoSchedulingInfo)?;
    let part_stat = answers[0].1.clone();
    let mut message = envelope("REPLY", ical);
    message.components.extend(answers.into_iter().map(|(component, _)| component));
    Ok(vec![ItipMessage { from: lower(&me), to: vec![to], summary: ItipSummary::Rsvp { part_stat }, message }])
}

/// The component of a reply: what identifies the instance, the organizer and the one attendee.
fn reply_component(component: &Component, attendee: &Property) -> Component {
    let mut out = Component::new(&component.name);
    for name in ["UID", "RECURRENCE-ID", "SEQUENCE", "DTSTART", "DTEND", "DURATION", "DUE", "SUMMARY", "ORGANIZER"] {
        if let Some(property) = component.property(name) {
            out.properties.push(property.clone());
        }
    }
    let mut attendee = attendee.clone();
    for param in ["RSVP", "SCHEDULE-AGENT", "SCHEDULE-STATUS", "SCHEDULE-FORCE-SEND"] {
        attendee.remove_param(param);
    }
    out.properties.push(attendee);
    if let Some(organizer) = out.property_mut("ORGANIZER") {
        for param in ["SCHEDULE-AGENT", "SCHEDULE-STATUS", "SCHEDULE-FORCE-SEND"] {
            organizer.remove_param(param);
        }
    }
    out.set(now_stamp());
    out
}

/// A `CANCEL` of a whole object (its series, or each instance when there is none).
fn cancel_message(old: &Component, sequence: i64) -> ItipMessage {
    let mut message = envelope("CANCEL", old);
    let series: Vec<&Component> = match old.schedulable().find(|c| c.property("RECURRENCE-ID").is_none()) {
        Some(series) => vec![series],
        None => old.schedulable().collect(),
    };
    for component in series {
        let mut out = Component::new(&component.name);
        for name in ["UID", "RECURRENCE-ID", "DTSTART", "DTEND", "DURATION", "DUE", "SUMMARY", "ORGANIZER", "ATTENDEE"]
        {
            out.properties.extend(component.properties(name).cloned());
        }
        out.set(Property::new("SEQUENCE", sequence.to_string()));
        out.set(Property::new("STATUS", "CANCELLED"));
        message.components.push(outgoing(&out));
    }
    ItipMessage { from: String::new(), to: Vec::new(), summary: ItipSummary::Cancel, message }
}

/// What removing an object sends: a `CANCEL` to the attendees when the account organizes it, a decline to the
/// organizer when it attends.
pub fn cancel(old: &Component, addresses: &[String]) -> Result<ItipMessage, ItipError> {
    if organizer(old).is_none() || !has_attendees(old) {
        return Err(ItipError::NoSchedulingInfo);
    }
    if let Some(from) = own_organizer(old, addresses) {
        if !organizer(old).is_some_and(server_agent) {
            return Err(ItipError::OtherSchedulingAgent);
        }
        let mut to: Vec<String> = old.schedulable().flat_map(|c| recipients(c, addresses)).collect();
        to.sort();
        to.dedup();
        if to.is_empty() {
            return Err(ItipError::NothingToSend);
        }
        let mut message = cancel_message(old, sequence(old) + 1);
        message.from = from;
        message.to = to;
        return Ok(message);
    }
    let main = main_component(old).ok_or(ItipError::NoSchedulingInfo)?;
    let Some(me) = own_attendee(main, addresses) else { return Err(ItipError::NotOrganizerNorAttendee) };
    let cancelled = main.text("STATUS").is_some_and(|status| status.trim().eq_ignore_ascii_case("CANCELLED"));
    if cancelled || part_stat(Some(me)) == "DECLINED" || !organizer(old).is_some_and(server_agent) {
        return Err(ItipError::NothingToSend);
    }
    let mut component = reply_component(main, me);
    if let Some(attendee) = component.property_mut("ATTENDEE") {
        attendee.set_param("PARTSTAT", "DECLINED");
    }
    let mut message = envelope("REPLY", old);
    message.components.push(component);
    Ok(ItipMessage {
        from: lower(&me.address().unwrap_or_default()),
        to: vec![organizer_address(old).ok_or(ItipError::NoSchedulingInfo)?],
        summary: ItipSummary::Rsvp { part_stat: "DECLINED".into() },
        message,
    })
}

/// The UID of an iTIP message.
pub fn uid(itip: &Component) -> Option<String> {
    itip.schedulable().find_map(Component::uid)
}

/// Whether `sender` may send this message: the organizer for what the organizer sends, an attendee for answers (or
/// who sends on their behalf, `SENT-BY`).
pub fn sender_allowed(itip: &Component, sender: &str) -> bool {
    let sender = lower(sender);
    let matches = |property: &Property| {
        property.address().is_some_and(|a| lower(&a) == sender)
            || property.param("SENT-BY").is_some_and(|by| lower(kernoid_pim::content::strip_mailto(by)) == sender)
    };
    let from_organizer = itip.schedulable().filter_map(|c| c.property("ORGANIZER")).any(matches);
    match itip.method().as_deref() {
        Some("REQUEST" | "ADD" | "CANCEL" | "DECLINECOUNTER" | "PUBLISH") => from_organizer,
        Some("REPLY" | "REFRESH" | "COUNTER") => itip.schedulable().flat_map(|c| c.properties("ATTENDEE")).any(matches),
        _ => false,
    }
}

/// An iTIP message without its method, as a calendar object.
fn as_object(itip: &Component) -> Component {
    let mut object = itip.clone();
    object.remove("METHOD");
    object
}

/// Applies a received message to the recipient's copy (`stored`, if there is one).
pub fn receive(
    stored: Option<&Component>,
    itip: &Component,
    addresses: &[String],
    sender: &str,
) -> Result<Received, ItipError> {
    let method = itip.method().ok_or_else(|| ItipError::Invalid("no METHOD".into()))?;
    if !sender_allowed(itip, sender) {
        return Err(ItipError::SenderNotAllowed);
    }
    match (method.as_str(), stored) {
        ("REQUEST", None) => Ok(Received::Store(as_object(itip))),
        ("REQUEST", Some(stored)) => {
            if own_organizer(stored, addresses).is_some() {
                return Err(ItipError::SenderNotAllowed);
            }
            Ok(merge_request(stored, itip, addresses).map_or(Received::Nothing, Received::Store))
        }
        ("ADD", Some(stored)) => {
            let mut object = stored.clone();
            for component in itip.schedulable() {
                let key = recurrence_key(component);
                object.components.retain(|c| !(c.is_schedulable() && key.is_some() && recurrence_key(c) == key));
                object.components.push(component.clone());
            }
            Ok(Received::Store(object))
        }
        ("CANCEL", Some(stored)) => Ok(Received::Store(apply_cancel(stored, itip))),
        ("REPLY", Some(stored)) => {
            if own_organizer(stored, addresses).is_none() {
                return Err(ItipError::SenderNotAllowed);
            }
            Ok(apply_reply(stored, itip, sender).map_or(Received::Nothing, Received::Store))
        }
        ("REFRESH", Some(stored)) => {
            let Some(from) = own_organizer(stored, addresses) else { return Err(ItipError::SenderNotAllowed) };
            let mut copy = stored.clone();
            let mut message = envelope("REQUEST", &copy);
            message.components.extend(copy.schedulable_mut().map(|c| outgoing(c)));
            Ok(Received::Send(ItipMessage { from, to: vec![lower(sender)], summary: ItipSummary::Update, message }))
        }
        _ => Ok(Received::Nothing),
    }
}

/// A `REQUEST` over a stored copy; `None` when it is older than the copy.
fn merge_request(stored: &Component, itip: &Component, addresses: &[String]) -> Option<Component> {
    let incoming: Vec<&Component> = itip.schedulable().collect();
    if sequence(itip) < sequence(stored) {
        return None;
    }
    let same_sequence = sequence(itip) == sequence(stored);
    let whole = incoming.iter().any(|c| c.property("RECURRENCE-ID").is_none());
    let mut object = stored.clone();
    object.remove("METHOD");
    // Time zones of the message replace those of the same name.
    for zone in itip.components("VTIMEZONE") {
        let tzid = zone.text("TZID");
        object.components.retain(|c| !(c.is("VTIMEZONE") && c.text("TZID") == tzid));
        let at = object.components.iter().position(Component::is_schedulable).unwrap_or(object.components.len());
        object.components.insert(at, zone.clone());
    }
    let old: Vec<Component> = object.schedulable().cloned().collect();
    if whole {
        object.components.retain(|c| !c.is_schedulable());
    } else {
        let keys: Vec<Option<String>> = incoming.iter().map(|c| recurrence_key(c)).collect();
        object.components.retain(|c| !(c.is_schedulable() && keys.contains(&recurrence_key(c))));
    }
    for component in incoming {
        let mut component = component.clone();
        if let Some(before) = old.iter().find(|c| recurrence_key(c) == recurrence_key(&component)) {
            // The account's own alarms stay; so does its answer to the same version.
            component.components.extend(before.components("VALARM").cloned());
            if same_sequence
                && let Some(answer) = own_attendee(before, addresses).cloned()
                && let Some(attendee) = component
                    .properties
                    .iter_mut()
                    .find(|p| p.is("ATTENDEE") && p.address().is_some_and(|a| is_own(&a, addresses)))
            {
                if let Some(status) = answer.param("PARTSTAT") {
                    attendee.set_param("PARTSTAT", status);
                }
                attendee.remove_param("RSVP");
            }
        }
        object.components.push(component);
    }
    Some(object)
}

fn apply_cancel(stored: &Component, itip: &Component) -> Component {
    let mut object = stored.clone();
    let whole = itip.schedulable().any(|c| c.property("RECURRENCE-ID").is_none());
    let seq = sequence(itip);
    if whole {
        for component in object.schedulable_mut() {
            component.set(Property::new("STATUS", "CANCELLED"));
            if seq > 0 {
                component.set(Property::new("SEQUENCE", seq.to_string()));
            }
        }
        return object;
    }
    for instance in itip.schedulable() {
        let Some(id) = instance.property("RECURRENCE-ID") else { continue };
        let key = Some(id.value.trim().to_owned());
        object.components.retain(|c| !(c.is_schedulable() && recurrence_key(c) == key));
        if let Some(series) = object.schedulable_mut().find(|c| c.property("RECURRENCE-ID").is_none()) {
            let mut exdate = id.clone();
            exdate.name = "EXDATE".into();
            exdate.remove_param("RANGE");
            series.properties.push(exdate);
        }
    }
    object
}

/// The series' instance at a recurrence id, as an override of its own.
fn instance_of(series: &Component, id: &Property, zones: &Zones) -> Component {
    let mut instance = series.clone();
    for name in ["RRULE", "RDATE", "EXDATE", "EXRULE", "DTEND", "DURATION"] {
        instance.remove(name);
    }
    let duration = expand::duration_of(series, zones, &TimeZone::UTC);
    let mut start = id.clone();
    start.name = "DTSTART".into();
    start.remove_param("RANGE");
    instance.set(start);
    if !duration.is_zero() {
        instance.set(Property::new("DURATION", duration.to_string()));
    }
    let at = instance.properties.iter().position(|p| p.is("DTSTART")).unwrap_or(0);
    instance.properties.insert(at, id.clone());
    instance
}

fn apply_reply(stored: &Component, itip: &Component, sender: &str) -> Option<Component> {
    let sender = lower(sender);
    let zones = Zones::of(stored);
    let mut object = stored.clone();
    let mut changed = false;
    for answer in itip.schedulable() {
        let Some(reply) = answer.properties("ATTENDEE").find(|a| {
            a.address().is_some_and(|address| lower(&address) == sender)
                || a.param("SENT-BY").is_some_and(|by| lower(kernoid_pim::content::strip_mailto(by)) == sender)
        }) else {
            continue;
        };
        let key = recurrence_key(answer);
        if component_for(&object, &key).is_none() {
            let (Some(id), Some(series)) = (answer.property("RECURRENCE-ID"), component_for(&object, &None)) else {
                continue;
            };
            let instance = instance_of(series, id, &zones);
            object.components.push(instance);
        }
        let Some(target) = object.schedulable_mut().find(|c| recurrence_key(c) == key) else { continue };
        let address = reply.address().map(|a| lower(&a)).unwrap_or_default();
        let Some(attendee) = target
            .properties
            .iter_mut()
            .find(|p| p.is("ATTENDEE") && p.address().is_some_and(|a| lower(&a) == address))
        else {
            continue;
        };
        attendee.set_param("PARTSTAT", reply.param("PARTSTAT").unwrap_or("NEEDS-ACTION").to_ascii_uppercase());
        attendee.remove_param("RSVP");
        match reply.param("DELEGATED-TO") {
            Some(_) => attendee
                .set_param_values("DELEGATED-TO", reply.param_values("DELEGATED-TO").map(str::to_owned).collect()),
            None => attendee.remove_param("DELEGATED-TO"),
        }
        attendee.set_param("SCHEDULE-STATUS", "2.0");
        changed = true;
    }
    changed.then_some(object)
}

#[cfg(test)]
mod tests {
    use kernoid_pim::ical;

    use super::*;

    const MEETING: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\nBEGIN:VEVENT\r\nUID:m@firma\r\n\
        DTSTAMP:20261001T080000Z\r\nDTSTART:20261110T100000Z\r\nDURATION:PT1H\r\nSUMMARY:Planning\r\n\
        ORGANIZER;CN=Alice:mailto:alice@firma.example\r\nATTENDEE;PARTSTAT=ACCEPTED:mailto:alice@firma.example\r\n\
        ATTENDEE;RSVP=TRUE;PARTSTAT=NEEDS-ACTION:mailto:bob@firma.example\r\n\
        ATTENDEE;RSVP=TRUE;PARTSTAT=NEEDS-ACTION;SCHEDULE-AGENT=CLIENT:mailto:carol@remote.example\r\n\
        BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\nDESCRIPTION:x\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    fn alice() -> Vec<String> {
        vec!["alice@firma.example".into()]
    }

    fn bob() -> Vec<String> {
        vec!["bob@firma.example".into()]
    }

    #[test]
    fn the_organizer_invites_updates_and_cancels() {
        let mut ical = ical::parse(MEETING).unwrap();
        let messages = create(&mut ical, &alice()).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].to, ["bob@firma.example"]);
        let text = messages[0].message.to_string();
        assert!(
            text.contains("METHOD:REQUEST") && !text.contains("VALARM") && !text.contains("SCHEDULE-AGENT"),
            "{text}"
        );
        assert!(ical.to_string().contains("SCHEDULE-STATUS=1.1"));

        // Nothing changed: nothing to send; a new time asks again with a higher sequence.
        let mut same = ical.clone();
        assert_eq!(update(&mut same, &ical, &alice()).unwrap_err(), ItipError::NothingToSend);
        let mut moved = ical::parse(&ical.to_string().replace("20261110T100000Z", "20261111T100000Z")).unwrap();
        let messages = update(&mut moved, &ical, &alice()).unwrap();
        assert_eq!(messages[0].summary, ItipSummary::Update);
        assert!(moved.to_string().contains("SEQUENCE:1"));

        // Bob taken off: cancelled for him.
        let text = ical.to_string().replace("\r\n ", "");
        let without = text.lines().filter(|line| !line.contains("bob@")).collect::<Vec<_>>().join("\r\n") + "\r\n";
        let mut without = ical::parse(&without).unwrap();
        let messages = update(&mut without, &ical, &alice()).unwrap();
        assert_eq!(messages[0].summary, ItipSummary::Cancel);
        assert_eq!(messages[0].to, ["bob@firma.example"]);

        let cancelled = cancel(&ical, &alice()).unwrap();
        assert!(cancelled.message.to_string().contains("STATUS:CANCELLED"));
        assert_eq!(cancelled.to, ["bob@firma.example"]);
    }

    #[test]
    fn an_attendee_answers_and_may_not_move_the_meeting() {
        let old = ical::parse(MEETING).unwrap();
        let accepted = MEETING.replace("RSVP=TRUE;PARTSTAT=NEEDS-ACTION:mailto:bob", "PARTSTAT=ACCEPTED:mailto:bob");
        let mut new = ical::parse(&accepted).unwrap();
        let messages = update(&mut new, &old, &bob()).unwrap();
        assert_eq!(messages[0].to, ["alice@firma.example"]);
        assert_eq!(messages[0].summary, ItipSummary::Rsvp { part_stat: "ACCEPTED".into() });
        let reply = messages[0].message.to_string();
        assert!(
            reply.contains("METHOD:REPLY") && reply.contains("ATTENDEE;PARTSTAT=ACCEPTED:mailto:bob@firma.example")
        );
        assert!(!reply.contains("carol"), "{reply}");

        let mut moved = ical::parse(&MEETING.replace("20261110T100000Z", "20261111T100000Z")).unwrap();
        assert_eq!(update(&mut moved, &old, &bob()).unwrap_err(), ItipError::CannotModifyInstance);
        let mut other =
            ical::parse(&MEETING.replace("ORGANIZER;CN=Alice:mailto:alice", "ORGANIZER:mailto:dave")).unwrap();
        assert_eq!(update(&mut other, &old, &bob()).unwrap_err(), ItipError::OrganizerMismatch);
        let declined = cancel(&old, &bob()).unwrap();
        assert!(declined.message.to_string().contains("PARTSTAT=DECLINED"));
    }

    #[test]
    fn received_messages_change_the_copies() {
        let mut organizer_copy = ical::parse(MEETING).unwrap();
        let invitation = create(&mut organizer_copy, &alice()).unwrap().remove(0).message;
        let Received::Store(bobs) = receive(None, &invitation, &bob(), "alice@firma.example").unwrap() else {
            panic!()
        };
        assert!(bobs.method().is_none());
        assert_eq!(
            receive(None, &invitation, &bob(), "mallory@evil.example").unwrap_err(),
            ItipError::SenderNotAllowed
        );

        let accepted =
            bobs.to_string().replace("RSVP=TRUE;PARTSTAT=NEEDS-ACTION:mailto:bob", "PARTSTAT=ACCEPTED:mailto:bob");
        let mut accepted = ical::parse(&accepted).unwrap();
        let reply = update(&mut accepted, &bobs, &bob()).unwrap().remove(0).message;
        let Received::Store(updated) = receive(Some(&organizer_copy), &reply, &alice(), "bob@firma.example").unwrap()
        else {
            panic!()
        };
        let text = updated.to_string().replace("\r\n ", "");
        let line = text.lines().find(|line| line.contains("mailto:bob@")).unwrap();
        assert!(line.contains("PARTSTAT=ACCEPTED"), "{line}");

        // The same version again keeps Bob's answer; a cancel cancels.
        let Received::Store(again) = receive(Some(&accepted), &invitation, &bob(), "alice@firma.example").unwrap()
        else {
            panic!()
        };
        assert!(again.to_string().contains("PARTSTAT=ACCEPTED:mailto:bob"));
        let cancel = cancel(&organizer_copy, &alice()).unwrap().message;
        let Received::Store(cancelled) = receive(Some(&accepted), &cancel, &bob(), "alice@firma.example").unwrap()
        else {
            panic!()
        };
        assert!(cancelled.to_string().contains("STATUS:CANCELLED"));
    }

    #[test]
    fn a_reply_for_one_instance_makes_an_override() {
        let series = MEETING.replace("DURATION:PT1H\r\n", "DURATION:PT1H\r\nRRULE:FREQ=DAILY;COUNT=3\r\n");
        let organizer_copy = ical::parse(&series).unwrap();
        let reply = "BEGIN:VCALENDAR\r\nMETHOD:REPLY\r\nBEGIN:VEVENT\r\nUID:m@firma\r\nRECURRENCE-ID:20261111T100000Z\r\n\
            ORGANIZER:mailto:alice@firma.example\r\nATTENDEE;PARTSTAT=DECLINED:mailto:bob@firma.example\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let reply = ical::parse(reply).unwrap();
        let Received::Store(updated) = receive(Some(&organizer_copy), &reply, &alice(), "bob@firma.example").unwrap()
        else {
            panic!()
        };
        assert_eq!(updated.schedulable().count(), 2);
        let instances = expand::expand(&updated, &TimeZone::UTC, None, 10).instances;
        assert_eq!(instances.len(), 3);
        assert_eq!(instances[1].end.as_second() - instances[1].start.as_second(), 3600);
    }
}
