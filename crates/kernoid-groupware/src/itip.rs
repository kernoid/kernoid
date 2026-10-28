// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
//! Scheduling on the store (RFC 0004, 7): the messages an organizer's or attendee's change sends, and what a received
//! iTIP message does to the recipient's calendars. The flow of receiving follows Stalwart's
//! `crates/groupware/src/calendar/itip.rs` (v0.16.27); the storage is kernoid's.

use calcard::{
    Entry, Parser,
    icalendar::{
        ICalendar, ICalendarComponentType, ICalendarEntry, ICalendarMethod, ICalendarProperty, ICalendarValue,
    },
};
use uuid::Uuid;

use crate::{
    Expect, Groupware, GroupwareError, Result, Written,
    scheduling::{
        ItipError,
        event_cancel::itip_cancel,
        event_create::itip_create,
        event_update::itip_update,
        inbound::{MergeResult, itip_import_message, itip_merge_changes, itip_method, itip_process_message},
        snapshot::itip_snapshot,
    },
};

/// What a write that may schedule did.
#[derive(Debug)]
pub struct Scheduled {
    pub written: Written,
    /// Scheduling changed the object (`SEQUENCE`, `SCHEDULE-STATUS`, …): the stored one is not what the client sent,
    /// so it gets no ETag (RFC 4791, 5.3.4).
    pub changed: bool,
    /// Messages queued.
    pub sent: usize,
}

/// A scheduling rule a write broke (RFC 6638, 3.2.2): the client is told which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleRefusal {
    OrganizerChange,
    AttendeeChange,
}

fn parse(text: &str) -> Option<ICalendar> {
    match Parser::new(text).entry() {
        Entry::ICalendar(ical) => Some(ical),
        _ => None,
    }
}

/// Whether a scheduling error only means "nothing to schedule", so that the object is stored as sent.
fn nothing_to_schedule(error: &ItipError) -> bool {
    matches!(
        error,
        ItipError::NoSchedulingInfo
            | ItipError::NotOrganizer
            | ItipError::NotOrganizerNorAttendee
            | ItipError::OtherSchedulingAgent
            | ItipError::NothingToSend
    )
}

impl Groupware {
    /// Stores an iCalendar object under `name` (CalDAV `PUT`) and sends what scheduling asks for: invitations and
    /// updates when the account organizes the event, answers when it attends.
    pub async fn put_event_scheduled(
        &self,
        account: Uuid,
        calendar: Uuid,
        name: &str,
        text: &str,
        expect: Expect,
    ) -> Result<std::result::Result<Scheduled, ScheduleRefusal>> {
        let addresses = self.principal(account).await?.addresses;
        let old = match self.event_by_name(account, calendar, name).await? {
            Some(event) => self.event_data(account, &[event.id]).await?.pop().map(|(_, text)| text),
            None => None,
        };
        let Some(mut ical) = parse(text) else {
            return Err(GroupwareError::Invalid("not an iCalendar object".into()));
        };
        let messages = match old.as_deref().and_then(parse) {
            Some(old) => itip_update(&mut ical, &old, &addresses),
            None => itip_create(&mut ical, &addresses),
        };
        let messages = match messages {
            Ok(messages) => messages,
            Err(error) if nothing_to_schedule(&error) => {
                let written = self.put_event(account, calendar, name, text, expect).await?;
                return Ok(Ok(Scheduled { written, changed: false, sent: 0 }));
            }
            Err(ItipError::OrganizerMismatch | ItipError::CannotModifyAddress) => {
                return Ok(Err(ScheduleRefusal::OrganizerChange));
            }
            Err(ItipError::CannotModifyProperty(_) | ItipError::CannotModifyInstance) => {
                return Ok(Err(ScheduleRefusal::AttendeeChange));
            }
            Err(error) => return Err(GroupwareError::Invalid(format!("scheduling: {error:?}"))),
        };
        let changed_text = ical.to_string();
        let mut written = self.put_event(account, calendar, name, &changed_text, expect).await?;
        written.event = self.replace_event(account, written.event.id, &changed_text, true).await?;
        let sent = self.send_itip(account, messages).await?;
        Ok(Ok(Scheduled { written, changed: true, sent }))
    }

    /// Destroys an event (CalDAV `DELETE`) and sends what scheduling asks for: a cancellation to the attendees when
    /// the account organizes it, a decline to the organizer when it attends.
    pub async fn destroy_event_scheduled(&self, account: Uuid, id: Uuid, expect: Expect) -> Result<usize> {
        let addresses = self.principal(account).await?.addresses;
        let old = self.event_data(account, &[id]).await?.pop().map(|(_, text)| text);
        self.destroy_event(account, id, expect).await?;
        let Some(old) = old.as_deref().and_then(parse) else { return Ok(0) };
        match itip_cancel(&old, &addresses, true) {
            Ok(message) => self.send_itip(account, vec![message]).await,
            Err(_) => Ok(0),
        }
    }

    /// Applies an iTIP message the account received by mail from `sender` – whose address the caller verified – to
    /// its calendars (RFC 0004, 7); returns the messages to send in turn (such as an answer to a refresh).
    pub async fn receive_itip(&self, account: Uuid, sender: &str, text: &str) -> Result<usize> {
        let principal = self.principal(account).await?;
        let addresses = principal.addresses;
        let sender = sender.to_lowercase();
        let Some(mut itip) = parse(text).filter(|ical| {
            ical.components.len() > 1 && ical.components[0].component_type == ICalendarComponentType::VCalendar
        }) else {
            return Err(GroupwareError::Invalid("not an iTIP message".into()));
        };
        // Microsoft Exchange leaves the organizer out of replies: it is the recipient (checked against the event).
        let method = itip.components[0]
            .property(&ICalendarProperty::Method)
            .and_then(|entry| entry.values.first())
            .and_then(|value| value.as_text())
            .map(str::to_ascii_uppercase);
        if matches!(method.as_deref(), Some("REPLY" | "REQUEST"))
            && let Some(own) = addresses.first()
        {
            for component in &mut itip.components {
                if component.component_type.is_scheduling_object()
                    && component.entries.iter().any(|entry| entry.name == ICalendarProperty::Attendee)
                    && !component.entries.iter().any(|entry| entry.name == ICalendarProperty::Organizer)
                {
                    component.entries.push(ICalendarEntry {
                        name: ICalendarProperty::Organizer,
                        params: vec![],
                        values: vec![ICalendarValue::Text(format!("mailto:{own}"))],
                    });
                }
            }
        }
        let itip_snapshots = itip_snapshot(&itip, &addresses, false).map_err(scheduling)?;
        if !itip_snapshots.sender_is_organizer_or_attendee(&sender) {
            return Err(GroupwareError::Invalid("the sender is neither organizer nor attendee".into()));
        }
        let uid = itip_snapshots.uid.to_string();
        let existing = self.events_by_uid(account, &uid).await?.into_iter().next();
        match existing {
            Some(event) => {
                let Some((_, stored)) = self.event_data(account, &[event.id]).await?.pop() else {
                    return Err(GroupwareError::NotFound("the event"));
                };
                let Some(mut ical) = parse(&stored) else { return Err(GroupwareError::Unreadable) };
                let snapshots = itip_snapshot(&ical, &addresses, false).map_err(scheduling)?;
                match itip_process_message(&ical, snapshots, &itip, itip_snapshots, sender.clone())
                    .map_err(scheduling)?
                {
                    MergeResult::Actions(changes) => {
                        itip_merge_changes(&mut ical, &itip, changes);
                        self.replace_event(account, event.id, &ical.to_string(), true).await?;
                        self.notify(account, Some(event.id), "updated", &sender, &itip).await?;
                        Ok(0)
                    }
                    MergeResult::Message(message) => self.send_itip(account, vec![message]).await,
                    MergeResult::None => Ok(0),
                }
            }
            None => {
                if itip_method(&itip).map_err(scheduling)? != &ICalendarMethod::Request {
                    return Err(GroupwareError::NotFound("the event"));
                }
                let mut ical = itip.clone();
                itip_import_message(&mut ical).map_err(scheduling)?;
                let calendar = self.default_calendar(account).await?.id;
                let event = self.create_event(account, calendar, &ical.to_string()).await?;
                self.notify(account, Some(event.id), "created", &sender, &itip).await?;
                Ok(0)
            }
        }
    }
}

fn scheduling(error: ItipError) -> GroupwareError {
    GroupwareError::Invalid(format!("scheduling: {error:?}"))
}
