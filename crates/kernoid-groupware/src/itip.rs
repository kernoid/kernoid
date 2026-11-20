// SPDX-License-Identifier: AGPL-3.0-or-later
//! Scheduling on the store (RFC 0004, 7): the messages an organizer's or attendee's change sends, and what a received
//! iTIP message does to the recipient's calendars – the decisions are `scheduling`'s, the storage is here.

use kernoid_pim::{Component, Property, ical};
use uuid::Uuid;

use crate::{
    Expect, Groupware, GroupwareError, Result, Written,
    scheduling::{self, ItipError, Received},
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

fn parse(text: &str) -> Option<Component> {
    ical::parse(text).ok()
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
            Some(old) => scheduling::update(&mut ical, &old, &addresses),
            None => scheduling::create(&mut ical, &addresses),
        };
        let messages = match messages {
            Ok(messages) => messages,
            Err(error) if nothing_to_schedule(&error) => {
                let written = self.put_event(account, calendar, name, text, expect).await?;
                return Ok(Ok(Scheduled { written, changed: false, sent: 0 }));
            }
            Err(ItipError::OrganizerMismatch) => {
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
        match scheduling::cancel(&old, &addresses) {
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
        let Some(mut itip) = parse(text).filter(|ical| ical.schedulable().next().is_some()) else {
            return Err(GroupwareError::Invalid("not an iTIP message".into()));
        };
        // Microsoft Exchange leaves the organizer out of replies: it is the recipient (checked against the event).
        if matches!(itip.method().as_deref(), Some("REPLY" | "REQUEST"))
            && let Some(own) = addresses.first()
        {
            for component in itip.schedulable_mut() {
                if component.property("ATTENDEE").is_some() && component.property("ORGANIZER").is_none() {
                    component.properties.push(Property::new("ORGANIZER", format!("mailto:{own}")));
                }
            }
        }
        let uid =
            scheduling::uid(&itip).ok_or_else(|| GroupwareError::Invalid("an iTIP message without UID".into()))?;
        if !scheduling::sender_allowed(&itip, &sender) {
            return Err(GroupwareError::Invalid("the sender is neither organizer nor attendee".into()));
        }
        let existing = self.events_by_uid(account, &uid).await?.into_iter().next();
        let stored = match &existing {
            Some(event) => {
                let Some((_, stored)) = self.event_data(account, &[event.id]).await?.pop() else {
                    return Err(GroupwareError::NotFound("the event"));
                };
                Some(parse(&stored).ok_or(GroupwareError::Unreadable)?)
            }
            None => None,
        };
        if existing.is_none() && itip.method().as_deref() != Some("REQUEST") {
            return Err(GroupwareError::NotFound("the event"));
        }
        match scheduling::receive(stored.as_ref(), &itip, &addresses, &sender).map_err(scheduling)? {
            Received::Store(object) => {
                let text = object.to_string();
                match existing {
                    Some(event) => {
                        self.replace_event(account, event.id, &text, true).await?;
                        self.notify(account, Some(event.id), "updated", &sender, &itip).await?;
                    }
                    None => {
                        let calendar = self.default_calendar(account).await?.id;
                        let event = self.create_event(account, calendar, &text).await?;
                        self.notify(account, Some(event.id), "created", &sender, &itip).await?;
                    }
                }
                Ok(0)
            }
            Received::Send(message) => self.send_itip(account, vec![message]).await,
            Received::Nothing => Ok(0),
        }
    }
}

fn scheduling(error: ItipError) -> GroupwareError {
    GroupwareError::Invalid(format!("scheduling: {error:?}"))
}
