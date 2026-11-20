// SPDX-License-Identifier: AGPL-3.0-or-later
//! Whole calendars and address books in and out (RFC 0004, 9): one iCalendar file (`.ics`) with every event of a
//! calendar, one vCard file (`.vcf`) with every contact of an address book. An import splits the file by UID into
//! objects and stores each as a client would; one that is there already is replaced.

use std::collections::BTreeMap;

use kernoid_pim::{Component, Property, ical, vcard};
use uuid::Uuid;

use crate::{Expect, Groupware, GroupwareError, Result};

/// What an import did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Imported {
    pub stored: usize,
    /// Objects that could not be stored, with why.
    pub refused: Vec<(String, String)>,
}

impl Groupware {
    /// Every event of a calendar in one iCalendar object; time zones once each.
    pub async fn export_calendar(&self, account: Uuid, calendar: Uuid) -> Result<String> {
        self.calendar(account, calendar).await?;
        let ids: Vec<Uuid> = self.events(account, calendar).await?.into_iter().map(|event| event.id).collect();
        let mut out = Component::calendar(crate::PROD_ID);
        let mut zones: BTreeMap<String, Component> = BTreeMap::new();
        let mut components = Vec::new();
        for (_, text) in self.event_data(account, &ids).await? {
            let Ok(calendar) = ical::parse(&text) else { continue };
            for component in calendar.components {
                if component.is("VTIMEZONE") {
                    let tzid = component.text("TZID").unwrap_or_default();
                    zones.entry(tzid).or_insert(component);
                } else {
                    components.push(component);
                }
            }
        }
        out.components.extend(zones.into_values());
        out.components.extend(components);
        Ok(out.to_string())
    }

    /// Stores the events of an iCalendar file in a calendar, one object per UID with the time zones it may need.
    pub async fn import_calendar(&self, account: Uuid, calendar: Uuid, text: &str) -> Result<Imported> {
        self.calendar(account, calendar).await?;
        let calendars = ical::parse_all(text).map_err(|_| GroupwareError::Invalid("not an iCalendar file".into()))?;
        let mut zones: Vec<Component> = Vec::new();
        let mut by_uid: BTreeMap<String, Vec<Component>> = BTreeMap::new();
        let mut imported = Imported::default();
        for calendar_block in calendars {
            for component in calendar_block.components {
                if component.is("VTIMEZONE") {
                    zones.push(component);
                } else if component.is_schedulable() {
                    match component.uid() {
                        Some(uid) => by_uid.entry(uid).or_default().push(component),
                        None => imported.refused.push((component.name.clone(), "no UID".into())),
                    }
                }
            }
        }
        if by_uid.is_empty() && imported.refused.is_empty() {
            return Err(GroupwareError::Invalid("no events in the file".into()));
        }
        for (uid, components) in by_uid {
            let mut object = Component::calendar(crate::PROD_ID);
            object.components.extend(zones.iter().cloned());
            object.components.extend(components);
            let object = object.to_string();
            let existing =
                self.events_by_uid(account, &uid).await?.into_iter().find(|event| event.calendar == calendar);
            let result = match existing {
                Some(event) => self.replace_event(account, event.id, &object, false).await.map(|_| ()),
                None => self.create_event(account, calendar, &object).await.map(|_| ()),
            };
            match result {
                Ok(()) => imported.stored += 1,
                Err(error @ (GroupwareError::Invalid(_) | GroupwareError::TooLarge { .. })) => {
                    imported.refused.push((uid, error.to_string()));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(imported)
    }

    /// Every contact of an address book in one vCard file.
    pub async fn export_addressbook(&self, account: Uuid, addressbook: Uuid) -> Result<String> {
        self.addressbook(account, addressbook).await?;
        let ids: Vec<Uuid> =
            self.contacts(account, Some(addressbook)).await?.into_iter().map(|contact| contact.id).collect();
        let mut out = String::new();
        for (_, text) in self.contact_data(account, &ids).await? {
            for card in vcard::parse_all(&text).unwrap_or_default() {
                out.push_str(&card.to_string());
            }
        }
        Ok(out)
    }

    /// Stores the vCards of a file in an address book; one without a UID gets one.
    pub async fn import_addressbook(&self, account: Uuid, addressbook: Uuid, text: &str) -> Result<Imported> {
        self.addressbook(account, addressbook).await?;
        let mut imported = Imported::default();
        let cards = vcard::parse_all(text).map_err(|_| GroupwareError::Invalid("not a vCard file".into()))?;
        if cards.is_empty() {
            return Err(GroupwareError::Invalid("no contacts in the file".into()));
        }
        for mut card in cards {
            let uid = match card.uid() {
                Some(uid) => uid,
                None => {
                    let uid = format!("urn:uuid:{}", Uuid::now_v7());
                    card.properties.insert(0, Property::text("UID", &uid));
                    uid
                }
            };
            let card = card.to_string();
            let name = crate::resource_name(&uid, Uuid::now_v7(), "vcf");
            let existing =
                self.contacts(account, Some(addressbook)).await?.into_iter().find(|contact| contact.uid == uid);
            let result = match existing {
                Some(contact) => self.replace_contact(account, contact.id, &card).await.map(|_| ()),
                None => self.put_contact(account, addressbook, &name, &card, Expect::New).await.map(|_| ()),
            };
            match result {
                Ok(()) => imported.stored += 1,
                Err(
                    error @ (GroupwareError::Invalid(_)
                    | GroupwareError::TooLarge { .. }
                    | GroupwareError::PreconditionFailed),
                ) => {
                    imported.refused.push((uid, error.to_string()));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(imported)
    }
}
