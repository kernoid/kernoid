// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a path names once it is looked up (RFC 0004, 8.1): principals, homes, collections – the user's own and those
//! shared with it, which appear in its home as `shared-<id>` – and objects, with the user's level on each.

use kernoid_groupware::{
    AddressBookInfo, CalendarInfo, CollectionType, ContactInfo, EventInfo, GroupwareError, Level, PrincipalInfo,
};
use uuid::Uuid;

use crate::{
    Dav, Error,
    path::{self, Target},
};

#[derive(Debug, Clone)]
pub(crate) enum Collection {
    Calendar { owner: Uuid, segment: String, level: Level, info: CalendarInfo },
    Inbox { owner: Uuid },
    Outbox { owner: Uuid },
    Addressbook { owner: Uuid, segment: String, level: Level, info: AddressBookInfo },
}

#[derive(Debug, Clone)]
pub(crate) enum Node {
    Root,
    Principals,
    Principal(PrincipalInfo),
    CalendarHome,
    AddressbookHome,
    Collection(Collection),
    Event(Collection, EventInfo),
    Contact(Collection, ContactInfo),
}

/// The segment a shared collection has in the grantee's home.
pub(crate) fn shared_segment(id: Uuid) -> String {
    format!("shared-{id}")
}

impl Collection {
    pub fn owner(&self) -> Uuid {
        match self {
            Self::Calendar { owner, .. }
            | Self::Inbox { owner }
            | Self::Outbox { owner }
            | Self::Addressbook { owner, .. } => *owner,
        }
    }

    /// The calendar's or address book's id.
    pub fn id(&self) -> Option<Uuid> {
        match self {
            Self::Calendar { info, .. } => Some(info.id),
            Self::Addressbook { info, .. } => Some(info.id),
            _ => None,
        }
    }

    pub fn level(&self) -> Level {
        match self {
            Self::Calendar { level, .. } | Self::Addressbook { level, .. } => *level,
            Self::Inbox { .. } | Self::Outbox { .. } => Level::Admin,
        }
    }

    pub fn is_calendar(&self) -> bool {
        !matches!(self, Self::Addressbook { .. })
    }

    /// Its href in the home of `user`.
    pub fn href(&self, user: Uuid) -> String {
        match self {
            Self::Calendar { segment, .. } => format!("{}{}/", path::calendar_home(user), path::encode(segment)),
            Self::Inbox { .. } => format!("{}inbox/", path::calendar_home(user)),
            Self::Outbox { .. } => format!("{}outbox/", path::calendar_home(user)),
            Self::Addressbook { segment, .. } => format!("{}{}/", path::addressbook_home(user), path::encode(segment)),
        }
    }
}

impl Node {
    pub fn href(&self, user: Uuid) -> String {
        match self {
            Self::Root => format!("{}/", path::BASE),
            Self::Principals => format!("{}/principals/", path::BASE),
            Self::Principal(principal) => path::principal(principal.id),
            Self::CalendarHome => path::calendar_home(user),
            Self::AddressbookHome => path::addressbook_home(user),
            Self::Collection(collection) => collection.href(user),
            Self::Event(collection, event) => {
                format!("{}{}", collection.href(user), path::encode(&event.resource_name))
            }
            Self::Contact(collection, contact) => {
                format!("{}{}", collection.href(user), path::encode(&contact.resource_name))
            }
        }
    }

    pub fn is_collection(&self) -> bool {
        !matches!(self, Self::Event(..) | Self::Contact(..))
    }
}

impl Dav {
    /// Looks a path up for `user`: only its own homes, principals of its tenant.
    pub(crate) async fn resolve(&self, user: &PrincipalInfo, target: &Target) -> Result<Node, Error> {
        let own = |home: &Uuid| if *home == user.id { Ok(()) } else { Err(Error::Forbidden) };
        Ok(match target {
            Target::Root => Node::Root,
            Target::Principals => Node::Principals,
            Target::Principal(id) => {
                let principal = self.groupware.principal(*id).await.map_err(|_| Error::NotFound)?;
                if principal.tenant != user.tenant {
                    return Err(Error::NotFound);
                }
                Node::Principal(principal)
            }
            Target::CalendarHome(home) => {
                own(home)?;
                Node::CalendarHome
            }
            Target::AddressbookHome(home) => {
                own(home)?;
                Node::AddressbookHome
            }
            Target::Calendar(home, segment) => {
                own(home)?;
                Node::Collection(self.calendar_collection(user.id, segment).await?)
            }
            Target::Addressbook(home, segment) => {
                own(home)?;
                Node::Collection(self.addressbook_collection(user.id, segment).await?)
            }
            Target::CalendarObject(home, segment, name) => {
                own(home)?;
                let collection = self.calendar_collection(user.id, segment).await?;
                let Collection::Calendar { owner, info, .. } = &collection else { return Err(Error::NotFound) };
                let event = self.groupware.event_by_name(*owner, info.id, name).await?.ok_or(Error::NotFound)?;
                Node::Event(collection, event)
            }
            Target::Contact(home, segment, name) => {
                own(home)?;
                let collection = self.addressbook_collection(user.id, segment).await?;
                let Collection::Addressbook { owner, info, .. } = &collection else { return Err(Error::NotFound) };
                let contact = self.groupware.contact_by_name(*owner, info.id, name).await?.ok_or(Error::NotFound)?;
                Node::Contact(collection, contact)
            }
        })
    }

    pub(crate) async fn calendar_collection(&self, user: Uuid, segment: &str) -> Result<Collection, Error> {
        match segment {
            "inbox" => return Ok(Collection::Inbox { owner: user }),
            "outbox" => return Ok(Collection::Outbox { owner: user }),
            _ => {}
        }
        if let Some(id) = segment.strip_prefix("shared-").and_then(|id| Uuid::parse_str(id).ok()) {
            let shared = self.groupware.shared_with(user).await?;
            let found = shared
                .into_iter()
                .find(|shared| {
                    shared.collection == id
                        && shared.collection_type == CollectionType::Calendar
                        && shared.level >= Level::Read
                })
                .ok_or(Error::NotFound)?;
            let info = self.groupware.calendar(found.owner, id).await?;
            return Ok(Collection::Calendar { owner: found.owner, segment: segment.into(), level: found.level, info });
        }
        let info = self.groupware.calendar_by_name(user, segment).await?.ok_or(Error::NotFound)?;
        Ok(Collection::Calendar { owner: user, segment: segment.into(), level: Level::Admin, info })
    }

    pub(crate) async fn addressbook_collection(&self, user: Uuid, segment: &str) -> Result<Collection, Error> {
        if let Some(id) = segment.strip_prefix("shared-").and_then(|id| Uuid::parse_str(id).ok()) {
            let shared = self.groupware.shared_with(user).await?;
            let found = shared
                .into_iter()
                .find(|shared| shared.collection == id && shared.collection_type == CollectionType::AddressBook)
                .ok_or(Error::NotFound)?;
            let info = self.groupware.addressbook(found.owner, id).await?;
            return Ok(Collection::Addressbook {
                owner: found.owner,
                segment: segment.into(),
                level: found.level,
                info,
            });
        }
        let info = self.groupware.addressbook_by_name(user, segment).await?.ok_or(Error::NotFound)?;
        Ok(Collection::Addressbook { owner: user, segment: segment.into(), level: Level::Admin, info })
    }

    /// The collections in a home: the user's own and those shared with it at `read` or more.
    pub(crate) async fn home_collections(&self, user: Uuid, calendars: bool) -> Result<Vec<Collection>, Error> {
        let mut collections = Vec::new();
        if calendars {
            for info in self.groupware.calendars(user).await? {
                collections.push(Collection::Calendar {
                    owner: user,
                    segment: info.resource_name.clone(),
                    level: Level::Admin,
                    info,
                });
            }
            collections.push(Collection::Inbox { owner: user });
            collections.push(Collection::Outbox { owner: user });
        } else {
            for info in self.groupware.addressbooks(user).await? {
                collections.push(Collection::Addressbook {
                    owner: user,
                    segment: info.resource_name.clone(),
                    level: Level::Admin,
                    info,
                });
            }
        }
        for shared in self.groupware.shared_with(user).await? {
            if shared.level < Level::Read {
                continue;
            }
            match (shared.collection_type, calendars) {
                (CollectionType::Calendar, true) => {
                    let Ok(info) = self.groupware.calendar(shared.owner, shared.collection).await else { continue };
                    collections.push(Collection::Calendar {
                        owner: shared.owner,
                        segment: shared_segment(shared.collection),
                        level: shared.level,
                        info,
                    });
                }
                (CollectionType::AddressBook, false) => {
                    let Ok(info) = self.groupware.addressbook(shared.owner, shared.collection).await else { continue };
                    collections.push(Collection::Addressbook {
                        owner: shared.owner,
                        segment: shared_segment(shared.collection),
                        level: shared.level,
                        info,
                    });
                }
                _ => {}
            }
        }
        Ok(collections)
    }
}

impl From<GroupwareError> for Error {
    fn from(error: GroupwareError) -> Self {
        Error::Groupware(error)
    }
}
