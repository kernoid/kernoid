// SPDX-License-Identifier: AGPL-3.0-or-later
//! JMAP for Contacts (RFC 9610; RFC 0004, 8.2): `AddressBook/get`, `/changes`, `/set`; `ContactCard/get`,
//! `/changes`, `/query`, `/set`. Contacts are stored as vCard and shown as JSContact (`js`).

use kernoid_groupware::{
    AddressBookInfo, AddressBookUpdate, CollectionAccess, Expect, GroupwareError, Level, NewAddressBook, ObjectType,
};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    MAX_OBJECTS_IN_GET, MAX_OBJECTS_IN_SET, js,
    mailbox::{ids, invalid_properties, properties},
    request::{Context, MethodError, MethodResult},
};

/// A `SetError` for what the store refused.
pub(crate) fn set_error(error: &GroupwareError) -> Value {
    if matches!(
        error,
        GroupwareError::Store(_)
            | GroupwareError::Mail(kernoid_mail::MailError::Store(_) | kernoid_mail::MailError::Blob(_))
    ) {
        return crate::mailbox::internal_error(error);
    }
    let kind = match error {
        GroupwareError::NotFound(_) => "notFound",
        GroupwareError::Invalid(_) | GroupwareError::UidConflict(_) => "invalidProperties",
        GroupwareError::OverQuota => "overQuota",
        GroupwareError::TooLarge { .. } => "tooLarge",
        GroupwareError::NotEmpty => "addressBookHasContents",
        _ => "forbidden",
    };
    json!({ "type": kind, "description": error.to_string() })
}

fn forbidden(description: &str) -> Value {
    json!({ "type": "forbidden", "description": description })
}

const BOOK_PROPERTIES: [&str; 9] = [
    "id",
    "name",
    "description",
    "sortOrder",
    "isDefault",
    "isSubscribed",
    "shareWith",
    "myRights",
    "kernoid:collectionKey",
];

fn book_rights(access: &CollectionAccess, book: Uuid) -> Value {
    let level = access.level(book);
    let at_least = |wanted: Level| level.is_some_and(|level| level >= wanted);
    json!({
        "mayRead": at_least(Level::Read),
        "mayWrite": at_least(Level::Write),
        "mayShare": at_least(Level::Admin),
        "mayDelete": access.owned,
    })
}

fn book_object(book: &AddressBookInfo, access: &CollectionAccess, properties: &[String]) -> Value {
    let mut out = Map::new();
    for property in properties {
        let value = match property.as_str() {
            "name" => json!(book.name),
            "description" => json!(book.description),
            "sortOrder" => json!(book.sort_order),
            "isDefault" => json!(book.is_default && access.owned),
            "isSubscribed" => json!(book.is_subscribed),
            "shareWith" => Value::Null,
            "myRights" => book_rights(access, book.id),
            "kernoid:collectionKey" => crate::openpgp::b64_or_null(book.collection_key.as_deref()),
            _ => continue,
        };
        out.insert(property.clone(), value);
    }
    out.insert("id".into(), json!(book.id.to_string()));
    Value::Object(out)
}

impl Context<'_> {
    pub async fn addressbook_get(&self, args: Map<String, Value>) -> MethodResult {
        let (owner, access) = self.groupware_access(&args).await?;
        let groupware = self.groupware()?;
        let state = groupware.state(owner).await?;
        let wanted = ids(&args)?;
        let properties = properties(&args, "properties", &BOOK_PROPERTIES);
        let books: Vec<AddressBookInfo> = groupware
            .addressbooks(owner)
            .await?
            .into_iter()
            .filter(|book| access.allows(book.id, Level::Read))
            .collect();
        let mut list = Vec::new();
        let mut not_found = Vec::new();
        match wanted {
            None => list.extend(books.iter().map(|book| book_object(book, &access, &properties))),
            Some(wanted) => {
                if wanted.len() > MAX_OBJECTS_IN_GET {
                    return Err(MethodError::new("requestTooLarge", "too many ids"));
                }
                for id in wanted {
                    match books.iter().find(|book| book.id.to_string() == id) {
                        Some(book) => list.push(book_object(book, &access, &properties)),
                        None => not_found.push(id),
                    }
                }
            }
        }
        Ok(vec![(
            "AddressBook/get".into(),
            json!({ "accountId": owner.to_string(), "state": state.to_string(), "list": list, "notFound": not_found }),
        )])
    }

    pub async fn addressbook_set(&mut self, args: Map<String, Value>) -> MethodResult {
        let (owner, access) = self.groupware_access(&args).await?;
        let groupware = self.groupware()?.clone();
        let old_state = groupware.state(owner).await?;
        crate::mailbox::if_in_state(&args, old_state as u64)?;
        let mut created = Map::new();
        let mut not_created = Map::new();
        let mut updated = Map::new();
        let mut not_updated = Map::new();
        let mut destroyed = Vec::new();
        let mut not_destroyed = Map::new();
        let count = ["create", "update", "destroy"]
            .iter()
            .map(|key| {
                args.get(*key)
                    .map_or(0, |value| value.as_object().map_or(0, Map::len).max(value.as_array().map_or(0, Vec::len)))
            })
            .sum::<usize>();
        if count > MAX_OBJECTS_IN_SET {
            return Err(MethodError::new("requestTooLarge", "too many changes"));
        }
        if let Some(Value::Object(create)) = args.get("create") {
            for (creation, value) in create {
                if !access.owned {
                    not_created.insert(creation.clone(), forbidden("only the owner creates address books"));
                    continue;
                }
                let Some(object) = value.as_object() else {
                    not_created.insert(creation.clone(), invalid_properties("an object"));
                    continue;
                };
                let Some(name) = object.get("name").and_then(Value::as_str) else {
                    not_created.insert(creation.clone(), invalid_properties("name is required"));
                    continue;
                };
                let new = NewAddressBook {
                    resource_name: None,
                    name: name.to_owned(),
                    description: object.get("description").and_then(Value::as_str).map(str::to_owned),
                    sort_order: object.get("sortOrder").and_then(Value::as_i64).unwrap_or(0),
                    is_default: false,
                };
                let made = groupware.create_addressbook(owner, new).await;
                let made = match made {
                    Ok(id) => crate::openpgp::seal_new(&groupware, owner, self.caller.account, id, object).await,
                    Err(error) => Err(error),
                };
                match made {
                    Ok(id) => {
                        self.created.insert(creation.clone(), id.to_string());
                        created.insert(creation.clone(), json!({ "id": id.to_string(), "isDefault": false }));
                    }
                    Err(error) => {
                        not_created.insert(creation.clone(), set_error(&error));
                    }
                }
            }
        }
        if let Some(Value::Object(update)) = args.get("update") {
            for (id, value) in update {
                let Some(book) = self.id(id) else {
                    not_updated.insert(id.clone(), json!({ "type": "notFound" }));
                    continue;
                };
                if !access.allows(book, Level::Admin) {
                    not_updated.insert(id.clone(), forbidden("this needs the right to share"));
                    continue;
                }
                let Some(patch) = value.as_object() else {
                    not_updated.insert(id.clone(), invalid_properties("an object"));
                    continue;
                };
                let update = AddressBookUpdate {
                    name: patch.get("name").and_then(Value::as_str).map(str::to_owned),
                    description: patch.get("description").map(|value| value.as_str().map(str::to_owned)),
                    sort_order: patch.get("sortOrder").and_then(Value::as_i64),
                    is_default: patch.get("isDefault").and_then(Value::as_bool).filter(|_| access.owned),
                    is_subscribed: patch.get("isSubscribed").and_then(Value::as_bool),
                };
                match groupware.update_addressbook(owner, book, update).await {
                    Ok(()) => {
                        updated.insert(id.clone(), Value::Null);
                    }
                    Err(error) => {
                        not_updated.insert(id.clone(), set_error(&error));
                    }
                }
            }
        }
        if let Some(Value::Array(destroy)) = args.get("destroy") {
            let remove = args.get("onDestroyRemoveContents").and_then(Value::as_bool).unwrap_or(false);
            for id in destroy.iter().filter_map(Value::as_str) {
                let Some(book) = self.id(id) else {
                    not_destroyed.insert(id.to_owned(), json!({ "type": "notFound" }));
                    continue;
                };
                if !access.owned {
                    not_destroyed.insert(id.to_owned(), forbidden("only the owner destroys address books"));
                    continue;
                }
                match groupware.destroy_addressbook(owner, book, remove).await {
                    Ok(()) => destroyed.push(id.to_owned()),
                    Err(error) => {
                        not_destroyed.insert(id.to_owned(), set_error(&error));
                    }
                }
            }
        }
        // onSuccessSetIsDefault: the first created or updated one that asked for it.
        if let Some(target) = args.get("onSuccessSetIsDefault").and_then(Value::as_str)
            && access.owned
            && let Some(book) = self.id(target)
        {
            let _ = groupware
                .update_addressbook(owner, book, AddressBookUpdate { is_default: Some(true), ..Default::default() })
                .await;
        }
        let new_state = groupware.state(owner).await?;
        Ok(vec![(
            "AddressBook/set".into(),
            json!({
                "accountId": owner.to_string(),
                "oldState": old_state.to_string(),
                "newState": new_state.to_string(),
                "created": created, "notCreated": not_created,
                "updated": updated, "notUpdated": not_updated,
                "destroyed": destroyed, "notDestroyed": not_destroyed,
            }),
        )])
    }

    /// `*/changes` of calendars and contacts.
    pub async fn groupware_changes(&self, args: Map<String, Value>, kind: ObjectType, name: &str) -> MethodResult {
        let (owner, _) = self.groupware_access(&args).await?;
        let since = args
            .get("sinceState")
            .and_then(Value::as_str)
            .and_then(|state| state.parse::<i64>().ok())
            .ok_or_else(|| MethodError::new("cannotCalculateChanges", "unknown state"))?;
        let max = args.get("maxChanges").and_then(Value::as_u64).map(|max| max as usize);
        if max == Some(0) {
            return Err(MethodError::invalid("maxChanges must be positive"));
        }
        let changes = self.groupware()?.changes(owner, kind, since, max).await?;
        let ids = |ids: Vec<Uuid>| ids.into_iter().map(|id| id.to_string()).collect::<Vec<_>>();
        let mut response = json!({
            "accountId": owner.to_string(),
            "oldState": changes.old_state.to_string(),
            "newState": changes.new_state.to_string(),
            "hasMoreChanges": changes.has_more_changes,
            "created": ids(changes.created),
            "updated": ids(changes.updated),
            "destroyed": ids(changes.destroyed),
        });
        if matches!(kind, ObjectType::Calendar | ObjectType::AddressBook) {
            response["updatedProperties"] = Value::Null;
        }
        Ok(vec![(name.to_owned(), response)])
    }

    pub async fn contact_get(&self, args: Map<String, Value>) -> MethodResult {
        let (owner, access) = self.groupware_access(&args).await?;
        let groupware = self.groupware()?;
        let state = groupware.state(owner).await?;
        let wanted = match ids(&args)? {
            Some(wanted) => {
                if wanted.len() > MAX_OBJECTS_IN_GET {
                    return Err(MethodError::new("requestTooLarge", "too many ids"));
                }
                wanted
            }
            None => groupware
                .contacts(owner, None)
                .await?
                .into_iter()
                .filter(|contact| access.allows(contact.addressbook, Level::Read))
                .take(MAX_OBJECTS_IN_GET)
                .map(|contact| contact.id.to_string())
                .collect(),
        };
        let selected: Option<Vec<String>> = match args.get("properties") {
            Some(Value::Array(list)) => Some(list.iter().filter_map(Value::as_str).map(str::to_owned).collect()),
            _ => None,
        };
        let uuids: Vec<Uuid> = wanted.iter().filter_map(|id| Uuid::parse_str(id).ok()).collect();
        let data = groupware.contact_data(owner, &uuids).await?;
        let mut list = Vec::new();
        let mut not_found = Vec::new();
        for id in wanted {
            let found = data.iter().find(|(contact, _)| contact.id.to_string() == id);
            let Some((contact, text)) = found.filter(|(contact, _)| access.allows(contact.addressbook, Level::Read))
            else {
                not_found.push(id);
                continue;
            };
            let Some(mut card) = js::card_to_json(text) else {
                not_found.push(id);
                continue;
            };
            card.insert("id".into(), json!(contact.id.to_string()));
            card.insert("addressBookIds".into(), json!({ contact.addressbook.to_string(): true }));
            if let Some(selected) = &selected {
                card.retain(|key, _| key == "id" || selected.iter().any(|wanted| wanted == key));
            }
            list.push(Value::Object(card));
        }
        Ok(vec![(
            "ContactCard/get".into(),
            json!({ "accountId": owner.to_string(), "state": state.to_string(), "list": list, "notFound": not_found }),
        )])
    }

    pub async fn contact_query(&self, args: Map<String, Value>) -> MethodResult {
        let (owner, access) = self.groupware_access(&args).await?;
        let groupware = self.groupware()?;
        let state = groupware.state(owner).await?;
        let filter = args.get("filter").and_then(Value::as_object).cloned().unwrap_or_default();
        let in_book = filter.get("inAddressBook").and_then(Value::as_str).and_then(|id| Uuid::parse_str(id).ok());
        let uid = filter.get("uid").and_then(Value::as_str);
        let email = filter.get("email").and_then(Value::as_str).map(str::to_lowercase);
        let text = filter.get("text").or_else(|| filter.get("name")).and_then(Value::as_str).map(str::to_lowercase);
        let contacts: Vec<_> = groupware
            .contacts(owner, in_book)
            .await?
            .into_iter()
            .filter(|contact| access.allows(contact.addressbook, Level::Read))
            .filter(|contact| uid.is_none_or(|uid| contact.uid == uid))
            .filter(|contact| email.as_ref().is_none_or(|email| contact.emails.iter().any(|e| e.contains(email))))
            .collect();
        // Text is in the sealed vCards: those left are opened (RFC 0004, 3), and their values searched.
        let mut ids = Vec::new();
        if let Some(text) = &text {
            let wanted: Vec<Uuid> = contacts.iter().map(|contact| contact.id).collect();
            for (contact, card) in groupware.contact_data(owner, &wanted).await? {
                if js::card_text(&card).contains(text.as_str()) {
                    ids.push(contact.id.to_string());
                }
            }
        } else {
            ids = contacts.iter().map(|contact| contact.id.to_string()).collect();
        }
        let total = ids.len();
        let position = args.get("position").and_then(Value::as_i64).unwrap_or(0).max(0) as usize;
        let limit = args.get("limit").and_then(Value::as_u64).map_or(usize::MAX, |limit| limit as usize);
        let page: Vec<String> = ids.into_iter().skip(position).take(limit).collect();
        Ok(vec![(
            "ContactCard/query".into(),
            json!({
                "accountId": owner.to_string(),
                "queryState": state.to_string(),
                "canCalculateChanges": false,
                "position": position,
                "ids": page,
                "total": total,
            }),
        )])
    }

    pub async fn contact_set(&mut self, args: Map<String, Value>) -> MethodResult {
        let (owner, access) = self.groupware_access(&args).await?;
        let groupware = self.groupware()?.clone();
        let old_state = groupware.state(owner).await?;
        crate::mailbox::if_in_state(&args, old_state as u64)?;
        let mut created = Map::new();
        let mut not_created = Map::new();
        let mut updated = Map::new();
        let mut not_updated = Map::new();
        let mut destroyed = Vec::new();
        let mut not_destroyed = Map::new();
        let default_book = groupware.addressbooks(owner).await?.into_iter().find(|book| book.is_default).map(|b| b.id);
        if let Some(Value::Object(create)) = args.get("create") {
            for (creation, value) in create {
                let Some(mut object) = value.as_object().cloned() else {
                    not_created.insert(creation.clone(), invalid_properties("an object"));
                    continue;
                };
                let book = match object.remove("addressBookIds") {
                    Some(Value::Object(books)) if books.len() == 1 => books.keys().next().and_then(|id| self.id(id)),
                    None => default_book,
                    _ => {
                        not_created.insert(creation.clone(), invalid_properties("one address book per contact"));
                        continue;
                    }
                };
                let Some(book) = book.filter(|book| access.allows(*book, Level::Write)) else {
                    not_created.insert(creation.clone(), forbidden("the address book may not be written"));
                    continue;
                };
                object.remove("id");
                object.entry("@type").or_insert(json!("Card"));
                object.entry("version").or_insert(json!("1.0"));
                object.entry("uid").or_insert_with(|| json!(format!("urn:uuid:{}", Uuid::now_v7())));
                let result = match js::json_to_card(&object) {
                    Ok(card) => groupware.create_contact(owner, book, &card).await.map_err(|error| set_error(&error)),
                    Err(error) => Err(invalid_properties(error)),
                };
                match result {
                    Ok(contact) => {
                        self.created.insert(creation.clone(), contact.id.to_string());
                        created.insert(creation.clone(), json!({ "id": contact.id.to_string(), "uid": contact.uid }));
                    }
                    Err(error) => {
                        not_created.insert(creation.clone(), error);
                    }
                }
            }
        }
        if let Some(Value::Object(update)) = args.get("update") {
            for (id, value) in update {
                let result: Result<(), Value> = async {
                    let contact_id = self.id(id).ok_or_else(|| json!({ "type": "notFound" }))?;
                    let patch = value.as_object().ok_or_else(|| invalid_properties("an object"))?;
                    let (contact, text) = groupware
                        .contact_data(owner, &[contact_id])
                        .await
                        .map_err(|error| set_error(&error))?
                        .pop()
                        .ok_or_else(|| json!({ "type": "notFound" }))?;
                    if !access.allows(contact.addressbook, Level::Write) {
                        return Err(forbidden("the address book may not be written"));
                    }
                    let mut patch = patch.clone();
                    let target = match patch.remove("addressBookIds") {
                        Some(Value::Object(books)) if books.len() == 1 => {
                            books.keys().next().and_then(|id| self.id(id))
                        }
                        Some(_) => return Err(invalid_properties("one address book per contact")),
                        None => None,
                    };
                    if !patch.is_empty() {
                        let mut card = js::card_to_json(&text).ok_or_else(|| invalid_properties("unreadable"))?;
                        js::patch(&mut card, &patch).map_err(invalid_properties)?;
                        let text = js::json_to_card(&card).map_err(invalid_properties)?;
                        groupware.replace_contact(owner, contact_id, &text).await.map_err(|error| set_error(&error))?;
                    }
                    if let Some(target) = target.filter(|target| *target != contact.addressbook) {
                        if !access.allows(target, Level::Write) {
                            return Err(forbidden("the address book may not be written"));
                        }
                        groupware
                            .move_contact(owner, contact_id, target, None)
                            .await
                            .map_err(|error| set_error(&error))?;
                    }
                    Ok(())
                }
                .await;
                match result {
                    Ok(()) => {
                        updated.insert(id.clone(), Value::Null);
                    }
                    Err(error) => {
                        not_updated.insert(id.clone(), error);
                    }
                }
            }
        }
        if let Some(Value::Array(destroy)) = args.get("destroy") {
            for id in destroy.iter().filter_map(Value::as_str) {
                let result: Result<(), Value> = async {
                    let contact_id = self.id(id).ok_or_else(|| json!({ "type": "notFound" }))?;
                    let contact = groupware.contact(owner, contact_id).await.map_err(|error| set_error(&error))?;
                    if !access.allows(contact.addressbook, Level::Write) {
                        return Err(forbidden("the address book may not be written"));
                    }
                    groupware
                        .destroy_contact(owner, contact_id, Expect::Any)
                        .await
                        .map_err(|error| set_error(&error))?;
                    Ok(())
                }
                .await;
                match result {
                    Ok(()) => destroyed.push(id.to_owned()),
                    Err(error) => {
                        not_destroyed.insert(id.to_owned(), error);
                    }
                }
            }
        }
        let new_state = groupware.state(owner).await?;
        Ok(vec![(
            "ContactCard/set".into(),
            json!({
                "accountId": owner.to_string(),
                "oldState": old_state.to_string(),
                "newState": new_state.to_string(),
                "created": created, "notCreated": not_created,
                "updated": updated, "notUpdated": not_updated,
                "destroyed": destroyed, "notDestroyed": not_destroyed,
            }),
        )])
    }
}
