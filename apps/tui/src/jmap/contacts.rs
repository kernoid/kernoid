// SPDX-License-Identifier: MIT
//! Contacts over JMAP (RFC 9610): the address books of every account the user reaches, and their cards as JSContact –
//! read, made, changed and removed.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{CONTACTS, Client, Error, Result, ids_of};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct NameComponent {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Name {
    #[serde(default)]
    pub full: Option<String>,
    #[serde(default)]
    pub components: Vec<NameComponent>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmailEntry {
    pub address: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Phone {
    pub number: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Organization {
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Note {
    pub note: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    pub id: String,
    #[serde(default)]
    pub address_book_ids: BTreeMap<String, bool>,
    #[serde(default)]
    pub name: Option<Name>,
    #[serde(default)]
    pub emails: Option<BTreeMap<String, EmailEntry>>,
    #[serde(default)]
    pub phones: Option<BTreeMap<String, Phone>>,
    #[serde(default)]
    pub organizations: Option<BTreeMap<String, Organization>>,
    #[serde(default)]
    pub notes: Option<BTreeMap<String, Note>>,
    #[serde(skip)]
    pub account: String,
}

impl Card {
    /// The name to show: the full name, the parts of the name, or the first address.
    pub fn full_name(&self) -> String {
        if let Some(full) = self.name.as_ref().and_then(|name| name.full.clone()).filter(|full| !full.is_empty()) {
            return full;
        }
        let parts: Vec<&str> = self
            .name
            .iter()
            .flat_map(|name| name.components.iter())
            .filter(|part| !part.value.is_empty() && part.kind != "separator")
            .map(|part| part.value.as_str())
            .collect();
        if !parts.is_empty() {
            return parts.join(" ");
        }
        self.emails().into_iter().next().unwrap_or_default()
    }

    pub fn emails(&self) -> Vec<String> {
        self.emails.iter().flat_map(|map| map.values()).map(|entry| entry.address.clone()).collect()
    }

    pub fn phones(&self) -> Vec<String> {
        self.phones.iter().flat_map(|map| map.values()).map(|phone| phone.number.clone()).collect()
    }

    pub fn organization(&self) -> Option<String> {
        let names: Vec<_> =
            self.organizations.iter().flat_map(|map| map.values()).filter_map(|o| o.name.clone()).collect();
        (!names.is_empty()).then(|| names.join(", "))
    }

    pub fn notes(&self) -> Vec<String> {
        self.notes.iter().flat_map(|map| map.values()).map(|note| note.note.clone()).collect()
    }
}

#[derive(Deserialize)]
struct List<T> {
    list: Vec<T>,
}

/// The cards of every account with contacts, `text` searching them; sorted by name.
pub fn cards(client: &Client, text: &str) -> Result<Vec<Card>> {
    let mut out = Vec::new();
    for (account, _) in client.session.accounts_with(CONTACTS) {
        let mut filter = Map::new();
        if !text.trim().is_empty() {
            filter.insert("text".into(), text.trim().into());
        }
        let responses = client.request(
            &[CONTACTS],
            vec![
                ("ContactCard/query", json!({ "accountId": account, "filter": filter }), "q"),
                ("ContactCard/get", json!({ "accountId": account, "#ids": ids_of("q", "ContactCard/query") }), "g"),
            ],
        )?;
        let value = responses.get("g").cloned().unwrap_or(json!({ "list": [] }));
        let cards = serde_json::from_value::<List<Card>>(value).map_err(|error| Error::Protocol(error.to_string()))?;
        out.extend(cards.list.into_iter().map(|mut card| {
            card.account = account.to_owned();
            card
        }));
    }
    out.sort_by_key(|card| card.full_name().to_lowercase());
    Ok(out)
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BookRights {
    pub may_write: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressBook {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub is_default: bool,
    #[serde(default)]
    pub my_rights: Option<BookRights>,
    #[serde(skip)]
    pub account: String,
    /// The name of the account, for address books shared with the user.
    #[serde(skip)]
    pub shared: Option<String>,
}

impl AddressBook {
    pub fn writable(&self) -> bool {
        self.my_rights.is_none_or(|rights| rights.may_write)
    }
}

/// The address books of every account with contacts; the user's default first.
pub fn address_books(client: &Client) -> Result<Vec<AddressBook>> {
    let mut out = Vec::new();
    for (id, account) in client.session.accounts_with(CONTACTS) {
        let result = client.call(&[CONTACTS], "AddressBook/get", json!({ "accountId": id }))?;
        let books =
            serde_json::from_value::<List<AddressBook>>(result).map_err(|error| Error::Protocol(error.to_string()))?;
        out.extend(books.list.into_iter().map(|mut book| {
            book.account = id.to_owned();
            book.shared = (!account.is_personal).then(|| account.name.clone());
            book
        }));
    }
    out.sort_by_key(|book| (book.shared.is_some(), !book.is_default, book.name.to_lowercase()));
    Ok(out)
}

/// A card as the user writes it: one of each, as the web app has it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CardForm {
    pub name: String,
    pub email: String,
    pub phone: String,
    pub organization: String,
    pub note: String,
}

impl CardForm {
    pub fn of(card: &Card) -> Self {
        Self {
            name: card.full_name(),
            email: card.emails().into_iter().next().unwrap_or_default(),
            phone: card.phones().into_iter().next().unwrap_or_default(),
            organization: card.organization().unwrap_or_default(),
            note: card.notes().join("\n"),
        }
    }

    /// The JSContact properties (without `addressBookIds`); empty fields remove what was.
    pub fn object(&self) -> Value {
        let or_null = |empty: bool, value: Value| if empty { Value::Null } else { value };
        json!({
            "name": { "full": self.name },
            "emails": or_null(self.email.is_empty(), json!({ "e1": { "@type": "EmailAddress", "address": self.email } })),
            "phones": or_null(self.phone.is_empty(), json!({ "p1": { "@type": "Phone", "number": self.phone } })),
            "organizations": or_null(self.organization.is_empty(),
                json!({ "o1": { "@type": "Organization", "name": self.organization } })),
            "notes": or_null(self.note.is_empty(), json!({ "n1": { "@type": "Note", "note": self.note } })),
        })
    }
}

pub fn create(client: &Client, book: &AddressBook, form: &CardForm) -> Result<()> {
    let mut object = form.object();
    object["@type"] = "Card".into();
    object["version"] = "1.0".into();
    object["addressBookIds"] = json!({ book.id.as_str(): true });
    client.set(&[CONTACTS], "ContactCard", &book.account, json!({ "create": { "c": object } }), json!({}))?;
    Ok(())
}

/// Changes a card, and moves it to `book` (of the same account).
pub fn update(client: &Client, book: &AddressBook, id: &str, form: &CardForm) -> Result<()> {
    let mut object = form.object();
    object["addressBookIds"] = json!({ book.id.as_str(): true });
    client.set(&[CONTACTS], "ContactCard", &book.account, json!({ "update": { id: object } }), json!({}))?;
    Ok(())
}

pub fn destroy(client: &Client, account: &str, id: &str) -> Result<()> {
    client.set(&[CONTACTS], "ContactCard", account, json!({ "destroy": [id] }), json!({}))?;
    Ok(())
}
