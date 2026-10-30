// SPDX-License-Identifier: MIT
//! Contacts over JMAP (RFC 9610): the address books of every account the user reaches, and their cards as JSContact –
//! read, made, changed and removed.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::{CONTACTS, Client, Error, Result, ids_of};

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
    /// `work`, `private` (RFC 9553, 1.5.1).
    #[serde(default)]
    pub contexts: Option<BTreeMap<String, bool>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Phone {
    pub number: String,
    #[serde(default)]
    pub contexts: Option<BTreeMap<String, bool>>,
    /// `mobile`, `voice`, `fax`, `text` … (RFC 9553, 2.3.3).
    #[serde(default)]
    pub features: Option<BTreeMap<String, bool>>,
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
pub async fn cards(client: &Client, text: &str) -> Result<Vec<Card>> {
    let mut out = Vec::new();
    for (account, _) in client.session.accounts_with(CONTACTS) {
        let mut filter = Map::new();
        if !text.trim().is_empty() {
            filter.insert("text".into(), text.trim().into());
        }
        let responses = client
            .request(
                &[CONTACTS],
                vec![
                    ("ContactCard/query", json!({ "accountId": account, "filter": filter }), "q"),
                    ("ContactCard/get", json!({ "accountId": account, "#ids": ids_of("q", "ContactCard/query") }), "g"),
                ],
            )
            .await?;
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
pub async fn address_books(client: &Client) -> Result<Vec<AddressBook>> {
    let mut out = Vec::new();
    for (id, account) in client.session.accounts_with(CONTACTS) {
        let result = client.call(&[CONTACTS], "AddressBook/get", json!({ "accountId": id })).await?;
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

/// The contexts a value may have (RFC 9553, 1.5.1); for phones, other labels are its features.
pub const CONTEXTS: [&str; 2] = ["work", "private"];
/// The features of a phone (RFC 9553, 2.3.3).
pub const FEATURES: [&str; 7] = ["mobile", "voice", "text", "video", "fax", "pager", "textphone"];

/// A value with its labels – contexts, and for a phone its features: `alice@x.example (work)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Labelled {
    pub value: String,
    pub labels: Vec<String>,
}

impl Labelled {
    fn of(value: &str, maps: &[&Option<BTreeMap<String, bool>>]) -> Self {
        let labels = maps
            .iter()
            .flat_map(|map| map.iter().flat_map(|map| map.iter()))
            .filter(|(_, on)| **on)
            .map(|(label, _)| label.clone())
            .collect();
        Self { value: value.to_owned(), labels }
    }

    /// As the editor shows it.
    pub fn render(&self) -> String {
        if self.labels.is_empty() { self.value.clone() } else { format!("{} ({})", self.value, self.labels.join(", ")) }
    }

    /// From the editor; `allowed` are the labels it may have.
    pub fn parse(text: &str, allowed: &[&str]) -> std::result::Result<Self, String> {
        let text = text.trim();
        let (value, labels) = match text.strip_suffix(')').and_then(|rest| rest.rsplit_once('(')) {
            Some((value, labels)) => {
                (value.trim(), labels.split(',').map(|label| label.trim().to_lowercase()).collect())
            }
            None => (text, Vec::new()),
        };
        let labels: Vec<String> = labels.into_iter().filter(|label: &String| !label.is_empty()).collect();
        if let Some(unknown) = labels.iter().find(|label| !allowed.contains(&label.as_str())) {
            return Err(format!("unknown label {unknown} – one of {}", allowed.join(", ")));
        }
        Ok(Self { value: value.to_owned(), labels })
    }

    fn set(&self, among: &[&str]) -> Value {
        let on: Map<String, Value> = self
            .labels
            .iter()
            .filter(|label| among.contains(&label.as_str()))
            .map(|label| (label.clone(), json!(true)))
            .collect();
        if on.is_empty() { Value::Null } else { Value::Object(on) }
    }
}

/// A card as the user writes it: every address, phone number and organisation, with their labels.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CardForm {
    pub name: String,
    pub emails: Vec<Labelled>,
    pub phones: Vec<Labelled>,
    pub organizations: Vec<String>,
    pub note: String,
}

impl CardForm {
    pub fn of(card: &Card) -> Self {
        Self {
            name: card.full_name(),
            emails: card
                .emails
                .iter()
                .flat_map(|map| map.values())
                .map(|entry| Labelled::of(&entry.address, &[&entry.contexts]))
                .collect(),
            phones: card
                .phones
                .iter()
                .flat_map(|map| map.values())
                .map(|phone| Labelled::of(&phone.number, &[&phone.contexts, &phone.features]))
                .collect(),
            organizations: card
                .organizations
                .iter()
                .flat_map(|map| map.values())
                .filter_map(|organization| organization.name.clone())
                .collect(),
            note: card.notes().join("\n"),
        }
    }

    /// The JSContact properties (without `addressBookIds`); empty fields remove what was.
    pub fn object(&self) -> Value {
        let map = |prefix: &str, values: Vec<Value>| -> Value {
            if values.is_empty() {
                return Value::Null;
            }
            Value::Object(
                values.into_iter().enumerate().map(|(n, value)| (format!("{prefix}{}", n + 1), value)).collect(),
            )
        };
        let emails = self
            .emails
            .iter()
            .map(|email| json!({ "@type": "EmailAddress", "address": email.value, "contexts": email.set(&CONTEXTS) }))
            .collect();
        let phones = self
            .phones
            .iter()
            .map(|phone| {
                json!({ "@type": "Phone", "number": phone.value, "contexts": phone.set(&CONTEXTS),
                        "features": phone.set(&FEATURES) })
            })
            .collect();
        let organizations =
            self.organizations.iter().map(|name| json!({ "@type": "Organization", "name": name })).collect();
        json!({
            "name": { "full": self.name },
            "emails": map("e", emails),
            "phones": map("p", phones),
            "organizations": map("o", organizations),
            "notes": if self.note.is_empty() { Value::Null } else { json!({ "n1": { "@type": "Note", "note": self.note } }) },
        })
    }
}

pub async fn create(client: &Client, book: &AddressBook, form: &CardForm) -> Result<()> {
    let mut object = form.object();
    object["@type"] = "Card".into();
    object["version"] = "1.0".into();
    object["addressBookIds"] = json!({ book.id.as_str(): true });
    client.set(&[CONTACTS], "ContactCard", &book.account, json!({ "create": { "c": object } }), json!({})).await?;
    Ok(())
}

/// Changes a card, and moves it to `book` (of the same account).
pub async fn update(client: &Client, book: &AddressBook, id: &str, form: &CardForm) -> Result<()> {
    let mut object = form.object();
    object["addressBookIds"] = json!({ book.id.as_str(): true });
    client.set(&[CONTACTS], "ContactCard", &book.account, json!({ "update": { id: object } }), json!({})).await?;
    Ok(())
}

/// Cards as stored – every property –, for writing them to a file.
pub async fn raw_cards(client: &Client, account: &str, ids: &[String]) -> Result<Vec<Map<String, Value>>> {
    let result = client.call(&[CONTACTS], "ContactCard/get", json!({ "accountId": account, "ids": ids })).await?;
    Ok(result
        .get("list")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(|card| card.as_object().cloned()).collect())
        .unwrap_or_default())
}

/// Makes the cards read from a file in `book`; how many were made, and why the others were not.
pub async fn import(
    client: &Client,
    book: &AddressBook,
    cards: Vec<Map<String, Value>>,
) -> Result<(usize, Vec<String>)> {
    let create: Map<String, Value> = cards
        .into_iter()
        .enumerate()
        .map(|(n, mut card)| {
            card.insert("addressBookIds".into(), json!({ book.id.as_str(): true }));
            (format!("i{n}"), Value::Object(card))
        })
        .collect();
    let result =
        client.call(&[CONTACTS], "ContactCard/set", json!({ "accountId": book.account, "create": create })).await?;
    Ok(crate::calendars::made_and_refused(&result))
}

pub async fn destroy(client: &Client, account: &str, id: &str) -> Result<()> {
    client.set(&[CONTACTS], "ContactCard", account, json!({ "destroy": [id] }), json!({})).await?;
    Ok(())
}
