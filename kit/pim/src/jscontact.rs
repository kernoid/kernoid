// SPDX-License-Identifier: MIT
//! JSContact (RFC 9553) as JSON objects, converted from and to vCard after RFC 9555. A vCard of 3.0 or 2.1 is read as
//! its 4.0 form. What has no JSContact property stays in `vCardProps` (`[name, params, "unknown", value]`, the value
//! as written); the group of a property (`item1.EMAIL`, Apple's labels) is kept in the item's `vCardParams`.

use serde_json::{Map, Value, json};

use crate::{
    content::{Error, Param, Property, escape},
    jscalendar::new_uid,
    time,
    vcard::{self, VCard, Version},
};

type Object = Map<String, Value>;

/// N's fields in order and the kinds of name component they hold (RFC 9555, 2.3.4; RFC 9554 adds the last two).
const NAME_KINDS: [&str; 7] = ["surname", "given", "given2", "title", "credential", "surname2", "generation"];
/// ADR's fields in order and the kinds of address component they hold.
const ADDRESS_KINDS: [&str; 7] = ["postOfficeBox", "apartment", "name", "locality", "region", "postcode", "country"];

fn contexts(property: &Property) -> Object {
    let mut out = Object::new();
    for kind in property.param_values("TYPE") {
        match kind.to_ascii_lowercase().as_str() {
            "work" => {
                out.insert("work".into(), json!(true));
            }
            "home" => {
                out.insert("private".into(), json!(true));
            }
            "other" => {
                out.insert("other".into(), json!(true));
            }
            _ => {}
        }
    }
    out
}

/// The common parts of an item: contexts, preference, label, the vCard group.
fn item(kind: &str, property: &Property) -> Object {
    let mut out = Object::new();
    out.insert("@type".into(), json!(kind));
    let contexts = contexts(property);
    if !contexts.is_empty() {
        out.insert("contexts".into(), Value::Object(contexts));
    }
    if let Some(pref) = property.param("PREF").and_then(|p| p.trim().parse::<u64>().ok()) {
        out.insert("pref".into(), json!(pref));
    }
    if let Some(label) = property.param("LABEL").filter(|_| !property.is("ADR")) {
        out.insert("label".into(), json!(label));
    }
    if let Some(group) = &property.group {
        out.insert("vCardParams".into(), json!({ "group": group }));
    }
    out
}

fn add(map: &mut Object, prefix: &str, value: Object) {
    let id = format!("{prefix}{}", map.len() + 1);
    map.insert(id, Value::Object(value));
}

fn partial_date(value: &str) -> Option<Value> {
    let value = value.trim();
    let date = value.split(['T', 't']).next()?;
    let digits: String = date.chars().filter(|c| c.is_ascii_digit()).collect();
    let mut out = Object::new();
    out.insert("@type".into(), json!("PartialDate"));
    if let Some(rest) = date.strip_prefix("--") {
        let rest: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
        if rest.len() != 4 {
            return None;
        }
        out.insert("month".into(), json!(rest[0..2].parse::<u8>().ok()?));
        out.insert("day".into(), json!(rest[2..4].parse::<u8>().ok()?));
        return Some(Value::Object(out));
    }
    match digits.len() {
        8 => {
            out.insert("year".into(), json!(digits[0..4].parse::<u16>().ok()?));
            out.insert("month".into(), json!(digits[4..6].parse::<u8>().ok()?));
            out.insert("day".into(), json!(digits[6..8].parse::<u8>().ok()?));
        }
        6 if date.contains('-') => {
            out.insert("year".into(), json!(digits[0..4].parse::<u16>().ok()?));
            out.insert("month".into(), json!(digits[4..6].parse::<u8>().ok()?));
        }
        4 => {
            out.insert("year".into(), json!(digits.parse::<u16>().ok()?));
        }
        _ => return None,
    }
    Some(Value::Object(out))
}

fn prop_json(property: &Property) -> Value {
    let mut params = Object::new();
    if let Some(group) = &property.group {
        params.insert("group".into(), json!(group));
    }
    for param in &property.params {
        let value = if param.values.len() == 1 { json!(param.values[0]) } else { json!(param.values) };
        params.insert(param.name.to_ascii_lowercase(), value);
    }
    json!([property.name.to_ascii_lowercase(), params, "unknown", property.value])
}

fn prop_from_json(value: &Value) -> Option<Property> {
    let items = value.as_array()?;
    let mut property =
        Property::new(items.first()?.as_str()?, items.get(3).and_then(Value::as_str).unwrap_or_default());
    if let Some(params) = items.get(1).and_then(Value::as_object) {
        for (name, value) in params {
            let values: Vec<String> = match value {
                Value::Array(values) => values.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect(),
                Value::String(value) => vec![value.clone()],
                _ => continue,
            };
            if name == "group" {
                property.group = values.into_iter().next();
                continue;
            }
            property.params.push(Param { name: name.to_ascii_uppercase(), values });
        }
    }
    Some(property)
}

fn slot<'a>(groups: &'a mut [(&'static str, &'static str, Object)], key: &str) -> &'a mut Object {
    &mut groups.iter_mut().find(|(k, _, _)| *k == key).expect("known").2
}

/// A vCard as a JSContact Card.
pub fn from_vcard(card: &VCard) -> Object {
    let normal = VCard { version: Version::V4_0, properties: card.properties.clone() };
    let properties = vcard::parse(&normal.write(Version::V4_0)).map(|card| card.properties).unwrap_or_default();
    let mut out = Object::new();
    out.insert("@type".into(), json!("Card"));
    out.insert("version".into(), json!("1.0"));
    let mut name = Object::new();
    let mut groups: Vec<(&'static str, &'static str, Object)> = [
        ("nicknames", "k"),
        ("organizations", "o"),
        ("titles", "t"),
        ("emails", "e"),
        ("phones", "p"),
        ("addresses", "a"),
        ("onlineServices", "s"),
        ("links", "l"),
        ("media", "m"),
        ("notes", "n"),
        ("anniversaries", "d"),
        ("directories", "r"),
        ("calendars", "c"),
        ("schedulingAddresses", "x"),
        ("cryptoKeys", "y"),
        ("preferredLanguages", "g"),
    ]
    .into_iter()
    .map(|(key, prefix)| (key, prefix, Object::new()))
    .collect();
    let mut keywords = Object::new();
    let mut members = Object::new();
    let mut related = Object::new();
    let mut extra = Vec::new();
    for property in &properties {
        match property.name.as_str() {
            "UID" => {
                out.insert("uid".into(), json!(property.as_text().trim()));
            }
            "KIND" => {
                out.insert("kind".into(), json!(property.as_text().trim().to_ascii_lowercase()));
            }
            "PRODID" => {
                out.insert("prodId".into(), json!(property.as_text()));
            }
            "LANGUAGE" => {
                out.insert("language".into(), json!(property.as_text()));
            }
            "REV" | "CREATED" => {
                let parsed = time::Time::parse(&property.value.replace(['-', ':'], ""), None, false)
                    .map(|t| t.resolve(&crate::tz::Zones::default(), &jiff::tz::TimeZone::UTC));
                match parsed {
                    Some(instant) => {
                        out.insert(
                            if property.is("REV") { "updated" } else { "created" }.into(),
                            json!(time::format_utc(instant)),
                        );
                    }
                    None => extra.push(prop_json(property)),
                }
            }
            "FN" if !name.contains_key("full") => {
                name.insert("full".into(), json!(property.as_text()));
            }
            "N" if !name.contains_key("components") => {
                let mut components = Vec::new();
                for (index, values) in property.field_lists().into_iter().enumerate() {
                    let Some(kind) = NAME_KINDS.get(index) else { break };
                    for value in values {
                        components.push(json!({ "kind": kind, "value": value }));
                    }
                }
                if !components.is_empty() {
                    name.insert("components".into(), Value::Array(components));
                }
                let sort: Vec<String> = property.param_values("SORT-AS").map(str::to_owned).collect();
                if let Some(first) = sort.first() {
                    let parts: Vec<&str> = first.split(',').collect();
                    let mut sort_as = Object::new();
                    for (index, part) in parts.iter().enumerate().filter(|(_, part)| !part.is_empty()) {
                        if let Some(kind) = NAME_KINDS.get(index) {
                            sort_as.insert((*kind).into(), json!(part));
                        }
                    }
                    name.insert("sortAs".into(), Value::Object(sort_as));
                }
            }
            "NICKNAME" => {
                for nick in property.texts() {
                    let mut value = item("Nickname", property);
                    value.insert("name".into(), json!(nick));
                    add(slot(&mut groups, "nicknames"), "k", value);
                }
            }
            "ORG" => {
                let fields = property.fields();
                let mut value = item("Organization", property);
                if let Some(first) = fields.first().filter(|f| !f.is_empty()) {
                    value.insert("name".into(), json!(first));
                }
                let units: Vec<Value> = fields
                    .iter()
                    .skip(1)
                    .filter(|f| !f.is_empty())
                    .map(|f| json!({ "@type": "OrgUnit", "name": f }))
                    .collect();
                if !units.is_empty() {
                    value.insert("units".into(), Value::Array(units));
                }
                add(slot(&mut groups, "organizations"), "o", value);
            }
            "TITLE" | "ROLE" => {
                let mut value = item("Title", property);
                value.insert("name".into(), json!(property.as_text()));
                value.insert("kind".into(), json!(if property.is("TITLE") { "title" } else { "role" }));
                add(slot(&mut groups, "titles"), "t", value);
            }
            "EMAIL" => {
                let mut value = item("EmailAddress", property);
                value.insert("address".into(), json!(property.as_text().trim()));
                add(slot(&mut groups, "emails"), "e", value);
            }
            "TEL" => {
                let mut value = item("Phone", property);
                value.insert("number".into(), json!(property.as_text().trim()));
                let mut features = Object::new();
                for kind in property.param_values("TYPE") {
                    let feature = match kind.to_ascii_lowercase().as_str() {
                        "cell" => "mobile".to_owned(),
                        k @ ("voice" | "fax" | "pager" | "text" | "textphone" | "video" | "main-number") => {
                            k.to_owned()
                        }
                        _ => continue,
                    };
                    features.insert(feature, json!(true));
                }
                if !features.is_empty() {
                    value.insert("features".into(), Value::Object(features));
                }
                add(slot(&mut groups, "phones"), "p", value);
            }
            "ADR" => {
                let mut value = item("Address", property);
                let mut components = Vec::new();
                for (index, values) in property.field_lists().into_iter().enumerate() {
                    let Some(kind) = ADDRESS_KINDS.get(index) else { break };
                    for part in values {
                        components.push(json!({ "kind": kind, "value": part }));
                    }
                }
                if !components.is_empty() {
                    value.insert("components".into(), Value::Array(components));
                }
                for (param, key) in
                    [("LABEL", "full"), ("CC", "countryCode"), ("GEO", "coordinates"), ("TZ", "timeZone")]
                {
                    if let Some(found) = property.param(param) {
                        value.insert(key.into(), json!(found));
                    }
                }
                add(slot(&mut groups, "addresses"), "a", value);
            }
            "IMPP" | "X-SOCIALPROFILE" => {
                let mut value = item("OnlineService", property);
                value.insert("uri".into(), json!(property.value.trim()));
                if property.is("X-SOCIALPROFILE")
                    && let Some(service) = property.param("TYPE")
                {
                    value.insert("service".into(), json!(service));
                    value.remove("contexts");
                }
                add(slot(&mut groups, "onlineServices"), "s", value);
            }
            "URL" => {
                let mut value = item("Link", property);
                value.insert("uri".into(), json!(property.value.trim()));
                add(slot(&mut groups, "links"), "l", value);
            }
            "PHOTO" | "LOGO" | "SOUND" => {
                let mut value = item("Media", property);
                value.insert("kind".into(), json!(property.name.to_ascii_lowercase()));
                value.insert("uri".into(), json!(property.value.trim()));
                if let Some(media) = property.param("MEDIATYPE") {
                    value.insert("mediaType".into(), json!(media));
                }
                add(slot(&mut groups, "media"), "m", value);
            }
            "NOTE" => {
                let mut value = item("Note", property);
                value.insert("note".into(), json!(property.as_text()));
                add(slot(&mut groups, "notes"), "n", value);
            }
            "CATEGORIES" => {
                for word in property.texts() {
                    keywords.insert(word, json!(true));
                }
            }
            "BDAY" | "ANNIVERSARY" | "DEATHDATE" => match partial_date(&property.value) {
                Some(date) if !property.has_param_value("VALUE", "text") => {
                    let mut value = item("Anniversary", property);
                    let kind = match property.name.as_str() {
                        "BDAY" => "birth",
                        "DEATHDATE" => "death",
                        _ => "wedding",
                    };
                    value.insert("kind".into(), json!(kind));
                    value.insert("date".into(), date);
                    add(slot(&mut groups, "anniversaries"), "d", value);
                }
                _ => extra.push(prop_json(property)),
            },
            "MEMBER" => {
                members.insert(property.value.trim().to_owned(), json!(true));
            }
            "RELATED" => {
                let entry = related
                    .entry(property.value.trim().to_owned())
                    .or_insert_with(|| json!({ "@type": "Relation", "relation": {} }));
                for kind in property.param_values("TYPE") {
                    if let Some(Value::Object(relation)) = entry.get_mut("relation") {
                        relation.insert(kind.to_ascii_lowercase(), json!(true));
                    }
                }
            }
            "SOURCE" | "CALURI" | "FBURL" | "CALADRURI" | "KEY" => {
                let (key, prefix, kind, ty) = match property.name.as_str() {
                    "SOURCE" => ("directories", "r", Some("entry"), "Directory"),
                    "CALURI" => ("calendars", "c", Some("calendar"), "Calendar"),
                    "FBURL" => ("calendars", "c", Some("freeBusy"), "Calendar"),
                    "CALADRURI" => ("schedulingAddresses", "x", None, "SchedulingAddress"),
                    _ => ("cryptoKeys", "y", None, "CryptoKey"),
                };
                let mut value = item(ty, property);
                value.insert("uri".into(), json!(property.value.trim()));
                if let Some(kind) = kind {
                    value.insert("kind".into(), json!(kind));
                }
                if let Some(media) = property.param("MEDIATYPE") {
                    value.insert("mediaType".into(), json!(media));
                }
                add(slot(&mut groups, key), prefix, value);
            }
            "LANG" => {
                let mut value = item("LanguagePref", property);
                value.insert("language".into(), json!(property.as_text().trim()));
                add(slot(&mut groups, "preferredLanguages"), "g", value);
            }
            _ => extra.push(prop_json(property)),
        }
    }
    if !name.is_empty() {
        name.insert("@type".into(), json!("Name"));
        out.insert("name".into(), Value::Object(name));
    }
    for (key, _, map) in groups {
        if !map.is_empty() {
            out.insert(key.into(), Value::Object(map));
        }
    }
    for (key, map) in [("keywords", keywords), ("members", members), ("relatedTo", related)] {
        if !map.is_empty() {
            out.insert(key.into(), Value::Object(map));
        }
    }
    if !extra.is_empty() {
        out.insert("vCardProps".into(), Value::Array(extra));
    }
    out
}

/// The common parameters of an item back.
fn item_params(property: &mut Property, value: &Object) {
    let mut types: Vec<String> = property.param_values("TYPE").map(str::to_owned).collect();
    if let Some(Value::Object(contexts)) = value.get("contexts") {
        for (context, on) in contexts {
            if on.as_bool() != Some(true) {
                continue;
            }
            match context.as_str() {
                "work" => types.push("work".into()),
                "private" => types.push("home".into()),
                "other" => types.push("other".into()),
                _ => {}
            }
        }
    }
    property.set_param_values("TYPE", types);
    if let Some(pref) = value.get("pref").and_then(Value::as_u64) {
        property.set_param("PREF", pref.to_string());
    }
    if let Some(label) = value.get("label").and_then(Value::as_str) {
        property.set_param("LABEL", label);
    }
    if let Some(group) = value.get("vCardParams").and_then(|p| p.get("group")).and_then(Value::as_str) {
        property.group = Some(group.to_owned());
    }
}

fn str_of<'a>(object: &'a Object, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

fn items<'a>(object: &'a Object, key: &str) -> impl Iterator<Item = &'a Object> + 'a {
    object.get(key).and_then(Value::as_object).into_iter().flat_map(|map| map.values().filter_map(Value::as_object))
}

/// A structured value: fields of lists, each item escaped.
fn structured(fields: &[Vec<String>]) -> String {
    let mut end = fields.len();
    while end > 0 && fields[end - 1].is_empty() {
        end -= 1;
    }
    let minimum = end.max(5).min(fields.len());
    fields[..minimum.max(end)]
        .iter()
        .map(|items| items.iter().map(|item| escape(item)).collect::<Vec<_>>().join(","))
        .collect::<Vec<_>>()
        .join(";")
}

/// A JSContact Card as a vCard (4.0).
pub fn to_vcard(object: &Object) -> Result<VCard, Error> {
    if let Some(kind) = str_of(object, "@type")
        && kind != "Card"
    {
        return Err(Error(format!("@type: {kind} is not a Card")));
    }
    let mut props = Vec::new();
    let uid = str_of(object, "uid").map(str::to_owned).unwrap_or_else(|| format!("urn:uuid:{}", new_uid()));
    props.push(Property::text("UID", &uid));
    if let Some(kind) = str_of(object, "kind") {
        props.push(Property::text("KIND", kind));
    }
    let name = object.get("name").and_then(Value::as_object);
    if let Some(full) = name.and_then(|name| str_of(name, "full")) {
        props.push(Property::text("FN", full));
    }
    if let Some(components) = name.and_then(|name| name.get("components")).and_then(Value::as_array) {
        let mut fields = vec![Vec::new(); 5];
        for component in components {
            let (Some(kind), Some(value)) =
                (component.get("kind").and_then(Value::as_str), component.get("value").and_then(Value::as_str))
            else {
                continue;
            };
            if let Some(index) = NAME_KINDS.iter().position(|k| *k == kind) {
                if fields.len() <= index {
                    fields.resize(index + 1, Vec::new());
                }
                fields[index].push(value.to_owned());
            }
        }
        let mut property = Property::new("N", structured(&fields));
        if let Some(Value::Object(sort_as)) = name.and_then(|name| name.get("sortAs")) {
            let parts: Vec<String> = NAME_KINDS[..2]
                .iter()
                .map(|kind| sort_as.get(*kind).and_then(Value::as_str).unwrap_or_default().to_owned())
                .collect();
            property.set_param("SORT-AS", parts.join(",").trim_end_matches(',').to_owned());
        }
        props.push(property);
    }
    for value in items(object, "nicknames") {
        if let Some(nick) = str_of(value, "name") {
            let mut property = Property::text("NICKNAME", nick);
            item_params(&mut property, value);
            props.push(property);
        }
    }
    for value in items(object, "organizations") {
        let mut fields = vec![vec![str_of(value, "name").unwrap_or_default().to_owned()]];
        for unit in value.get("units").and_then(Value::as_array).into_iter().flatten() {
            if let Some(unit) = unit.get("name").and_then(Value::as_str) {
                fields.push(vec![unit.to_owned()]);
            }
        }
        let text = fields.iter().map(|f| escape(&f[0])).collect::<Vec<_>>().join(";");
        let mut property = Property::new("ORG", text);
        item_params(&mut property, value);
        props.push(property);
    }
    for value in items(object, "titles") {
        if let Some(title) = str_of(value, "name") {
            let name = if str_of(value, "kind") == Some("role") { "ROLE" } else { "TITLE" };
            let mut property = Property::text(name, title);
            item_params(&mut property, value);
            props.push(property);
        }
    }
    for value in items(object, "emails") {
        if let Some(address) = str_of(value, "address") {
            let mut property = Property::text("EMAIL", address);
            item_params(&mut property, value);
            props.push(property);
        }
    }
    for value in items(object, "phones") {
        if let Some(number) = str_of(value, "number") {
            let mut property = Property::text("TEL", number);
            if number.starts_with("tel:") {
                property = Property::new("TEL", number).with_param("VALUE", "uri");
            }
            let mut types = Vec::new();
            if let Some(Value::Object(features)) = value.get("features") {
                for (feature, on) in features {
                    if on.as_bool() == Some(true) {
                        types.push(if feature == "mobile" { "cell".to_owned() } else { feature.clone() });
                    }
                }
            }
            property.set_param_values("TYPE", types);
            item_params(&mut property, value);
            props.push(property);
        }
    }
    for value in items(object, "addresses") {
        let mut fields = vec![Vec::new(); 7];
        for component in value.get("components").and_then(Value::as_array).into_iter().flatten() {
            let (Some(kind), Some(part)) =
                (component.get("kind").and_then(Value::as_str), component.get("value").and_then(Value::as_str))
            else {
                continue;
            };
            let index = match kind {
                "postOfficeBox" => 0,
                "apartment" | "room" | "floor" | "building" => 1,
                "name" | "number" | "block" | "direction" | "landmark" => 2,
                "locality" | "subdistrict" | "district" => 3,
                "region" => 4,
                "postcode" => 5,
                "country" => 6,
                _ => continue,
            };
            fields[index].push(part.to_owned());
        }
        // A street's name and number are one field.
        let street = fields[2].join(" ");
        fields[2] = if street.is_empty() { Vec::new() } else { vec![street] };
        let mut property = Property::new("ADR", structured(&fields));
        for (key, param) in [("full", "LABEL"), ("countryCode", "CC"), ("coordinates", "GEO"), ("timeZone", "TZ")] {
            if let Some(found) = str_of(value, key) {
                property.set_param(param, found);
            }
        }
        item_params(&mut property, value);
        props.push(property);
    }
    for value in items(object, "onlineServices") {
        if let Some(uri) = str_of(value, "uri") {
            let mut property = match str_of(value, "service") {
                Some(service) => Property::new("X-SOCIALPROFILE", uri).with_param("TYPE", service),
                None => Property::new("IMPP", uri),
            };
            item_params(&mut property, value);
            props.push(property);
        }
    }
    for value in items(object, "links") {
        if let Some(uri) = str_of(value, "uri") {
            let mut property = Property::new("URL", uri);
            item_params(&mut property, value);
            props.push(property);
        }
    }
    for value in items(object, "media") {
        if let Some(uri) = str_of(value, "uri") {
            let name = match str_of(value, "kind") {
                Some("logo") => "LOGO",
                Some("sound") => "SOUND",
                _ => "PHOTO",
            };
            let mut property = Property::new(name, uri);
            if let Some(media) = str_of(value, "mediaType") {
                property.set_param("MEDIATYPE", media);
            }
            item_params(&mut property, value);
            props.push(property);
        }
    }
    for value in items(object, "notes") {
        if let Some(note) = str_of(value, "note") {
            let mut property = Property::text("NOTE", note);
            item_params(&mut property, value);
            props.push(property);
        }
    }
    if let Some(Value::Object(keywords)) = object.get("keywords") {
        let words: Vec<String> =
            keywords.iter().filter(|(_, on)| on.as_bool() == Some(true)).map(|(w, _)| escape(w)).collect();
        if !words.is_empty() {
            props.push(Property::new("CATEGORIES", words.join(",")));
        }
    }
    for value in items(object, "anniversaries") {
        let Some(date) = value.get("date").and_then(Value::as_object) else { continue };
        let text = if let Some(utc) = str_of(date, "utc") {
            utc.replace(['-', ':'], "")
        } else {
            let year = date.get("year").and_then(Value::as_u64);
            let month = date.get("month").and_then(Value::as_u64);
            let day = date.get("day").and_then(Value::as_u64);
            match (year, month, day) {
                (Some(y), Some(m), Some(d)) => format!("{y:04}{m:02}{d:02}"),
                (None, Some(m), Some(d)) => format!("--{m:02}{d:02}"),
                (Some(y), Some(m), None) => format!("{y:04}-{m:02}"),
                (Some(y), None, None) => format!("{y:04}"),
                _ => continue,
            }
        };
        let name = match str_of(value, "kind") {
            Some("birth") => "BDAY",
            Some("death") => "DEATHDATE",
            _ => "ANNIVERSARY",
        };
        let mut property = Property::new(name, text);
        item_params(&mut property, value);
        props.push(property);
    }
    if let Some(Value::Object(members)) = object.get("members") {
        for (member, on) in members {
            if on.as_bool() == Some(true) {
                props.push(Property::new("MEMBER", member.clone()));
            }
        }
    }
    if let Some(Value::Object(related)) = object.get("relatedTo") {
        for (uri, relation) in related {
            let mut property = Property::new("RELATED", uri.clone());
            if let Some(Value::Object(kinds)) = relation.get("relation") {
                property.set_param_values(
                    "TYPE",
                    kinds.iter().filter(|(_, on)| on.as_bool() == Some(true)).map(|(k, _)| k.clone()).collect(),
                );
            }
            props.push(property);
        }
    }
    for (key, name) in [
        ("directories", "SOURCE"),
        ("calendars", "CALURI"),
        ("schedulingAddresses", "CALADRURI"),
        ("cryptoKeys", "KEY"),
    ] {
        for value in items(object, key) {
            let Some(uri) = str_of(value, "uri") else { continue };
            let name = if str_of(value, "kind") == Some("freeBusy") { "FBURL" } else { name };
            let mut property = Property::new(name, uri);
            if let Some(media) = str_of(value, "mediaType") {
                property.set_param("MEDIATYPE", media);
            }
            item_params(&mut property, value);
            props.push(property);
        }
    }
    for value in items(object, "preferredLanguages") {
        if let Some(language) = str_of(value, "language") {
            let mut property = Property::text("LANG", language);
            item_params(&mut property, value);
            props.push(property);
        }
    }
    if let Some(language) = str_of(object, "language") {
        props.push(Property::text("LANGUAGE", language));
    }
    if let Some(prod_id) = str_of(object, "prodId") {
        props.push(Property::text("PRODID", prod_id));
    }
    for (key, name) in [("updated", "REV"), ("created", "CREATED")] {
        if let Some(instant) = str_of(object, key).and_then(time::parse_utc) {
            props.push(Property::new(
                name,
                format!("{}Z", time::format_date_time(jiff::tz::TimeZone::UTC.to_datetime(instant))),
            ));
        }
    }
    if let Some(Value::Array(extra)) = object.get("vCardProps") {
        props.extend(extra.iter().filter_map(prop_from_json));
    }
    Ok(VCard { version: Version::V4_0, properties: props })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cards_go_both_ways() {
        let text = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:urn:uuid:1\r\nFN:Jane Doe\r\nN:Doe;Jane;Ann;Dr.;\r\nNICKNAME:JD\r\n\
            ORG:Example Inc.;Sales\r\nTITLE:Lead\r\nitem1.EMAIL;TYPE=INTERNET,WORK,pref:jane@example.org\r\nitem1.X-ABLabel:Office\r\n\
            TEL;TYPE=CELL,VOICE:+49 170 1\r\nADR;TYPE=HOME:;;Main St 1;Berlin;;10115;Germany\r\nBDAY:1985-04-12\r\n\
            NOTE:Line 1\\nLine 2\r\nCATEGORIES:friends,work\r\nX-CUSTOM;X-P=1:value\r\nEND:VCARD\r\n";
        let card = vcard::parse(text).unwrap();
        let json = from_vcard(&card);
        assert_eq!(json["uid"], "urn:uuid:1");
        assert_eq!(json["name"]["full"], "Jane Doe");
        assert_eq!(json["name"]["components"][0], json!({ "kind": "surname", "value": "Doe" }));
        assert_eq!(json["emails"]["e1"]["address"], "jane@example.org");
        assert_eq!(json["emails"]["e1"]["pref"], 1);
        assert_eq!(json["emails"]["e1"]["contexts"], json!({ "work": true }));
        assert_eq!(json["phones"]["p1"]["features"], json!({ "mobile": true, "voice": true }));
        assert_eq!(json["addresses"]["a1"]["components"][1], json!({ "kind": "locality", "value": "Berlin" }));
        assert_eq!(
            json["anniversaries"]["d1"]["date"],
            json!({ "@type": "PartialDate", "year": 1985, "month": 4, "day": 12 })
        );
        assert_eq!(json["notes"]["n1"]["note"], "Line 1\nLine 2");
        assert_eq!(json["organizations"]["o1"]["units"][0]["name"], "Sales");
        let back = to_vcard(&json).unwrap().write(Version::V4_0);
        for line in [
            "UID:urn:uuid:1",
            "FN:Jane Doe",
            "N:Doe;Jane;Ann;Dr.;",
            "ORG:Example Inc.;Sales",
            "item1.EMAIL;TYPE=work;PREF=1:jane@example.org",
            "item1.X-ABLABEL:Office",
            "ADR;TYPE=home:;;Main St 1;Berlin;;10115;Germany",
            "BDAY:19850412",
            "NOTE:Line 1\\nLine 2",
            "X-CUSTOM;X-P=1:value",
        ] {
            assert!(back.contains(line), "{line}\n{back}");
        }
        let again = from_vcard(&vcard::parse(&back).unwrap());
        assert_eq!(again["emails"], json["emails"]);
        assert_eq!(again["addresses"], json["addresses"]);
    }

    #[test]
    fn a_card_from_json() {
        let object = json!({ "@type": "Card", "version": "1.0", "name": { "full": "Carol Example" },
            "emails": { "e1": { "address": "carol@example.org" } } });
        let card = to_vcard(object.as_object().unwrap()).unwrap();
        let text = card.write(Version::V4_0);
        assert!(text.contains("FN:Carol Example") && text.contains("EMAIL:carol@example.org"), "{text}");
        assert!(card.uid().is_some_and(|uid| uid.starts_with("urn:uuid:")));
        assert!(to_vcard(json!({ "@type": "Event" }).as_object().unwrap()).is_err());
    }
}
