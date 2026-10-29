// SPDX-License-Identifier: AGPL-3.0-or-later
//! JMAP's vacation response (RFC 8621, 8): one object, `singleton`, of the caller's own mail account – read and
//! changed by its owner; delivery answers with it (`kernoid_mail::VacationResponse`).

use std::hash::{DefaultHasher, Hash, Hasher};

use chrono::{DateTime, SecondsFormat, Utc};
use kernoid_mail::VacationResponse;
use serde_json::{Map, Value, json};

use crate::{
    mailbox::{ids, invalid_properties},
    request::{Context, MethodError, MethodResult},
};

pub const VACATION: &str = "urn:ietf:params:jmap:vacationresponse";
const SINGLETON: &str = "singleton";

fn date(value: Option<DateTime<Utc>>) -> Value {
    value.map_or(Value::Null, |date| json!(date.to_rfc3339_opts(SecondsFormat::Secs, true)))
}

fn object(vacation: &VacationResponse) -> Value {
    json!({
        "id": SINGLETON,
        "isEnabled": vacation.enabled,
        "fromDate": date(vacation.from_date),
        "toDate": date(vacation.to_date),
        "subject": vacation.subject,
        "textBody": vacation.text_body,
        "htmlBody": vacation.html_body,
    })
}

/// The state: what the object is – it changes with it.
fn state(vacation: &VacationResponse) -> String {
    let mut hasher = DefaultHasher::new();
    object(vacation).to_string().hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

/// The patch of `/set` applied (RFC 8620, 5.3: properties of the object, `null` for none).
fn apply(vacation: &mut VacationResponse, patch: &Map<String, Value>) -> Result<(), Value> {
    let text = |value: &Value| match value {
        Value::Null => Ok(None),
        Value::String(text) => Ok(Some(text.clone())),
        _ => Err(invalid_properties("a string or null")),
    };
    let when = |value: &Value| match value {
        Value::Null => Ok(None),
        Value::String(text) => DateTime::parse_from_rfc3339(text)
            .map(|date| Some(date.with_timezone(&Utc)))
            .map_err(|_| invalid_properties(format!("{text} is not a UTCDate"))),
        _ => Err(invalid_properties("a UTCDate or null")),
    };
    for (property, value) in patch {
        match property.as_str() {
            "isEnabled" => vacation.enabled = value.as_bool().ok_or_else(|| invalid_properties("isEnabled"))?,
            "fromDate" => vacation.from_date = when(value)?,
            "toDate" => vacation.to_date = when(value)?,
            "subject" => vacation.subject = text(value)?,
            "textBody" => vacation.text_body = text(value)?,
            "htmlBody" => vacation.html_body = text(value)?,
            "id" if value == SINGLETON => {}
            other => return Err(invalid_properties(format!("{other} cannot be set"))),
        }
    }
    Ok(())
}

impl Context<'_> {
    /// The caller's own mail account, the only one with a vacation response.
    async fn own_mail(&self, args: &Map<String, Value>) -> Result<uuid::Uuid, MethodError> {
        let access = self.access(args).await?;
        if !access.owned {
            return Err(MethodError::new(
                "accountNotSupportedByMethod",
                "only the own account has a vacation response",
            ));
        }
        Ok(access.owner)
    }

    pub async fn vacation_get(&self, args: Map<String, Value>) -> MethodResult {
        let account = self.own_mail(&args).await?;
        let vacation = self.jmap.mail().vacation_response(account).await?;
        let (mut list, mut not_found) = (Vec::new(), Vec::new());
        match ids(&args)? {
            None => list.push(object(&vacation)),
            Some(wanted) => {
                for id in wanted {
                    if id == SINGLETON { list.push(object(&vacation)) } else { not_found.push(Value::String(id)) }
                }
            }
        }
        Ok(vec![(
            "VacationResponse/get".into(),
            json!({ "accountId": account.to_string(), "state": state(&vacation), "list": list, "notFound": not_found }),
        )])
    }

    pub async fn vacation_set(&self, args: Map<String, Value>) -> MethodResult {
        let account = self.own_mail(&args).await?;
        let mail = self.jmap.mail();
        let mut vacation = mail.vacation_response(account).await?;
        let old_state = state(&vacation);
        if let Some(Value::String(expected)) = args.get("ifInState")
            && *expected != old_state
        {
            return Err(MethodError::new("stateMismatch", "the vacation response has changed"));
        }
        let singleton = || json!({ "type": "singleton", "description": "there is one vacation response" });
        let mut not_created = Map::new();
        if let Some(Value::Object(create)) = args.get("create") {
            for key in create.keys() {
                not_created.insert(key.clone(), singleton());
            }
        }
        let mut not_destroyed = Map::new();
        if let Some(Value::Array(destroy)) = args.get("destroy") {
            for id in destroy.iter().filter_map(Value::as_str) {
                not_destroyed.insert(id.to_owned(), singleton());
            }
        }
        let mut updated = Map::new();
        let mut not_updated = Map::new();
        if let Some(Value::Object(update)) = args.get("update") {
            for (id, patch) in update {
                if id != SINGLETON {
                    not_updated.insert(id.clone(), json!({ "type": "notFound" }));
                    continue;
                }
                let mut changed = vacation.clone();
                let result = match patch.as_object() {
                    Some(patch) => apply(&mut changed, patch),
                    None => Err(invalid_properties("a patch object")),
                };
                let result = match result {
                    Ok(()) => mail.set_vacation_response(account, &changed).await.map_err(|error| match error {
                        kernoid_mail::MailError::Invalid(text) => invalid_properties(text),
                        other => json!({ "type": "serverFail", "description": other.to_string() }),
                    }),
                    Err(error) => Err(error),
                };
                match result {
                    Ok(()) => {
                        vacation = changed;
                        updated.insert(id.clone(), Value::Null);
                    }
                    Err(error) => {
                        not_updated.insert(id.clone(), error);
                    }
                }
            }
        }
        let or_null = |map: Map<String, Value>| if map.is_empty() { Value::Null } else { Value::Object(map) };
        Ok(vec![(
            "VacationResponse/set".into(),
            json!({
                "accountId": account.to_string(),
                "oldState": old_state,
                "newState": state(&vacation),
                "created": null,
                "updated": or_null(updated),
                "destroyed": null,
                "notCreated": or_null(not_created),
                "notUpdated": or_null(not_updated),
                "notDestroyed": or_null(not_destroyed),
            }),
        )])
    }
}
