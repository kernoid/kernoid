// SPDX-License-Identifier: AGPL-3.0-or-later
//! JMAP Sharing's principals (RFC 9670, 2; RFC 0005, 11): the people and groups of the caller's tenant, so that a
//! program can find whom to share with. Read-only: `Principal/get` and `Principal/query`.

use kernoid_identity::Identity;
use serde_json::{Map, Value, json};

use crate::{
    MAX_OBJECTS_IN_GET,
    mailbox::ids,
    request::{Context, MethodError, MethodResult},
};

/// A principal: a person's account or a group.
struct Principal {
    id: String,
    kind: &'static str,
    name: String,
    email: Option<String>,
}

impl Principal {
    fn object(&self) -> Value {
        json!({
            "id": self.id,
            "type": self.kind,
            "name": self.name,
            "description": null,
            "email": self.email,
            "timeZone": null,
            "capabilities": {},
            "accounts": null,
        })
    }
}

/// The people and groups of the tenant – not shared mailboxes or drives, which nobody is.
async fn principals(identity: &Identity, tenant: uuid::Uuid) -> Result<Vec<Principal>, MethodError> {
    let mut out: Vec<Principal> = identity
        .accounts(tenant)
        .await
        .map_err(MethodError::server_fail)?
        .into_iter()
        .filter(|account| account.active && !account.shared && !account.drive)
        .map(|account| Principal {
            id: account.id.to_string(),
            kind: "individual",
            name: account.display_name,
            email: Some(account.address).filter(|address| !address.is_empty()),
        })
        .collect();
    out.extend(identity.groups(tenant).await.map_err(MethodError::server_fail)?.into_iter().map(|group| Principal {
        id: group.id.to_string(),
        kind: "group",
        name: group.name,
        email: group.addresses.first().cloned(),
    }));
    out.sort_by_key(|principal| principal.name.to_lowercase());
    Ok(out)
}

fn matches(principal: &Principal, filter: &Map<String, Value>) -> bool {
    let has = |value: Option<&str>, needle: &Value| {
        let needle = needle.as_str().unwrap_or_default().to_lowercase();
        value.is_some_and(|value| value.to_lowercase().contains(&needle))
    };
    filter.iter().all(|(key, value)| match key.as_str() {
        "name" => has(Some(&principal.name), value),
        "email" => has(principal.email.as_deref(), value),
        "text" => has(Some(&principal.name), value) || has(principal.email.as_deref(), value),
        "type" => value.as_str() == Some(principal.kind),
        _ => false,
    })
}

impl Context<'_> {
    fn directory(&self, args: &Map<String, Value>) -> Result<&Identity, MethodError> {
        let identity =
            self.jmap.identity.as_ref().ok_or_else(|| MethodError::new("unknownMethod", "no principals here"))?;
        if args.get("accountId").and_then(Value::as_str) != Some(self.caller.account.to_string().as_str()) {
            return Err(MethodError::new("accountNotFound", "principals are in the caller's own account"));
        }
        Ok(identity)
    }

    pub async fn principal_get(&self, args: Map<String, Value>) -> MethodResult {
        let identity = self.directory(&args)?;
        let all = principals(identity, self.caller.tenant).await?;
        let mut list = Vec::new();
        let mut not_found = Vec::new();
        match ids(&args)? {
            None => list.extend(all.iter().map(Principal::object)),
            Some(wanted) => {
                if wanted.len() > MAX_OBJECTS_IN_GET {
                    return Err(MethodError::new("requestTooLarge", "too many ids"));
                }
                for id in wanted {
                    match all.iter().find(|principal| principal.id == id) {
                        Some(principal) => list.push(principal.object()),
                        None => not_found.push(id),
                    }
                }
            }
        }
        Ok(vec![(
            "Principal/get".into(),
            json!({ "accountId": self.caller.account.to_string(), "state": "0", "list": list, "notFound": not_found }),
        )])
    }

    pub async fn principal_query(&self, args: Map<String, Value>) -> MethodResult {
        let identity = self.directory(&args)?;
        let filter = args.get("filter").and_then(Value::as_object).cloned().unwrap_or_default();
        let ids: Vec<String> = principals(identity, self.caller.tenant)
            .await?
            .into_iter()
            .filter(|principal| matches(principal, &filter))
            .map(|principal| principal.id)
            .collect();
        let total = ids.len();
        let position = args.get("position").and_then(Value::as_u64).unwrap_or(0) as usize;
        let limit = args.get("limit").and_then(Value::as_u64).map_or(usize::MAX, |limit| limit as usize);
        let page: Vec<&String> = ids.iter().skip(position).take(limit).collect();
        Ok(vec![(
            "Principal/query".into(),
            json!({
                "accountId": self.caller.account.to_string(),
                "queryState": "0",
                "canCalculateChanges": false,
                "position": position.min(total),
                "ids": page,
                "total": total,
            }),
        )])
    }
}
