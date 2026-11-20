// SPDX-License-Identifier: MIT
//! JMAP's helpers for objects (RFC 8620): JSON Pointers (RFC 6901, with JMAP's `*` for every item) and `PatchObject`
//! (5.3) – keys are pointers into the object, values replace, `null` removes.

use serde_json::{Map, Value};

/// The parts of a JSON Pointer, its escapes undone (`~1` is `/`, `~0` is `~`); a leading `/` is optional, as in a
/// `PatchObject`'s keys.
pub fn pointer_parts(pointer: &str) -> Vec<String> {
    let pointer = pointer.strip_prefix('/').unwrap_or(pointer);
    if pointer.is_empty() {
        return Vec::new();
    }
    pointer.split('/').map(|part| part.replace("~1", "/").replace("~0", "~")).collect()
}

/// A part of a pointer escaped.
pub fn escape_part(part: &str) -> String {
    part.replace('~', "~0").replace('/', "~1")
}

/// What a pointer reaches in a value; `*` takes every item of an array (or value of an object), so the result may be
/// several values (RFC 8620, 3.7).
pub fn evaluate<'a>(value: &'a Value, pointer: &str) -> Vec<&'a Value> {
    let mut current = vec![value];
    for part in pointer_parts(pointer) {
        let mut next = Vec::new();
        for value in current {
            match (value, part.as_str()) {
                (Value::Array(items), "*") => {
                    for item in items {
                        match item {
                            Value::Array(inner) => next.extend(inner.iter()),
                            other => next.push(other),
                        }
                    }
                }
                (Value::Object(map), "*") => next.extend(map.values()),
                (Value::Array(items), index) => {
                    if let Some(item) = index.parse::<usize>().ok().and_then(|index| items.get(index)) {
                        next.push(item);
                    }
                }
                (Value::Object(map), key) => {
                    if let Some(item) = map.get(key) {
                        next.push(item);
                    }
                }
                _ => {}
            }
        }
        current = next;
    }
    current
}

/// Why a patch could not be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchError(pub String);

impl std::fmt::Display for PatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PatchError {}

/// Applies a `PatchObject`: each key a pointer to a property in an object that exists (all parts but the last), the
/// value set, `null` removing it. A patch that sets a property and another inside it is refused.
pub fn patch(object: &mut Map<String, Value>, patch: &Map<String, Value>) -> Result<(), PatchError> {
    let paths: Vec<Vec<String>> = patch.keys().map(|key| pointer_parts(key)).collect();
    for (index, path) in paths.iter().enumerate() {
        if path.is_empty() {
            return Err(PatchError("an empty path".into()));
        }
        if paths
            .iter()
            .enumerate()
            .any(|(other, prefix)| other != index && path.len() > prefix.len() && path.starts_with(prefix))
        {
            return Err(PatchError(format!("{}: patched and changed inside", path.join("/"))));
        }
    }
    for (key, value) in patch {
        let parts = pointer_parts(key);
        let (last, parents) = parts.split_last().expect("checked");
        let mut current = &mut *object;
        for part in parents {
            current = match current.get_mut(part) {
                Some(Value::Object(next)) => next,
                _ => return Err(PatchError(format!("{key}: no such object"))),
            };
        }
        if value.is_null() {
            current.remove(last);
        } else {
            current.insert(last.clone(), value.clone());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn patches_and_pointers() {
        let mut object = json!({ "name": { "full": "Ann", "x": 1 }, "a/b": 2, "list": [{ "id": 1 }, { "id": 2 }] });
        let Value::Object(map) = &mut object else { unreachable!() };
        let change = json!({ "name/full": "Ann B.", "name/x": null, "a~1b": 3 });
        patch(map, change.as_object().unwrap()).unwrap();
        assert_eq!(object, json!({ "name": { "full": "Ann B." }, "a/b": 3, "list": [{ "id": 1 }, { "id": 2 }] }));
        assert_eq!(evaluate(&object, "/list/*/id"), [&json!(1), &json!(2)]);
        assert_eq!(evaluate(&object, "/list/1/id"), [&json!(2)]);
        let Value::Object(map) = &mut object else { unreachable!() };
        assert!(patch(map, json!({ "missing/x": 1 }).as_object().unwrap()).is_err());
        assert!(patch(map, json!({ "name": {}, "name/full": "x" }).as_object().unwrap()).is_err());
        assert_eq!(escape_part("a/~b"), "a~1~0b");
    }
}
