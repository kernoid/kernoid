// SPDX-License-Identifier: AGPL-3.0-or-later
//! The headers WebDAV adds to HTTP (RFC 4918, 10): `Depth`, `Destination`, `If`, `Lock-Token`, `Overwrite` and
//! `Timeout`. A header that cannot be read counts as absent.

use http::HeaderMap;

/// `Depth` (RFC 4918, 10.2). Absent, it is `infinity`, the default of `PROPFIND` and `LOCK`; servers decide what they
/// do with it (kernoid answers `infinity` like `1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Depth {
    Zero,
    One,
    #[default]
    Infinity,
}

impl Depth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Zero => "0",
            Self::One => "1",
            Self::Infinity => "infinity",
        }
    }
}

/// The first value of `Timeout` (RFC 4918, 10.7) that kernoid understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Timeout {
    #[default]
    None,
    Infinite,
    Second(u64),
}

/// One condition of an `If` list (RFC 4918, 10.4): a state token (a lock token) or an entity tag, maybe negated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IfCondition {
    StateToken { is_not: bool, token: String },
    ETag { is_not: bool, tag: String },
}

/// One list of an `If` header, with the resource it is tagged with, if any.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IfList {
    pub resource: Option<String>,
    pub conditions: Vec<IfCondition>,
}

/// The WebDAV headers of a request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestHeaders {
    pub depth: Depth,
    pub timeout: Timeout,
    /// `Lock-Token` without its angle brackets.
    pub lock_token: Option<String>,
    pub destination: Option<String>,
    /// `Overwrite: F`.
    pub overwrite_fail: bool,
    pub if_: Vec<IfList>,
}

impl RequestHeaders {
    pub fn from_map(headers: &HeaderMap) -> Self {
        let get = |name: &str| headers.get(name).and_then(|value| value.to_str().ok()).map(str::trim);
        Self {
            depth: get("depth").map(parse_depth).unwrap_or_default(),
            timeout: get("timeout").map(parse_timeout).unwrap_or_default(),
            lock_token: get("lock-token").map(|value| {
                value.strip_prefix('<').and_then(|value| value.strip_suffix('>')).unwrap_or(value).trim().to_owned()
            }),
            destination: get("destination").map(str::to_owned),
            overwrite_fail: get("overwrite").is_some_and(|value| value.eq_ignore_ascii_case("F")),
            if_: get("if").map(parse_if).unwrap_or_default(),
        }
    }

    /// The lock tokens the `If` header names without `Not`.
    pub fn state_tokens(&self) -> Vec<String> {
        self.if_
            .iter()
            .flat_map(|list| list.conditions.iter())
            .filter_map(|condition| match condition {
                IfCondition::StateToken { is_not: false, token } => Some(token.clone()),
                _ => None,
            })
            .collect()
    }
}

fn parse_depth(value: &str) -> Depth {
    match value {
        "0" => Depth::Zero,
        "1" => Depth::One,
        _ => Depth::Infinity,
    }
}

fn parse_timeout(value: &str) -> Timeout {
    for item in value.split(',').map(str::trim) {
        if item.eq_ignore_ascii_case("Infinite") {
            return Timeout::Infinite;
        }
        if let Some(seconds) = item.get(..7).filter(|prefix| prefix.eq_ignore_ascii_case("Second-")).and(item.get(7..))
            && let Ok(seconds) = seconds.parse()
        {
            return Timeout::Second(seconds);
        }
    }
    Timeout::None
}

/// `If = ( 1*No-tag-list | 1*Tagged-list )`; a list is `"(" 1*Condition ")"`, a condition `["Not"] (Coded-URL |
/// "[" entity-tag "]")`. What does not follow the grammar ends the header.
fn parse_if(value: &str) -> Vec<IfList> {
    let mut lists = Vec::new();
    let mut resource = None;
    let mut rest = value.trim_start();
    while let Some(first) = rest.chars().next() {
        match first {
            '<' => {
                let Some(end) = rest.find('>') else { break };
                resource = Some(rest[1..end].to_owned());
                rest = rest[end + 1..].trim_start();
            }
            '(' => {
                let Some(end) = rest.find(')') else { break };
                let mut inner = rest[1..end].trim_start();
                let mut conditions = Vec::new();
                while !inner.is_empty() {
                    let is_not = inner.len() >= 3 && inner[..3].eq_ignore_ascii_case("not");
                    if is_not {
                        inner = inner[3..].trim_start();
                    }
                    if let Some(after) = inner.strip_prefix('<') {
                        let Some(end) = after.find('>') else { break };
                        conditions.push(IfCondition::StateToken { is_not, token: after[..end].to_owned() });
                        inner = after[end + 1..].trim_start();
                    } else if let Some(after) = inner.strip_prefix('[') {
                        let Some(end) = after.find(']') else { break };
                        conditions.push(IfCondition::ETag { is_not, tag: after[..end].trim().to_owned() });
                        inner = after[end + 1..].trim_start();
                    } else {
                        break;
                    }
                }
                lists.push(IfList { resource: resource.clone(), conditions });
                rest = rest[end + 1..].trim_start();
            }
            _ => break,
        }
    }
    lists
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> RequestHeaders {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_str(value).unwrap());
        }
        RequestHeaders::from_map(&map)
    }

    #[test]
    fn depth_timeout_and_tokens() {
        assert_eq!(headers(&[]).depth, Depth::Infinity);
        assert_eq!(headers(&[("depth", "0")]).depth, Depth::Zero);
        assert_eq!(headers(&[("depth", "1")]).depth, Depth::One);
        assert_eq!(headers(&[("depth", "infinity")]).depth, Depth::Infinity);
        assert_eq!(headers(&[("timeout", "Second-60")]).timeout, Timeout::Second(60));
        assert_eq!(headers(&[("timeout", "Infinite, Second-4100000000")]).timeout, Timeout::Infinite);
        assert_eq!(headers(&[("timeout", "Extended-1, second-5")]).timeout, Timeout::Second(5));
        assert_eq!(headers(&[("timeout", "nonsense")]).timeout, Timeout::None);
        let parsed = headers(&[("lock-token", "<opaquelocktoken:abc>"), ("overwrite", "F"), ("destination", "/x")]);
        assert_eq!(parsed.lock_token.as_deref(), Some("opaquelocktoken:abc"));
        assert!(parsed.overwrite_fail && parsed.destination.as_deref() == Some("/x"));
        assert!(!headers(&[("overwrite", "T")]).overwrite_fail);
    }

    #[test]
    fn if_lists() {
        let parsed =
            headers(&[("if", r#"</a/b> (<urn:uuid:1> ["etag"]) (Not <urn:uuid:2>) <http://h/c>(<urn:uuid:3>)"#)]);
        assert_eq!(
            parsed.if_,
            vec![
                IfList {
                    resource: Some("/a/b".into()),
                    conditions: vec![
                        IfCondition::StateToken { is_not: false, token: "urn:uuid:1".into() },
                        IfCondition::ETag { is_not: false, tag: "\"etag\"".into() },
                    ],
                },
                IfList {
                    resource: Some("/a/b".into()),
                    conditions: vec![IfCondition::StateToken { is_not: true, token: "urn:uuid:2".into() }],
                },
                IfList {
                    resource: Some("http://h/c".into()),
                    conditions: vec![IfCondition::StateToken { is_not: false, token: "urn:uuid:3".into() }],
                },
            ]
        );
        assert_eq!(parsed.state_tokens(), ["urn:uuid:1", "urn:uuid:3"]);
        assert_eq!(headers(&[("if", "(<opaquelocktoken:x>)")]).state_tokens(), ["opaquelocktoken:x"]);
        assert!(headers(&[("if", "garbage")]).if_.is_empty());
    }
}
