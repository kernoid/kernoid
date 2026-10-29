// SPDX-License-Identifier: AGPL-3.0-or-later
//! The tree a tenant's directory is read as (RFC 0003, 8): `o=<tenant>` with `ou=people` – each person as
//! `uid=<login>` (`inetOrgPerson`) – and `ou=groups` – each group as `cn=<name>` (`groupOfNames`); the root DSE; and
//! what a search asks of it: which entries lie in its scope, which its filter matches, which attributes it returns.

use std::collections::HashMap;

use kernoid_identity::directory::Directory;
use ldap3_proto::proto::{
    LdapFilter, LdapPartialAttribute, LdapSearchResultEntry, LdapSearchScope, LdapSubstringFilter,
};
use uuid::Uuid;

/// StartTLS (RFC 4511, 4.14).
pub const OID_START_TLS: &str = "1.3.6.1.4.1.1466.20037";
/// Who am I? (RFC 4532).
pub const OID_WHOAMI: &str = ldap3_proto::proto::OID_WHOAMI;
/// Simple paged results (RFC 2696).
pub const OID_PAGED_RESULTS: &str = "1.2.840.113556.1.4.319";

/// Attributes returned only when asked for by name or with `+` (RFC 4511, 4.5.1.8).
const OPERATIONAL: [&str; 2] = ["entryuuid", "entrydn"];

/// An entry: its DN and attributes, values as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub dn: String,
    pub attributes: Vec<(String, Vec<String>)>,
}

impl Entry {
    fn new(dn: String) -> Self {
        Self { dn, attributes: Vec::new() }
    }

    fn with(mut self, name: &str, values: Vec<String>) -> Self {
        if !values.is_empty() {
            self.attributes.push((name.to_owned(), values));
        }
        self
    }

    fn values(&self, name: &str) -> Option<&[String]> {
        if name.eq_ignore_ascii_case("entrydn") {
            return None;
        }
        self.attributes.iter().find(|(own, _)| own.eq_ignore_ascii_case(name)).map(|(_, values)| values.as_slice())
    }
}

/// A value in a DN, escaped (RFC 4514, 2.4).
pub fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let last = value.chars().count().saturating_sub(1);
    for (index, c) in value.chars().enumerate() {
        let edge = (index == 0 && (c == ' ' || c == '#')) || (index == last && c == ' ');
        if edge || matches!(c, '"' | '+' | ',' | ';' | '<' | '>' | '\\' | '=') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A DN as it is compared: attribute types in lower case, no spaces around `,` and `=`, values in lower case – the
/// directory's values compare without case.
pub fn normalize(dn: &str) -> String {
    let mut out = String::with_capacity(dn.len());
    let mut escaped = false;
    for c in dn.trim().chars() {
        if escaped {
            out.extend(c.to_lowercase());
            escaped = false;
            continue;
        }
        match c {
            '\\' => {
                out.push('\\');
                escaped = true;
            }
            ' ' if out.ends_with(',') || out.ends_with('=') => {}
            ',' | '=' => {
                while out.ends_with(' ') && !out.ends_with("\\ ") {
                    out.pop();
                }
                out.push(c);
            }
            _ => out.extend(c.to_lowercase()),
        }
    }
    out
}

/// The value of a DN's first RDN if it is `uid=…`, unescaped – how a bind names an account – or `None`.
pub fn bind_login(dn: &str) -> Option<String> {
    let rest = dn.trim().strip_prefix("uid=").or_else(|| dn.trim().strip_prefix("UID="))?;
    let mut login = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => login.extend(chars.next()),
            ',' => break,
            _ => login.push(c),
        }
    }
    Some(login.trim().to_owned())
}

pub fn base_dn(tenant: Uuid) -> String {
    format!("o={tenant}")
}

pub fn person_dn(tenant: Uuid, login: &str) -> String {
    format!("uid={},ou=people,{}", escape(login), base_dn(tenant))
}

/// The entries of a tenant's tree, the tree's own first.
pub fn entries(tenant: Uuid, directory: &Directory) -> Vec<Entry> {
    let base = base_dn(tenant);
    let people_dn = format!("ou=people,{base}");
    let groups_dn = format!("ou=groups,{base}");
    let group_dns: HashMap<Uuid, String> =
        directory.groups.iter().map(|group| (group.id, format!("cn={},{groups_dn}", escape(&group.name)))).collect();
    let person_dns: HashMap<Uuid, String> =
        directory.people.iter().map(|person| (person.id, person_dn(tenant, &person.login))).collect();
    let mut out = vec![
        Entry::new(base.clone())
            .with("objectClass", vec!["top".into(), "organization".into()])
            .with("o", vec![tenant.to_string()]),
        Entry::new(people_dn)
            .with("objectClass", vec!["top".into(), "organizationalUnit".into()])
            .with("ou", vec!["people".into()]),
        Entry::new(groups_dn)
            .with("objectClass", vec!["top".into(), "organizationalUnit".into()])
            .with("ou", vec!["groups".into()]),
    ];
    for person in &directory.people {
        let name = if person.display_name.is_empty() { person.login.clone() } else { person.display_name.clone() };
        // `person` needs a surname: the last word of the name.
        let surname = name.split_whitespace().last().unwrap_or(&name).to_owned();
        let given = name.rsplit_once(' ').map(|(given, _)| given.to_owned());
        out.push(
            Entry::new(person_dns[&person.id].clone())
                .with(
                    "objectClass",
                    vec!["top".into(), "person".into(), "organizationalPerson".into(), "inetOrgPerson".into()],
                )
                .with("uid", vec![person.login.clone()])
                .with("cn", vec![name.clone()])
                .with("displayName", vec![name])
                .with("sn", vec![surname])
                .with("givenName", given.into_iter().collect())
                .with("mail", person.addresses.clone())
                .with("memberOf", person.groups.iter().filter_map(|group| group_dns.get(group).cloned()).collect())
                .with("entryUUID", vec![person.id.to_string()]),
        );
    }
    for group in &directory.groups {
        out.push(
            Entry::new(group_dns[&group.id].clone())
                .with("objectClass", vec!["top".into(), "groupOfNames".into()])
                .with("cn", vec![group.name.clone()])
                .with("mail", group.addresses.clone())
                .with("member", group.members.iter().filter_map(|member| person_dns.get(member).cloned()).collect())
                .with("entryUUID", vec![group.id.to_string()]),
        );
    }
    out
}

/// The root DSE (RFC 4512, 5.1): what the server offers, and the tree of whoever is bound.
pub fn root_dse(naming_context: Option<String>) -> Entry {
    Entry::new(String::new())
        .with("objectClass", vec!["top".into()])
        .with("namingContexts", naming_context.into_iter().collect())
        .with("supportedLDAPVersion", vec!["3".into()])
        .with("supportedExtension", vec![OID_START_TLS.into(), OID_WHOAMI.into()])
        .with("supportedControl", vec![OID_PAGED_RESULTS.into()])
        .with("vendorName", vec!["kernoid".into()])
        .with("vendorVersion", vec![env!("CARGO_PKG_VERSION").into()])
}

/// Whether `entry` (normalized DN) lies in the scope of `base` (normalized DN).
pub fn in_scope(entry: &str, base: &str, scope: &LdapSearchScope) -> bool {
    let below = |dn: &str| base.is_empty() || dn.ends_with(&format!(",{base}"));
    let parent = |dn: &str| dn.split_once(',').map(|(_, parent)| parent.to_owned()).unwrap_or_default();
    match scope {
        LdapSearchScope::Base => entry == base,
        LdapSearchScope::OneLevel => entry != base && parent(entry) == base,
        LdapSearchScope::Subtree => entry == base || (!entry.is_empty() && below(entry)),
        LdapSearchScope::Children => entry != base && !entry.is_empty() && below(entry),
    }
}

/// Whether `entry` matches `filter` (RFC 4511, 4.5.1.7); values compare without case.
pub fn matches(entry: &Entry, filter: &LdapFilter) -> bool {
    let values = |name: &str| -> Vec<String> {
        if name.eq_ignore_ascii_case("entrydn") {
            return vec![entry.dn.to_lowercase()];
        }
        entry.values(name).map(|values| values.iter().map(|value| value.to_lowercase()).collect()).unwrap_or_default()
    };
    match filter {
        LdapFilter::And(all) => all.iter().all(|filter| matches(entry, filter)),
        LdapFilter::Or(any) => any.iter().any(|filter| matches(entry, filter)),
        LdapFilter::Not(filter) => !matches(entry, filter),
        LdapFilter::Equality(name, value) | LdapFilter::Approx(name, value) => {
            let value = value.to_lowercase();
            if name.eq_ignore_ascii_case("member") || name.eq_ignore_ascii_case("memberof") {
                values(name).iter().any(|own| normalize(own) == normalize(&value))
            } else {
                values(name).contains(&value)
            }
        }
        LdapFilter::Present(name) => !values(name).is_empty(),
        LdapFilter::Substring(name, substring) => values(name).iter().any(|value| substring_matches(value, substring)),
        LdapFilter::GreaterOrEqual(name, value) => values(name).iter().any(|own| *own >= value.to_lowercase()),
        LdapFilter::LessOrEqual(name, value) => values(name).iter().any(|own| *own <= value.to_lowercase()),
        LdapFilter::Extensible(_) => false,
    }
}

fn substring_matches(value: &str, filter: &LdapSubstringFilter) -> bool {
    let mut rest = value;
    if let Some(initial) = &filter.initial {
        let Some(after) = rest.strip_prefix(initial.to_lowercase().as_str()) else { return false };
        rest = after;
    }
    for any in &filter.any {
        let any = any.to_lowercase();
        let Some(at) = rest.find(&any) else { return false };
        rest = &rest[at + any.len()..];
    }
    match &filter.final_ {
        Some(last) => rest.ends_with(last.to_lowercase().as_str()),
        None => true,
    }
}

/// The entry as a search returns it: the attributes asked for (none: all user attributes; `*` all user attributes;
/// `+` the operational ones; `1.1` none), only their names if `types_only`.
pub fn result(entry: &Entry, asked: &[String], types_only: bool) -> LdapSearchResultEntry {
    let all_user = asked.is_empty() || asked.iter().any(|name| name == "*");
    let all_operational = asked.iter().any(|name| name == "+");
    let wanted = |name: &str| {
        let operational = OPERATIONAL.contains(&name.to_lowercase().as_str());
        (if operational { all_operational } else { all_user }) || asked.iter().any(|own| own.eq_ignore_ascii_case(name))
    };
    let mut attributes: Vec<LdapPartialAttribute> = entry
        .attributes
        .iter()
        .filter(|(name, _)| wanted(name))
        .map(|(name, values)| LdapPartialAttribute {
            atype: name.clone(),
            vals: if types_only { Vec::new() } else { values.iter().map(|value| value.clone().into_bytes()).collect() },
        })
        .collect();
    if wanted("entryDN") && !entry.dn.is_empty() {
        attributes.push(LdapPartialAttribute {
            atype: "entryDN".into(),
            vals: if types_only { Vec::new() } else { vec![entry.dn.clone().into_bytes()] },
        });
    }
    LdapSearchResultEntry { dn: entry.dn.clone(), attributes }
}

#[cfg(test)]
mod tests {
    use kernoid_identity::directory::{Group, Person};

    use super::*;

    fn directory() -> (Uuid, Directory, Uuid, Uuid) {
        let (tenant, alice, staff) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let directory = Directory {
            people: vec![Person {
                id: alice,
                login: "alice@firma.example".into(),
                display_name: "Alice Liddell".into(),
                addresses: vec!["alice@firma.example".into(), "a@firma.example".into()],
                groups: vec![staff],
            }],
            groups: vec![Group {
                id: staff,
                name: "Staff, all".into(),
                addresses: vec!["staff@firma.example".into()],
                members: vec![alice],
            }],
        };
        (tenant, directory, alice, staff)
    }

    #[test]
    fn the_tree_has_people_and_groups() {
        let (tenant, directory, alice, _) = directory();
        let entries = entries(tenant, &directory);
        let dns: Vec<&str> = entries.iter().map(|entry| entry.dn.as_str()).collect();
        let base = format!("o={tenant}");
        assert_eq!(
            dns,
            [
                base.clone(),
                format!("ou=people,{base}"),
                format!("ou=groups,{base}"),
                format!("uid=alice@firma.example,ou=people,{base}"),
                format!("cn=Staff\\, all,ou=groups,{base}"),
            ]
        );
        let person = &entries[3];
        assert_eq!(person.values("SN").unwrap(), ["Liddell"]);
        assert_eq!(person.values("givenName").unwrap(), ["Alice"]);
        assert_eq!(person.values("memberOf").unwrap(), [format!("cn=Staff\\, all,ou=groups,{base}")]);
        assert_eq!(entries[4].values("member").unwrap(), std::slice::from_ref(&person.dn));
        assert_eq!(person.values("entryUUID").unwrap(), [alice.to_string()]);
    }

    #[test]
    fn filters_and_scopes_select() {
        let (tenant, directory, _, _) = directory();
        let entries = entries(tenant, &directory);
        let person = &entries[3];
        use LdapFilter::*;
        let eq = |name: &str, value: &str| Equality(name.into(), value.into());
        let sub = |name: &str, initial: Option<&str>, any: &[&str], last: Option<&str>| {
            Substring(
                name.into(),
                LdapSubstringFilter {
                    initial: initial.map(str::to_owned),
                    any: any.iter().map(|part| (*part).to_owned()).collect(),
                    final_: last.map(str::to_owned),
                },
            )
        };
        let member_of = format!("CN=Staff\\, all, OU=groups, o={tenant}");
        for (name, filter, expected) in [
            ("class", eq("objectClass", "inetOrgPerson"), true),
            ("class without case", eq("objectclass", "INETORGPERSON"), true),
            ("and", And(vec![eq("objectClass", "person"), eq("mail", "A@firma.example")]), true),
            ("or", Or(vec![sub("uid", Some("bob"), &[], None), sub("cn", None, &["lid"], None)]), true),
            ("not", Not(Box::new(Present("mail".into()))), false),
            ("initial and final", sub("uid", Some("alice@"), &[], Some(".example")), true),
            ("final", sub("uid", None, &[], Some("@other.example")), false),
            ("member of", eq("memberOf", &member_of), true),
            ("absent", Present("telephoneNumber".into()), false),
        ] {
            assert_eq!(matches(person, &filter), expected, "{name}");
        }
        let base = normalize(&format!("ou=people, o={tenant}"));
        let dn = normalize(&person.dn);
        assert!(in_scope(&dn, &base, &LdapSearchScope::OneLevel));
        assert!(in_scope(&dn, &normalize(&format!("o={tenant}")), &LdapSearchScope::Subtree));
        assert!(!in_scope(&dn, &normalize(&format!("o={tenant}")), &LdapSearchScope::OneLevel));
        assert!(!in_scope(&dn, &base, &LdapSearchScope::Base));
    }

    #[test]
    fn attributes_are_chosen() {
        let (tenant, directory, _, _) = directory();
        let person = &entries(tenant, &directory)[3];
        let names = |asked: &[&str]| -> Vec<String> {
            let asked: Vec<String> = asked.iter().map(|name| (*name).to_owned()).collect();
            result(person, &asked, false).attributes.into_iter().map(|attribute| attribute.atype).collect()
        };
        assert!(names(&[]).contains(&"mail".to_owned()) && !names(&[]).contains(&"entryUUID".to_owned()));
        assert_eq!(names(&["MAIL", "entryuuid"]), ["mail", "entryUUID"]);
        assert!(names(&["+"]).contains(&"entryDN".to_owned()));
        assert!(names(&["1.1"]).is_empty());
        assert!(result(person, &["mail".into()], true).attributes[0].vals.is_empty());
    }

    #[test]
    fn dns_are_escaped_and_read() {
        assert_eq!(escape(" a,b+c "), "\\ a\\,b\\+c\\ ");
        assert_eq!(normalize("UID=Alice@Firma.example, OU=People ,O=x"), "uid=alice@firma.example,ou=people,o=x");
        assert_eq!(bind_login("uid=alice@firma.example,ou=people,o=x").as_deref(), Some("alice@firma.example"));
        assert_eq!(bind_login("uid=a\\,b,ou=people").as_deref(), Some("a,b"));
        assert_eq!(bind_login("alice@firma.example"), None);
    }
}
