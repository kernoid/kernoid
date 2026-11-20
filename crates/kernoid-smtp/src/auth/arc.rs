// SPDX-License-Identifier: AGPL-3.0-or-later
//! ARC (RFC 8617): the chain of custody intermediaries add – per hop a set of `ARC-Authentication-Results`,
//! `ARC-Message-Signature` (a DKIM signature with an instance) and `ARC-Seal` (a signature over the sets so far).
//! `verify` is the validator of section 5.2; `seal` adds a set (section 5.1), which kernoid itself does not do on its
//! way – it is here for the tests of the chain and for later.

use base64::Engine;

use super::{
    dkim::{self, Algorithm, DkimResult, Kind, Signature, SigningKey},
    message::{Canonicalization, Header, Message},
    tags::{self, Tag},
};
use crate::Dns;

/// At most this many sets (RFC 8617, 4.2.1).
const MAX_SETS: u32 = 50;

/// The chain validation status (RFC 8617, 4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArcResult {
    Pass,
    /// Why the chain failed.
    Fail(String),
    None,
}

impl ArcResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail(_) => "fail",
            Self::None => "none",
        }
    }
}

/// What the check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcOutput {
    pub result: ArcResult,
    /// The number of sets.
    pub sets: u32,
}

/// An `ARC-Seal`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seal {
    instance: u32,
    algorithm: Algorithm,
    domain: String,
    selector: String,
    signature: Vec<u8>,
    cv: String,
}

impl Seal {
    fn parse(value: &[u8]) -> Result<(Self, Vec<Tag>), String> {
        let tags = tags::parse(value).map_err(|error| format!("ARC-Seal syntax: {error}"))?;
        let get = |name: &str| tags::get(&tags, name).ok_or_else(|| format!("the ARC-Seal has no {name}="));
        if tags.iter().any(|tag| tag.name == "h") {
            return Err("the ARC-Seal has h=".into());
        }
        let seal = Self {
            instance: instance(get("i")?).ok_or("the ARC-Seal's instance is not 1 to 50")?,
            algorithm: Algorithm::parse(get("a")?).ok_or("an unknown signing algorithm")?,
            domain: dkim::domain_name(get("d")?).ok_or("d= is not a domain")?,
            selector: dkim::domain_name(get("s")?).ok_or("s= is not a selector")?,
            signature: base64::engine::general_purpose::STANDARD
                .decode(tags::compact(get("b")?))
                .map_err(|_| "b= is not base64")?,
            cv: get("cv")?.trim().to_ascii_lowercase(),
        };
        Ok((seal, tags))
    }
}

fn instance(value: &str) -> Option<u32> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= 2 && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())?
        .filter(|instance| (1..=MAX_SETS).contains(instance))
}

/// The instance of an `ARC-Authentication-Results`: its value starts with `i=<n>;` (RFC 8617, 4.1.1).
fn results_instance(header: &Header<'_>) -> Option<u32> {
    let text = header.text();
    let (first, _) = text.split_once(';')?;
    let (name, value) = first.split_once('=')?;
    (name.trim() == "i").then(|| instance(value))?
}

/// One set of the chain.
struct Set<'a, 'm> {
    results: &'a Header<'m>,
    message_signature: (&'a Header<'m>, Signature, Vec<Tag>),
    seal: (&'a Header<'m>, Seal, Vec<Tag>),
}

/// The sets of `message` in order of their instances, or why the chain is broken (RFC 8617, 5.2, steps 1 and 3).
fn sets<'a, 'm>(message: &'a Message<'m>) -> Result<Vec<Set<'a, 'm>>, String> {
    type Slot<'a, 'm> = (
        Option<&'a Header<'m>>,
        Option<(&'a Header<'m>, Signature, Vec<Tag>)>,
        Option<(&'a Header<'m>, Seal, Vec<Tag>)>,
    );
    let mut slots: Vec<Slot<'a, 'm>> = Vec::new();
    let slot = |slots: &mut Vec<Slot<'a, 'm>>, instance: u32| -> usize {
        let index = instance as usize - 1;
        while slots.len() <= index {
            slots.push((None, None, None));
        }
        index
    };
    for header in &message.headers {
        if header.is("ARC-Authentication-Results") {
            let instance = results_instance(header).ok_or("an ARC-Authentication-Results without instance")?;
            let index = slot(&mut slots, instance);
            if slots[index].0.replace(header).is_some() {
                return Err(format!("two ARC-Authentication-Results of instance {instance}"));
            }
        } else if header.is("ARC-Message-Signature") {
            let (signature, tags) = Signature::parse(header.value(), Kind::ArcMessage)?;
            let instance = signature.instance;
            let index = slot(&mut slots, instance);
            if slots[index].1.replace((header, signature, tags)).is_some() {
                return Err(format!("two ARC-Message-Signatures of instance {instance}"));
            }
        } else if header.is("ARC-Seal") {
            let (seal, tags) = Seal::parse(header.value())?;
            let instance = seal.instance;
            let index = slot(&mut slots, instance);
            if slots[index].2.replace((header, seal, tags)).is_some() {
                return Err(format!("two ARC-Seals of instance {instance}"));
            }
        }
    }
    let mut sets = Vec::with_capacity(slots.len());
    for (index, slot) in slots.into_iter().enumerate() {
        let (Some(results), Some(message_signature), Some(seal)) = slot else {
            return Err(format!("the set of instance {} is incomplete", index + 1));
        };
        sets.push(Set { results, message_signature, seal });
    }
    Ok(sets)
}

/// What an `ARC-Seal` of the set at `index` signs: the sets up to it, its own `b=` empty (RFC 8617, 5.1.1).
fn sealed_data(sets: &[Set<'_, '_>], index: usize) -> Vec<u8> {
    let mut data = Vec::new();
    for (position, set) in sets[..=index].iter().enumerate() {
        Canonicalization::Relaxed.header(set.results.raw, &mut data);
        Canonicalization::Relaxed.header(set.message_signature.0.raw, &mut data);
        if position == index {
            data.extend_from_slice(&dkim::without_b(set.seal.0, &set.seal.2, Canonicalization::Relaxed));
        } else {
            Canonicalization::Relaxed.header(set.seal.0.raw, &mut data);
        }
    }
    data
}

/// Validates the chain of `message` (RFC 8617, 5.2).
pub async fn verify(dns: &Dns, message: &Message<'_>) -> ArcOutput {
    let any = message.headers.iter().any(|header| {
        header.is("ARC-Seal") || header.is("ARC-Message-Signature") || header.is("ARC-Authentication-Results")
    });
    if !any {
        return ArcOutput { result: ArcResult::None, sets: 0 };
    }
    let fail = |reason: String, sets: u32| ArcOutput { result: ArcResult::Fail(reason), sets };
    let sets = match sets(message) {
        Ok(sets) => sets,
        Err(reason) => return fail(reason, 0),
    };
    let count = sets.len() as u32;
    let Some(last) = sets.last() else { return fail("no complete set".into(), 0) };
    if last.seal.1.cv == "fail" {
        return fail("the last seal says the chain failed".into(), count);
    }
    for (index, set) in sets.iter().enumerate() {
        let expected = if index == 0 { "none" } else { "pass" };
        if set.seal.1.cv != expected {
            return fail(format!("cv={} in the set of instance {}", set.seal.1.cv, index + 1), count);
        }
    }
    let (header, signature, tags) = &last.message_signature;
    let (result, _) = dkim::check(dns, message, header, signature, tags).await;
    if result != DkimResult::Pass {
        return fail(format!("the newest message signature: {}", result.reason().unwrap_or(result.as_str())), count);
    }
    for index in (0..sets.len()).rev() {
        let seal = &sets[index].seal.1;
        if seal.algorithm == Algorithm::RsaSha1 {
            return fail("rsa-sha1 is no longer accepted (RFC 8301)".into(), count);
        }
        let key = match dkim::key(dns, &seal.selector, &seal.domain).await {
            Ok(key) => key,
            Err(result) => {
                return fail(format!("the key of seal {}: {}", index + 1, result.reason().unwrap_or("")), count);
            }
        };
        if !key.verifies(seal.algorithm, &sealed_data(&sets, index), &seal.signature) {
            return fail(format!("the seal of instance {} did not verify", index + 1), count);
        }
    }
    ArcOutput { result: ArcResult::Pass, sets: count }
}

/// Adds a set to `raw` (RFC 8617, 5.1): `results` are the authentication results this hop found (as in
/// `Authentication-Results` after the authserv-id), `chain` what `verify` found. The three headers, `ARC-Seal`
/// first, with their line ends – to be put in front of the message.
#[allow(clippy::too_many_arguments)]
pub fn seal(
    raw: &[u8],
    chain: &ArcOutput,
    key: &SigningKey,
    domain: &str,
    selector: &str,
    authserv_id: &str,
    results: &str,
    headers: &[&str],
) -> Result<String, String> {
    let instance = chain.sets + 1;
    if instance > MAX_SETS {
        return Err("the chain is full".into());
    }
    let cv = match (&chain.result, chain.sets) {
        (_, 0) => "none",
        (ArcResult::Pass, _) => "pass",
        _ => "fail",
    };
    let message = Message::parse(raw);
    let results = format!("ARC-Authentication-Results: i={instance}; {authserv_id};\r\n\t{results}\r\n");

    // The message signature: DKIM's, with the instance in place of the version.
    let names: Vec<String> = headers
        .iter()
        .flat_map(|name| std::iter::repeat_n(name.to_ascii_lowercase(), message.all(name).count()))
        .collect();
    let body_hash = dkim::body_hash(message.body, Canonicalization::Relaxed, None).unwrap_or_default();
    let tags = [
        ("i", instance.to_string()),
        ("a", key.algorithm().as_str().to_owned()),
        ("d", domain.to_owned()),
        ("s", selector.to_owned()),
        ("c", "relaxed/relaxed".to_owned()),
        ("h", names.join(":")),
        ("t", dkim::now().to_string()),
        ("bh", base64::engine::general_purpose::STANDARD.encode(body_hash)),
    ];
    let signed = dkim::signed_headers(&message, &names, Canonicalization::Relaxed);
    let message_signature = dkim::finish("ARC-Message-Signature", &tags, key, signed)?;

    // The seal: the earlier sets as they are – or, for a failed chain, only the new one (5.1.2).
    let mut data = Vec::new();
    if cv != "fail" {
        let earlier = sets(&message)?;
        for set in &earlier {
            Canonicalization::Relaxed.header(set.results.raw, &mut data);
            Canonicalization::Relaxed.header(set.message_signature.0.raw, &mut data);
            Canonicalization::Relaxed.header(set.seal.0.raw, &mut data);
        }
    }
    Canonicalization::Relaxed.header(results.as_bytes(), &mut data);
    Canonicalization::Relaxed.header(message_signature.as_bytes(), &mut data);
    let tags = [
        ("i", instance.to_string()),
        ("a", key.algorithm().as_str().to_owned()),
        ("t", dkim::now().to_string()),
        ("cv", cv.to_owned()),
        ("d", domain.to_owned()),
        ("s", selector.to_owned()),
    ];
    let seal = dkim::finish("ARC-Seal", &tags, key, data)?;
    Ok(format!("{seal}{message_signature}{results}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::dkim::tests::{ed25519_key, publish, rsa_key};

    const MESSAGE: &str = "From: Alice <alice@origin.example>\r\nTo: list@lists.example\r\nSubject: Hello\r\n\r\nHi all.\r\n";
    const HEADERS: [&str; 3] = ["From", "To", "Subject"];

    #[tokio::test]
    async fn chains_of_one_and_two_hops() {
        let dns = Dns::offline();
        let first = rsa_key();
        let second = ed25519_key();
        publish(&dns, "arc", "lists.example", &first);
        publish(&dns, "arc2", "relay.example", &second);
        let raw = MESSAGE.as_bytes();
        assert_eq!(verify(&dns, &Message::parse(raw)).await, ArcOutput { result: ArcResult::None, sets: 0 });

        let none = ArcOutput { result: ArcResult::None, sets: 0 };
        let set = seal(raw, &none, &first, "lists.example", "arc", "lists.example", "spf=pass smtp.mailfrom=origin.example", &HEADERS).unwrap();
        let one = format!("{set}{MESSAGE}");
        let output = verify(&dns, &Message::parse(one.as_bytes())).await;
        assert_eq!(output, ArcOutput { result: ArcResult::Pass, sets: 1 });

        // The list changes the subject and seals again; the chain still holds.
        let changed = one.replace("Subject: Hello", "Subject: [list] Hello");
        let chain = verify(&dns, &Message::parse(changed.as_bytes())).await;
        assert!(matches!(chain.result, ArcResult::Fail(_)), "the old message signature no longer holds");
        let checked = verify(&dns, &Message::parse(one.as_bytes())).await;
        let set = seal(one.as_bytes(), &checked, &second, "relay.example", "arc2", "relay.example", "arc=pass", &HEADERS).unwrap();
        assert!(set.contains("cv=pass"));
        let two = format!("{set}{one}");
        assert_eq!(verify(&dns, &Message::parse(two.as_bytes())).await, ArcOutput { result: ArcResult::Pass, sets: 2 });

        // Tampering with an earlier set breaks the seals; removing a header breaks the structure.
        let tampered = two.replace("spf=pass smtp.mailfrom=origin.example", "spf=pass smtp.mailfrom=evil.example");
        let output = verify(&dns, &Message::parse(tampered.as_bytes())).await;
        assert!(matches!(&output.result, ArcResult::Fail(reason) if reason.contains("did not verify")), "{output:?}");
        let first_results = two.find("ARC-Authentication-Results: i=1").unwrap();
        let end = first_results + two[first_results..].find("\r\n\t").unwrap();
        let end = end + two[end + 3..].find("\r\n").unwrap() + 5;
        let missing = format!("{}{}", &two[..first_results], &two[end..]);
        let output = verify(&dns, &Message::parse(missing.as_bytes())).await;
        assert!(matches!(&output.result, ArcResult::Fail(reason) if reason.contains("incomplete")), "{output:?}");
    }

    #[tokio::test]
    async fn seals_that_say_the_chain_failed() {
        let dns = Dns::offline();
        let key = ed25519_key();
        publish(&dns, "arc", "lists.example", &key);
        let broken = ArcOutput { result: ArcResult::Fail("x".into()), sets: 1 };
        let set = seal(MESSAGE.as_bytes(), &broken, &key, "lists.example", "arc", "lists.example", "arc=fail", &HEADERS).unwrap();
        assert!(set.contains("cv=fail") && set.contains("i=2"));
        let raw = format!("{set}{MESSAGE}");
        let output = verify(&dns, &Message::parse(raw.as_bytes())).await;
        assert!(matches!(&output.result, ArcResult::Fail(_)), "{output:?}");
        // A first set must say cv=none.
        let fake = seal(MESSAGE.as_bytes(), &ArcOutput { result: ArcResult::None, sets: 0 }, &key, "lists.example", "arc", "x", "y=z", &HEADERS)
            .unwrap()
            .replace("cv=none", "cv=pass");
        let output = verify(&dns, &Message::parse(format!("{fake}{MESSAGE}").as_bytes())).await;
        assert!(matches!(&output.result, ArcResult::Fail(reason) if reason.contains("cv=pass")), "{output:?}");
    }

    #[test]
    fn broken_headers_are_failures_not_panics() {
        for raw in [
            "ARC-Seal: i=0; a=rsa-sha256; cv=none; d=x.example; s=s; b=AA==\r\n\r\n",
            "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=x.example; s=s; b=AA==; h=from\r\n\r\n",
            "ARC-Authentication-Results: spf=pass\r\n\r\n",
            "ARC-Message-Signature: a=rsa-sha256; d=x.example; s=s; b=AA==; bh=AA==; h=from\r\n\r\n",
        ] {
            let message = Message::parse(raw.as_bytes());
            assert!(sets(&message).is_err(), "{raw}");
        }
    }
}
