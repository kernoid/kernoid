// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relying party's side of WebAuthn (W3C Web Authentication Level 3, 7.1 and 7.2), kernoid's own – the options for
//! the browser, and the checks of its answers: client data (type, challenge, origin), authenticator data (RP ID hash,
//! flags, counter, attested credential data), COSE public keys (RFC 9052/9053: ES256, EdDSA with Ed25519, RS256) and
//! signatures, verified with aws-lc-rs. CBOR through [`super::cbor`].
//!
//! **Attestation:** kernoid asks for none and trusts none: the statement of whatever format arrives is not verified,
//! as WebAuthn allows a relying party that accepts the attestation type None (Level 3, 7.1 step 21; 8.7). What is
//! checked is that the authenticator holds the key it names – by the signature of every later assertion.
//!
//! Part of the external audit before 1.0 (OPEN).

use aws_lc_rs::signature::{self, ParsedPublicKey, RsaPublicKeyComponents};
use base64::{
    Engine,
    alphabet::URL_SAFE,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{RelyingParty, cbor};

/// base64url without padding, as WebAuthn's JSON has it; padding is accepted when reading.
const B64: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new().with_encode_padding(false).with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// How long the browser lets the person answer, in milliseconds.
pub const TIMEOUT_MS: u64 = 300_000;

/// The algorithms kernoid accepts, in its order of preference (COSE identifiers).
pub const ES256: i64 = -7;
pub const EDDSA: i64 = -8;
pub const RS256: i64 = -257;
const ALGORITHMS: [i64; 3] = [ES256, EDDSA, RS256];

/// Flags of the authenticator data (Level 3, 6.1).
const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
const AT: u8 = 0x40;
const ED: u8 = 0x80;

/// A ceremony that did not pass; why stays here (every failure is the same answer outside).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected(pub &'static str);

type Result<T> = std::result::Result<T, Rejected>;

pub fn encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn decode(text: &str) -> Result<Vec<u8>> {
    B64.decode(text).map_err(|_| Rejected("not base64url"))
}

/// The base64url value at `field` of a JSON object.
fn binary(value: &Value, field: &str) -> Result<Vec<u8>> {
    decode(value.get(field).and_then(Value::as_str).ok_or(Rejected("a value is missing"))?)
}

/// A public key of a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "alg")]
pub enum PublicKey {
    /// ECDSA with P-256 and SHA-256: the point's coordinates.
    #[serde(rename = "ES256")]
    Es256 {
        #[serde(with = "base64url")]
        x: Vec<u8>,
        #[serde(with = "base64url")]
        y: Vec<u8>,
    },
    /// EdDSA with Ed25519.
    #[serde(rename = "EdDSA")]
    Ed25519 {
        #[serde(with = "base64url")]
        x: Vec<u8>,
    },
    /// RSASSA-PKCS1-v1_5 with SHA-256: modulus and exponent, big-endian.
    #[serde(rename = "RS256")]
    Rs256 {
        #[serde(with = "base64url")]
        n: Vec<u8>,
        #[serde(with = "base64url")]
        e: Vec<u8>,
    },
}

impl PublicKey {
    /// A COSE key (RFC 9052, 7; RFC 9053, 2.1, 2.2, 7; RFC 8812 for RSA), checked to be usable.
    pub fn from_cose(key: &cbor::Value) -> Result<Self> {
        let int = |label| key.int_key(label).and_then(cbor::Value::as_int);
        let bytes = |label| key.int_key(label).and_then(cbor::Value::as_bytes).map(<[u8]>::to_vec);
        let alg = int(3).ok_or(Rejected("the key names no algorithm"))?;
        let key = match (int(1), alg) {
            // EC2, P-256
            (Some(2), -7) if int(-1) == Some(1) => PublicKey::Es256 {
                x: bytes(-2).filter(|x| x.len() == 32).ok_or(Rejected("the key's x"))?,
                y: bytes(-3).filter(|y| y.len() == 32).ok_or(Rejected("the key's y"))?,
            },
            // OKP, Ed25519 – as EdDSA (-8) or as Ed25519 itself (-19, RFC 9864)
            (Some(1), -8 | -19) if int(-1) == Some(6) => {
                PublicKey::Ed25519 { x: bytes(-2).filter(|x| x.len() == 32).ok_or(Rejected("the key's x"))? }
            }
            // RSA
            (Some(3), -257) => PublicKey::Rs256 {
                n: bytes(-1).ok_or(Rejected("the key's n"))?,
                e: bytes(-2).ok_or(Rejected("the key's e"))?,
            },
            _ => return Err(Rejected("an algorithm kernoid does not accept")),
        };
        key.check()?;
        Ok(key)
    }

    /// The key as COSE – for kernoid's tests.
    pub fn to_cose(&self) -> cbor::Value {
        use cbor::Value::{Bytes, Int};
        cbor::Value::Map(match self {
            PublicKey::Es256 { x, y } => vec![
                (Int(1), Int(2)),
                (Int(3), Int(-7)),
                (Int(-1), Int(1)),
                (Int(-2), Bytes(x.clone())),
                (Int(-3), Bytes(y.clone())),
            ],
            PublicKey::Ed25519 { x } => {
                vec![(Int(1), Int(1)), (Int(3), Int(-8)), (Int(-1), Int(6)), (Int(-2), Bytes(x.clone()))]
            }
            PublicKey::Rs256 { n, e } => {
                vec![(Int(1), Int(3)), (Int(3), Int(-257)), (Int(-1), Bytes(n.clone())), (Int(-2), Bytes(e.clone()))]
            }
        })
    }

    /// Whether aws-lc-rs takes the key: a point on the curve, an RSA key of 2048 to 8192 bits with an odd exponent.
    fn check(&self) -> Result<()> {
        match self {
            PublicKey::Es256 { x, y } => {
                ParsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, [&[4][..], x, y].concat())
                    .map(drop)
                    .map_err(|_| Rejected("not a point of P-256"))
            }
            PublicKey::Ed25519 { x } => {
                ParsedPublicKey::new(&signature::ED25519, x).map(drop).map_err(|_| Rejected("not an Ed25519 key"))
            }
            PublicKey::Rs256 { n, e } => {
                let n = strip(n);
                let e = strip(e);
                let bits = n.len() * 8;
                if !(2048..=8192).contains(&bits) || e.is_empty() || e.len() > 4 || e[e.len() - 1] & 1 == 0 {
                    return Err(Rejected("an RSA key kernoid does not accept"));
                }
                Ok(())
            }
        }
    }

    /// Whether `signature` signs `message` with this key.
    pub fn verify(&self, message: &[u8], signed: &[u8]) -> Result<()> {
        let verified = match self {
            PublicKey::Es256 { x, y } => {
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, [&[4][..], x, y].concat())
                    .verify(message, signed)
            }
            PublicKey::Ed25519 { x } => {
                signature::UnparsedPublicKey::new(&signature::ED25519, x).verify(message, signed)
            }
            PublicKey::Rs256 { n, e } => RsaPublicKeyComponents { n: strip(n), e: strip(e) }.verify(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                message,
                signed,
            ),
        };
        verified.map_err(|_| Rejected("the signature does not verify"))
    }
}

/// Big-endian bytes without leading zeros.
fn strip(bytes: &[u8]) -> &[u8] {
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len());
    &bytes[first..]
}

/// A passkey as kernoid keeps it (`account_passkeys.credential`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    /// The format of this record: 1.
    pub kernoid: u8,
    #[serde(with = "base64url")]
    pub id: Vec<u8>,
    pub key: PublicKey,
    /// The signature counter last seen; 0 for authenticators that keep none.
    pub counter: u32,
    pub backup_eligible: bool,
    pub backup_state: bool,
    /// Whether this record came from webauthn-rs, which kernoid used before (it is written anew at the next use).
    #[serde(skip)]
    pub legacy: bool,
}

impl Credential {
    /// A stored passkey: kernoid's own record, or – written before kernoid verified passkeys itself – webauthn-rs'
    /// `Passkey` (0.5: `{"cred": {"cred_id", "cred": {"type_", "key"}, "counter", "backup_eligible", …}}`).
    pub fn from_stored(stored: &Value) -> Result<Self> {
        if stored.get("kernoid").is_some() {
            return serde_json::from_value(stored.clone()).map_err(|_| Rejected("a stored passkey that does not read"));
        }
        let cred = stored.get("cred").ok_or(Rejected("a stored passkey of no known form"))?;
        let unknown = Rejected("a stored webauthn-rs passkey that does not read");
        let id = legacy_bytes(cred.get("cred_id").ok_or(unknown.clone())?)?;
        let public = cred.get("cred").ok_or(unknown.clone())?;
        let key = public.get("key").ok_or(unknown.clone())?;
        let algorithm = public.get("type_").and_then(Value::as_str).ok_or(unknown.clone())?;
        let field = |object: &Value, name: &str| object.get(name).ok_or(unknown.clone()).and_then(legacy_bytes);
        let key = if let Some(ec) = key.get("EC_EC2") {
            if algorithm != "ES256" || ec.get("curve").and_then(Value::as_str) != Some("SECP256R1") {
                return Err(Rejected("a stored passkey with an algorithm kernoid does not accept"));
            }
            PublicKey::Es256 { x: field(ec, "x")?, y: field(ec, "y")? }
        } else if let Some(okp) = key.get("EC_OKP") {
            if algorithm != "EDDSA" || okp.get("curve").and_then(Value::as_str) != Some("ED25519") {
                return Err(Rejected("a stored passkey with an algorithm kernoid does not accept"));
            }
            PublicKey::Ed25519 { x: field(okp, "x")? }
        } else if let Some(rsa) = key.get("RSA") {
            if algorithm != "RS256" {
                return Err(Rejected("a stored passkey with an algorithm kernoid does not accept"));
            }
            PublicKey::Rs256 { n: field(rsa, "n")?, e: field(rsa, "e")? }
        } else {
            return Err(unknown);
        };
        key.check()?;
        let flag = |name: &str| cred.get(name).and_then(Value::as_bool).unwrap_or(false);
        Ok(Credential {
            kernoid: 1,
            id,
            key,
            counter: cred.get("counter").and_then(Value::as_u64).and_then(|c| u32::try_from(c).ok()).ok_or(unknown)?,
            backup_eligible: flag("backup_eligible"),
            backup_state: flag("backup_state"),
            legacy: true,
        })
    }

    pub fn to_stored(&self) -> Value {
        serde_json::to_value(self).expect("a credential serialises")
    }
}

/// Binary data as webauthn-rs wrote it: base64url (or standard base64) text, or an array of bytes.
fn legacy_bytes(value: &Value) -> Result<Vec<u8>> {
    let invalid = Rejected("a stored webauthn-rs passkey that does not read");
    match value {
        Value::String(text) => {
            decode(text).or_else(|_| base64::engine::general_purpose::STANDARD.decode(text)).map_err(|_| invalid)
        }
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_u64().and_then(|byte| u8::try_from(byte).ok()).ok_or(invalid.clone()))
            .collect(),
        _ => Err(invalid),
    }
}

mod base64url {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        super::decode(&text).map_err(|_| serde::de::Error::custom("not base64url"))
    }
}

/// A fresh challenge: 32 random bytes.
pub fn challenge() -> Option<Vec<u8>> {
    let mut bytes = vec![0u8; 32];
    getrandom::fill(&mut bytes).ok()?;
    Some(bytes)
}

fn descriptors(ids: &[Vec<u8>]) -> Vec<Value> {
    ids.iter().map(|id| json!({ "type": "public-key", "id": encode(id) })).collect()
}

/// The options of `navigator.credentials.create()` (Level 3, 5.4), as JSON with binary values in base64url.
pub fn creation_options(
    rp: &RelyingParty,
    challenge: &[u8],
    user_id: &[u8],
    name: &str,
    display_name: &str,
    exclude: &[Vec<u8>],
) -> Value {
    json!({ "publicKey": {
        "rp": { "id": rp.id, "name": rp.name },
        "user": { "id": encode(user_id), "name": name, "displayName": display_name },
        "challenge": encode(challenge),
        "pubKeyCredParams": ALGORITHMS.iter().map(|alg| json!({ "type": "public-key", "alg": alg })).collect::<Vec<_>>(),
        "timeout": TIMEOUT_MS,
        "excludeCredentials": descriptors(exclude),
        "authenticatorSelection": { "residentKey": "preferred", "requireResidentKey": false, "userVerification": "required" },
        "attestation": "none",
        "extensions": { "credProps": true },
    }})
}

/// The options of `navigator.credentials.get()` (Level 3, 5.5): the credentials allowed (none: the person picks a
/// discoverable one), offered in the browser's autofill if `conditional`.
pub fn request_options(rp: &RelyingParty, challenge: &[u8], allow: &[Vec<u8>], conditional: bool) -> Value {
    let public_key = json!({
        "challenge": encode(challenge),
        "rpId": rp.id,
        "allowCredentials": descriptors(allow),
        "userVerification": "required",
        "timeout": TIMEOUT_MS,
    });
    if conditional {
        json!({ "mediation": "conditional", "publicKey": public_key })
    } else {
        json!({ "publicKey": public_key })
    }
}

/// Whether the relying party can take passkeys: one of its origins must lie under its RP ID.
pub fn usable(rp: &RelyingParty) -> std::result::Result<(), &'static str> {
    let covered = |origin: &url::Url| {
        origin.host_str().is_some_and(|host| host == rp.id || host.ends_with(&format!(".{}", rp.id)))
    };
    if rp.id.is_empty() || !rp.origins.iter().any(covered) {
        return Err("no origin under the RP ID");
    }
    Ok(())
}

/// Checks the client data (Level 3, 5.8.1): its type, the challenge, an origin of the relying party, not in a frame
/// of another origin. Returns its hash.
fn client_data(rp: &RelyingParty, json: &[u8], kind: &str, challenge: &[u8]) -> Result<[u8; 32]> {
    let data: Value = serde_json::from_slice(json).map_err(|_| Rejected("the client data is not JSON"))?;
    if data.get("type").and_then(Value::as_str) != Some(kind) {
        return Err(Rejected("the client data is of another ceremony"));
    }
    if binary(&data, "challenge")? != challenge {
        return Err(Rejected("another challenge"));
    }
    let origin = data.get("origin").and_then(Value::as_str).ok_or(Rejected("no origin"))?;
    let origin = url::Url::parse(origin).map_err(|_| Rejected("an origin that does not parse"))?.origin();
    if !origin.is_tuple() || !rp.origins.iter().any(|allowed| allowed.origin() == origin) {
        return Err(Rejected("an origin of another site"));
    }
    if data.get("crossOrigin").and_then(Value::as_bool) == Some(true) || data.get("topOrigin").is_some() {
        return Err(Rejected("in a frame of another origin"));
    }
    Ok(Sha256::digest(json).into())
}

/// The authenticator data (Level 3, 6.1).
#[derive(Debug)]
struct AuthenticatorData {
    flags: u8,
    counter: u32,
    /// The attested credential data: its id and public key.
    credential: Option<(Vec<u8>, PublicKey)>,
}

fn authenticator_data(rp: &RelyingParty, data: &[u8]) -> Result<AuthenticatorData> {
    let truncated = Rejected("the authenticator data is too short");
    if data.len() < 37 {
        return Err(truncated);
    }
    if data[..32] != Sha256::digest(rp.id.as_bytes())[..] {
        return Err(Rejected("the authenticator data is for another RP ID"));
    }
    let flags = data[32];
    let counter = u32::from_be_bytes(data[33..37].try_into().expect("four bytes"));
    let mut rest = &data[37..];
    if flags & UP == 0 {
        return Err(Rejected("the person was not present"));
    }
    if flags & UV == 0 {
        return Err(Rejected("the person was not verified"));
    }
    if flags & BS != 0 && flags & BE == 0 {
        return Err(Rejected("backed up but not eligible for backup"));
    }
    let credential = if flags & AT != 0 {
        // AAGUID (16), the id's length (2), the id, the COSE key.
        if rest.len() < 18 {
            return Err(truncated);
        }
        let length = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
        if length == 0 || length > 1023 || rest.len() < 18 + length {
            return Err(Rejected("a credential id of a length WebAuthn does not allow"));
        }
        let id = rest[18..18 + length].to_vec();
        rest = &rest[18 + length..];
        let (key, used) = cbor::decode_prefix(rest).map_err(|_| Rejected("the public key is not CBOR"))?;
        rest = &rest[used..];
        Some((id, PublicKey::from_cose(&key)?))
    } else {
        None
    };
    if flags & ED != 0 {
        let (extensions, used) = cbor::decode_prefix(rest).map_err(|_| Rejected("the extensions are not CBOR"))?;
        if !matches!(extensions, cbor::Value::Map(_)) {
            return Err(Rejected("the extensions are not a map"));
        }
        rest = &rest[used..];
    }
    if !rest.is_empty() {
        return Err(Rejected("bytes after the authenticator data"));
    }
    Ok(AuthenticatorData { flags, counter, credential })
}

/// The browser's answer to `create()` (`PublicKeyCredential` as JSON, Level 3, 5.1.8).
fn credential_json(answer: &Value) -> Result<(Vec<u8>, &Value)> {
    if answer.get("type").and_then(Value::as_str) != Some("public-key") {
        return Err(Rejected("not a public key credential"));
    }
    let raw_id = binary(answer, "rawId")?;
    if let Some(id) = answer.get("id").and_then(Value::as_str)
        && decode(id)? != raw_id
    {
        return Err(Rejected("id and rawId differ"));
    }
    Ok((raw_id, answer.get("response").ok_or(Rejected("no response"))?))
}

/// Registering a credential (Level 3, 7.1): the new passkey, unless it is one of `exclude`.
pub fn finish_registration(rp: &RelyingParty, challenge: &[u8], answer: &Value) -> Result<Credential> {
    let (raw_id, response) = credential_json(answer)?;
    client_data(rp, &binary(response, "clientDataJSON")?, "webauthn.create", challenge)?;
    let object = cbor::decode(&binary(response, "attestationObject")?)
        .map_err(|_| Rejected("the attestation object is not CBOR"))?;
    object.text_key("fmt").and_then(cbor::Value::as_text).ok_or(Rejected("the attestation names no format"))?;
    if !matches!(object.text_key("attStmt"), Some(cbor::Value::Map(_))) {
        return Err(Rejected("the attestation has no statement"));
    }
    let data = object.text_key("authData").and_then(cbor::Value::as_bytes).ok_or(Rejected("no authenticator data"))?;
    let data = authenticator_data(rp, data)?;
    let (id, key) = data.credential.ok_or(Rejected("no attested credential"))?;
    if id != raw_id {
        return Err(Rejected("the credential id differs from rawId"));
    }
    Ok(Credential {
        kernoid: 1,
        id,
        key,
        counter: data.counter,
        backup_eligible: data.flags & BE != 0,
        backup_state: data.flags & BS != 0,
        legacy: false,
    })
}

/// The browser's answer to `get()`.
#[derive(Debug)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    /// The user handle: the account's id for a discoverable passkey.
    pub user_handle: Option<Vec<u8>>,
    client_data: Vec<u8>,
    authenticator_data: Vec<u8>,
    signature: Vec<u8>,
}

impl Assertion {
    pub fn from_json(answer: &Value) -> Result<Self> {
        let (credential_id, response) = credential_json(answer)?;
        let user_handle = match response.get("userHandle") {
            None | Some(Value::Null) => None,
            Some(Value::String(handle)) if handle.is_empty() => None,
            Some(Value::String(handle)) => Some(decode(handle)?),
            Some(_) => return Err(Rejected("a user handle that is no text")),
        };
        Ok(Assertion {
            credential_id,
            user_handle,
            client_data: binary(response, "clientDataJSON")?,
            authenticator_data: binary(response, "authenticatorData")?,
            signature: binary(response, "signature")?,
        })
    }
}

/// Verifying an assertion (Level 3, 7.2) with `credential` – which the caller found by its id and checked belongs to
/// the account – and updating its counter and backup state. Returns whether the record changed.
pub fn verify_assertion(
    rp: &RelyingParty,
    challenge: &[u8],
    assertion: &Assertion,
    credential: &mut Credential,
) -> Result<bool> {
    if assertion.credential_id != credential.id {
        return Err(Rejected("another credential"));
    }
    let hash = client_data(rp, &assertion.client_data, "webauthn.get", challenge)?;
    let data = authenticator_data(rp, &assertion.authenticator_data)?;
    if data.credential.is_some() {
        return Err(Rejected("attested credential data in an assertion"));
    }
    if (data.flags & BE != 0) != credential.backup_eligible {
        return Err(Rejected("backup eligibility changed"));
    }
    credential.key.verify(&[&assertion.authenticator_data[..], &hash].concat(), &assertion.signature)?;
    // A counter that does not grow means a cloned authenticator – unless the authenticator keeps none (step 22).
    if (data.counter != 0 || credential.counter != 0) && data.counter <= credential.counter {
        return Err(Rejected("the signature counter did not grow"));
    }
    let changed =
        credential.legacy || data.counter != credential.counter || (data.flags & BS != 0) != credential.backup_state;
    credential.counter = data.counter;
    credential.backup_state = data.flags & BS != 0;
    credential.legacy = false;
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::{super::soft::SoftPasskey, *};

    fn rp() -> RelyingParty {
        RelyingParty {
            id: "login.firma.de".into(),
            origins: vec!["https://login.firma.de".parse().unwrap(), "https://firma.example".parse().unwrap()],
            name: "Firma".into(),
        }
    }

    const ORIGIN: &str = "https://login.firma.de";

    fn registered(alg: i64) -> (SoftPasskey, Credential) {
        let mut device = SoftPasskey::new(alg);
        let challenge = challenge().unwrap();
        let options = creation_options(&rp(), &challenge, b"user", "alice@firma.de", "Alice", &[]);
        let answer = device.register(ORIGIN, &options);
        let credential = finish_registration(&rp(), &challenge, &answer).unwrap();
        assert_eq!(credential.id, device.credential_id());
        (device, credential)
    }

    fn assert_with(device: &mut SoftPasskey, origin: &str, credential: &mut Credential) -> Result<bool> {
        let challenge = challenge().unwrap();
        let answer = device
            .authenticate(origin, &request_options(&rp(), &challenge, std::slice::from_ref(&credential.id), false));
        verify_assertion(&rp(), &challenge, &Assertion::from_json(&answer).unwrap(), credential)
    }

    #[test]
    fn every_accepted_algorithm_registers_and_signs() {
        for alg in ALGORITHMS {
            let (mut device, mut credential) = registered(alg);
            assert!(matches!(
                (&credential.key, alg),
                (PublicKey::Es256 { .. }, ES256)
                    | (PublicKey::Ed25519 { .. }, EDDSA)
                    | (PublicKey::Rs256 { .. }, RS256)
            ));
            assert_eq!(assert_with(&mut device, ORIGIN, &mut credential), Ok(true));
            assert_eq!(credential.counter, 1);
            // A related origin of the relying party.
            assert_eq!(assert_with(&mut device, "https://firma.example", &mut credential), Ok(true));
            // Stored and read back.
            assert_eq!(Credential::from_stored(&credential.to_stored()).unwrap(), credential);
        }
    }

    #[test]
    fn phishing_replays_and_clones_are_refused() {
        let (mut device, mut credential) = registered(ES256);
        assert_eq!(
            assert_with(&mut device, "https://login.firma.de.evil.example", &mut credential),
            Err(Rejected("an origin of another site"))
        );
        assert_eq!(
            assert_with(&mut device, "http://login.firma.de", &mut credential),
            Err(Rejected("an origin of another site"))
        );

        // Another challenge than the one asked for.
        let challenge = challenge().unwrap();
        let answer = device.authenticate(ORIGIN, &request_options(&rp(), &challenge, &[], false));
        let assertion = Assertion::from_json(&answer).unwrap();
        assert_eq!(verify_assertion(&rp(), &[0; 32], &assertion, &mut credential), Err(Rejected("another challenge")));
        verify_assertion(&rp(), &challenge, &assertion, &mut credential).unwrap();
        // The same answer again: the counter did not grow.
        assert_eq!(
            verify_assertion(&rp(), &challenge, &assertion, &mut credential),
            Err(Rejected("the signature counter did not grow"))
        );

        // A changed byte of the authenticator data breaks the signature.
        let challenge = super::challenge().unwrap();
        let mut answer = device.authenticate(ORIGIN, &request_options(&rp(), &challenge, &[], false));
        let mut data = decode(answer["response"]["authenticatorData"].as_str().unwrap()).unwrap();
        data[36] ^= 0x40;
        answer["response"]["authenticatorData"] = encode(&data).into();
        assert_eq!(
            verify_assertion(&rp(), &challenge, &Assertion::from_json(&answer).unwrap(), &mut credential),
            Err(Rejected("the signature does not verify"))
        );
    }

    #[test]
    fn presence_and_verification_are_required() {
        let mut device = SoftPasskey::new(ES256);
        device.flags = UP;
        let challenge = challenge().unwrap();
        let answer = device.register(ORIGIN, &creation_options(&rp(), &challenge, b"user", "a", "A", &[]));
        assert_eq!(finish_registration(&rp(), &challenge, &answer), Err(Rejected("the person was not verified")));
        device.flags = UV;
        let answer = device.register(ORIGIN, &creation_options(&rp(), &challenge, b"user", "a", "A", &[]));
        assert_eq!(finish_registration(&rp(), &challenge, &answer), Err(Rejected("the person was not present")));
        device.flags = UP | UV | BS;
        let answer = device.register(ORIGIN, &creation_options(&rp(), &challenge, b"user", "a", "A", &[]));
        assert_eq!(
            finish_registration(&rp(), &challenge, &answer),
            Err(Rejected("backed up but not eligible for backup"))
        );
        // For another RP ID.
        device.flags = UP | UV;
        let other = RelyingParty { id: "firma.de".into(), ..rp() };
        let answer = device.register(ORIGIN, &creation_options(&other, &challenge, b"user", "a", "A", &[]));
        assert_eq!(
            finish_registration(&rp(), &challenge, &answer),
            Err(Rejected("the authenticator data is for another RP ID"))
        );
    }

    /// What webauthn-rs 0.5.5 stored for a passkey of its software token (registered in kernoid's tests before the
    /// change): it reads, with its id and key.
    #[test]
    fn passkeys_stored_by_webauthn_rs_still_read() {
        let stored: Value = serde_json::from_str(
            r#"{"cred":{"attestation":{"data":"Self_","metadata":"None"},"attestation_format":"packed","backup_eligible":false,"backup_state":false,"counter":1,"cred":{"key":{"EC_EC2":{"curve":"SECP256R1","x":"w2GV2nyztF0CCQLCOQBBUKvrHpFLS50CCk-9-tjK2Po","y":"4FH1tum3PbosXXuK9LNscdgX5RmdGF2KPzZAaEcISWk"}},"type_":"ES256"},"cred_id":"zw-m6qSxkK9JlmAJ2ogtOC7QP4Z_pkPZtZZhP8-c7_8","extensions":{"appid":"NotRequested","cred_props":"Ignored","cred_protect":"Ignored","hmac_create_secret":"NotRequested"},"registration_policy":"required","transports":null,"user_verified":true}}"#,
        )
        .unwrap();
        let credential = Credential::from_stored(&stored).unwrap();
        assert_eq!(encode(&credential.id), "zw-m6qSxkK9JlmAJ2ogtOC7QP4Z_pkPZtZZhP8-c7_8");
        assert!(credential.legacy && credential.counter == 1 && !credential.backup_eligible);
        assert!(
            matches!(&credential.key, PublicKey::Es256 { x, .. } if encode(x) == "w2GV2nyztF0CCQLCOQBBUKvrHpFLS50CCk-9-tjK2Po")
        );

        // And one of each algorithm, in that form, still signs in – and is written anew in kernoid's form.
        for alg in ALGORITHMS {
            let (mut device, own) = registered(alg);
            let key = match &own.key {
                PublicKey::Es256 { x, y } => {
                    json!({ "EC_EC2": { "curve": "SECP256R1", "x": encode(x), "y": encode(y) } })
                }
                PublicKey::Ed25519 { x } => json!({ "EC_OKP": { "curve": "ED25519", "x": encode(x) } }),
                PublicKey::Rs256 { n, e } => json!({ "RSA": { "n": encode(n), "e": e } }),
            };
            let name = match alg {
                ES256 => "ES256",
                EDDSA => "EDDSA",
                _ => "RS256",
            };
            let stored = json!({ "cred": {
                "cred_id": encode(&own.id), "cred": { "type_": name, "key": key }, "counter": 0,
                "backup_eligible": false, "backup_state": false, "user_verified": true,
            }});
            let mut credential = Credential::from_stored(&stored).unwrap();
            assert!(credential.legacy);
            assert_eq!(assert_with(&mut device, ORIGIN, &mut credential), Ok(true));
            let rewritten = credential.to_stored();
            assert_eq!(rewritten["kernoid"], 1);
            assert!(!Credential::from_stored(&rewritten).unwrap().legacy);
        }
    }

    #[test]
    fn keys_kernoid_does_not_accept_are_refused() {
        use cbor::Value::{Bytes, Int};
        let key = |pairs: Vec<(cbor::Value, cbor::Value)>| PublicKey::from_cose(&cbor::Value::Map(pairs));
        // P-256 with a point not on the curve.
        assert_eq!(
            key(vec![
                (Int(1), Int(2)),
                (Int(3), Int(-7)),
                (Int(-1), Int(1)),
                (Int(-2), Bytes(vec![1; 32])),
                (Int(-3), Bytes(vec![2; 32]))
            ]),
            Err(Rejected("not a point of P-256"))
        );
        // ES384, and RSA with a short modulus.
        assert_eq!(
            key(vec![(Int(1), Int(2)), (Int(3), Int(-35)), (Int(-1), Int(2))]),
            Err(Rejected("an algorithm kernoid does not accept"))
        );
        assert_eq!(
            key(vec![
                (Int(1), Int(3)),
                (Int(3), Int(-257)),
                (Int(-1), Bytes(vec![0xff; 128])),
                (Int(-2), Bytes(vec![1, 0, 1]))
            ]),
            Err(Rejected("an RSA key kernoid does not accept"))
        );
    }
}
