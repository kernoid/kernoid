// SPDX-License-Identifier: MIT
//! The hybrid keys of `kernoid_crypt::pq`: X-Wing against the draft's test vectors, sealing and signing.

use kernoid_crypt::{
    Domain,
    pq::{self, HybridKeys, xwing},
};

/// draft-connolly-cfrg-xwing-kem-11, appendix C.
const VECTORS: &str = include_str!("data/xwing-draft-11.json");

fn hex(text: &serde_json::Value) -> Vec<u8> {
    hex::decode(text.as_str().unwrap()).unwrap()
}

#[test]
fn x_wing_matches_the_drafts_test_vectors() {
    let vectors: Vec<serde_json::Value> = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors.len(), 3);
    for vector in vectors {
        let seed: [u8; 32] = hex(&vector["seed"]).try_into().unwrap();
        let eseed: [u8; 64] = hex(&vector["eseed"]).try_into().unwrap();
        let public = xwing::public_key(&seed);
        assert_eq!(public, hex(&vector["pk"]));
        let (shared, ciphertext) = xwing::encapsulate_derand(&public, &eseed).unwrap();
        assert_eq!(ciphertext, hex(&vector["ct"]));
        assert_eq!(shared.to_vec(), hex(&vector["ss"]));
        assert_eq!(xwing::decapsulate(&ciphertext, &seed).unwrap(), shared);
    }
}

#[test]
fn x_wing_refuses_keys_and_ciphertexts_of_the_wrong_size() {
    let public = xwing::public_key(&[7; 32]);
    assert!(xwing::encapsulate(&public[..100]).is_err());
    let (_, ciphertext) = xwing::encapsulate(&public).unwrap();
    assert!(xwing::decapsulate(&ciphertext[1..], &[7; 32]).is_err());
}

#[test]
fn sealed_data_opens_only_with_the_key_and_the_context() {
    let alice = HybridKeys::from_seed(Domain::KERNOID, [1; 32]);
    let bob = HybridKeys::from_seed(Domain::KERNOID, [2; 32]);
    let sealed = pq::seal(Domain::KERNOID, alice.receiving(), b"s-stream 3", b"the stream key").unwrap();
    assert_eq!(alice.open(b"s-stream 3", &sealed).unwrap(), b"the stream key");
    assert!(alice.open(b"s-stream 4", &sealed).is_err());
    assert!(bob.open(b"s-stream 3", &sealed).is_err());
    let mut changed = sealed.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(alice.open(b"s-stream 3", &changed).is_err());
    // Another program's keys of the same seed are other keys.
    let other = Domain { label: "aktujo/crypt", scheme: "aktujo" };
    assert_ne!(HybridKeys::from_seed(other, [1; 32]).receiving(), alice.receiving());
}

#[test]
fn signatures_need_both_halves() {
    let keys = HybridKeys::from_seed(Domain::KERNOID, [3; 32]);
    assert_eq!(keys.verifying().0.len(), pq::VERIFYING_KEY_LEN);
    let signature = keys.sign(b"a record");
    assert_eq!(signature.len(), pq::SIGNATURE_LEN);
    assert!(keys.verifying().verify(Domain::KERNOID, b"a record", &signature));
    assert!(!keys.verifying().verify(Domain::KERNOID, b"another record", &signature));
    let other = Domain { label: "aktujo/crypt", scheme: "aktujo" };
    assert!(!keys.verifying().verify(other, b"a record", &signature));
    // Either half broken: not valid.
    for at in [10, 64 + 10] {
        let mut broken = signature.clone();
        broken[at] ^= 1;
        assert!(!keys.verifying().verify(Domain::KERNOID, b"a record", &broken), "byte {at}");
    }
    // The same seed gives the same keys on every device; the signature is deterministic.
    let again = HybridKeys::from_seed(Domain::KERNOID, [3; 32]);
    assert_eq!(again.verifying(), keys.verifying());
    assert_eq!(again.sign(b"a record"), signature);
    assert_eq!(keys.verifying().id(), again.verifying().id());
}
