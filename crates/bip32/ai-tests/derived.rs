//! AI-written tests for derived keys. A submodule of `src/derived.rs`.

use super::*;
use crate::enc::TESTNET;

#[test]
fn derived_xpriv_serde_round_trips() {
    let key = DerivedXPriv::root_from_seed(&[7u8; 32], None).unwrap();
    let json = serde_json::to_string(&key).unwrap();
    assert!(json.contains("\"zprv"), "{json}");
    let back: DerivedXPriv = serde_json::from_str(&json).unwrap();
    let (a, b): (&XPriv, &XPriv) = (back.as_ref(), key.as_ref());
    assert_eq!(a, b);
}

#[test]
fn derived_xpub_serde_round_trips() {
    let key = DerivedXPriv::root_from_seed(&[7u8; 32], None)
        .unwrap()
        .verify_key();
    let json = serde_json::to_string(&key).unwrap();
    assert!(json.contains("\"zpub"), "{json}");
    let back: DerivedXPub = serde_json::from_str(&json).unwrap();
    assert_eq!(back, key);
}

#[test]
fn derived_testnet_serde_round_trips_losslessly() {
    let mut key = DerivedXPriv::root_from_seed(&[7u8; 32], Some(Hint::Legacy)).unwrap();
    key.set_network(&TESTNET);
    let json = serde_json::to_string(&key).unwrap();
    assert!(json.contains("\"tprv"), "{json}");
    let back: DerivedXPriv = serde_json::from_str(&json).unwrap();
    assert_eq!(serde_json::to_string(&back).unwrap(), json);

    let key_pub = key.verify_key();
    let json = serde_json::to_string(&key_pub).unwrap();
    assert!(json.contains("\"tpub"), "{json}");
    let back: DerivedXPub = serde_json::from_str(&json).unwrap();
    assert_eq!(serde_json::to_string(&back).unwrap(), json);
}

#[test]
fn derived_set_network_reaches_children_and_pubkeys() {
    let mut key = DerivedXPriv::root_from_seed(&[7u8; 32], None).unwrap();
    key.set_network(&TESTNET);
    let key_pub = key.verify_key();
    let child = key.derive_child(0).unwrap();
    let infos: [&XKeyInfo; 3] = [key.as_ref(), key_pub.as_ref(), child.as_ref()];
    for info in infos {
        assert_eq!(info.network, &TESTNET);
    }
}
