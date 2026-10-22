//! AI-written tests for derived keys. A submodule of `src/derived.rs`.

use super::*;

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
    let key = DerivedXPriv::root_from_seed(&[7u8; 32], None).unwrap().verify_key();
    let json = serde_json::to_string(&key).unwrap();
    assert!(json.contains("\"zpub"), "{json}");
    let back: DerivedXPub = serde_json::from_str(&json).unwrap();
    assert_eq!(back, key);
}
