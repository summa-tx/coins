//! AI-written tests for extended keys. A submodule of `src/xkeys.rs`.

use super::*;

#[test]
fn xpriv_serde_round_trips() {
    let xpriv = XPriv::root_from_seed(&[7u8; 32], None).unwrap();
    let json = serde_json::to_string(&xpriv).unwrap();
    assert!(json.starts_with("\"zprv"), "{json}");
    let back: XPriv = serde_json::from_str(&json).unwrap();
    assert_eq!(back, xpriv);
}

#[test]
fn xpub_serde_round_trips() {
    let xpub = XPriv::root_from_seed(&[7u8; 32], None).unwrap().verify_key();
    let json = serde_json::to_string(&xpub).unwrap();
    assert!(json.starts_with("\"zpub"), "{json}");
    let back: XPub = serde_json::from_str(&json).unwrap();
    assert_eq!(back, xpub);
}
