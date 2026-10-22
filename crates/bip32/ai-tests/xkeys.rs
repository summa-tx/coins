//! AI-written tests for extended keys. A submodule of `src/xkeys.rs`.

use super::*;
use crate::enc::TESTNET;

/// BIP-32 test vector 1, master xprv.
const VECTOR_1_XPRV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

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
    let xpub = XPriv::root_from_seed(&[7u8; 32], None)
        .unwrap()
        .verify_key();
    let json = serde_json::to_string(&xpub).unwrap();
    assert!(json.starts_with("\"zpub"), "{json}");
    let back: XPub = serde_json::from_str(&json).unwrap();
    assert_eq!(back, xpub);
}

#[test]
fn equality_ignores_network() {
    let a = XPriv::root_from_seed(&[7u8; 32], None).unwrap();
    let mut b = a.clone();
    b.set_network(&TESTNET);
    assert_eq!(a, b);
    assert_eq!(a.verify_key(), b.verify_key());
    let (ia, ib): (&XKeyInfo, &XKeyInfo) = (a.as_ref(), b.as_ref());
    assert_eq!(ia, ib);
}

#[test]
fn testnet_xpriv_serde_round_trips_losslessly() {
    let mut xpriv = XPriv::root_from_seed(&[7u8; 32], Some(Hint::Legacy)).unwrap();
    xpriv.set_network(&TESTNET);
    let json = serde_json::to_string(&xpriv).unwrap();
    assert!(json.starts_with("\"tprv"), "{json}");
    let back: XPriv = serde_json::from_str(&json).unwrap();
    assert_eq!(serde_json::to_string(&back).unwrap(), json);
    let info: &XKeyInfo = back.as_ref();
    assert_eq!(info.network, &TESTNET);
}

#[test]
fn xpriv_parses_from_str() {
    let xpriv: XPriv = VECTOR_1_XPRV.parse().unwrap();
    assert_eq!(xpriv.to_base58().as_str(), VECTOR_1_XPRV);
}
