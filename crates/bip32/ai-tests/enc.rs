//! AI-written tests for extended key encoding. A submodule of `src/enc.rs`.

use super::*;
use crate::xkeys::Parent;

#[test]
fn mainnet_versions_match_bip32_49_84() {
    assert_eq!(MAINNET.priv_version(Hint::Legacy), 0x0488_ADE4);
    assert_eq!(MAINNET.priv_version(Hint::Compatibility), 0x049d_7878);
    assert_eq!(MAINNET.priv_version(Hint::SegWit), 0x04b2_430c);
    assert_eq!(MAINNET.pub_version(Hint::Legacy), 0x0488_B21E);
    assert_eq!(MAINNET.pub_version(Hint::Compatibility), 0x049d_7cb2);
    assert_eq!(MAINNET.pub_version(Hint::SegWit), 0x04b2_4746);
}

#[test]
fn testnet_versions_match_bip32_49_84() {
    assert_eq!(TESTNET.priv_version(Hint::Legacy), 0x0435_8394);
    assert_eq!(TESTNET.priv_version(Hint::Compatibility), 0x044a_4e28);
    assert_eq!(TESTNET.priv_version(Hint::SegWit), 0x045f_18bc);
    assert_eq!(TESTNET.pub_version(Hint::Legacy), 0x0435_87CF);
    assert_eq!(TESTNET.pub_version(Hint::Compatibility), 0x044a_5262);
    assert_eq!(TESTNET.pub_version(Hint::SegWit), 0x045f_1cf6);
}

#[test]
fn hint_lookups_invert_version_lookups() {
    for network in [&MAINNET, &TESTNET] {
        for hint in [Hint::Legacy, Hint::Compatibility, Hint::SegWit] {
            assert_eq!(network.priv_hint(network.priv_version(hint)), Some(hint));
            assert_eq!(network.pub_hint(network.pub_version(hint)), Some(hint));
            assert_eq!(network.priv_hint(network.pub_version(hint)), None);
            assert_eq!(network.pub_hint(network.priv_version(hint)), None);
        }
    }
    assert_eq!(MAINNET.priv_hint(0xDEAD_BEEF), None);
    assert_eq!(MAINNET.priv_hint(TESTNET.priv_version(Hint::Legacy)), None);
}

/// BIP-32 test vector 1, master xprv.
const VECTOR_1_XPRV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
/// BIP-32 test vector 1, master xpub.
const VECTOR_1_XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

/// Re-encode a base58check key with its four version bytes replaced.
fn with_version(s: &str, version: u32) -> String {
    let mut bytes = decode_b58_check(s).unwrap();
    bytes[..4].copy_from_slice(&version.to_be_bytes());
    encode_b58_check(&bytes).to_string()
}

#[test]
fn every_known_prefix_round_trips() {
    for network in [&MAINNET, &TESTNET] {
        for hint in [Hint::Legacy, Hint::Compatibility, Hint::SegWit] {
            let mut xpriv = XPriv::root_from_seed(&[7u8; 32], Some(hint)).unwrap();
            xpriv.set_network(network);
            let s = xpriv.to_base58();
            assert_eq!(
                decode_b58_check(&s).unwrap()[..4],
                network.priv_version(hint).to_be_bytes()
            );
            let back = XPriv::from_base58(&s).unwrap();
            let info: &XKeyInfo = back.as_ref();
            assert_eq!(back, xpriv);
            assert_eq!(info.hint, hint);
            assert_eq!(info.network, network);

            let xpub = xpriv.verify_key();
            let s = xpub.to_base58();
            assert_eq!(
                decode_b58_check(&s).unwrap()[..4],
                network.pub_version(hint).to_be_bytes()
            );
            let back = XPub::from_base58(&s).unwrap();
            let info: &XKeyInfo = back.as_ref();
            assert_eq!(back, xpub);
            assert_eq!(info.hint, hint);
            assert_eq!(info.network, network);
        }
    }
}

#[test]
fn testnet_prefix_is_recognized_and_preserved() {
    let tprv = with_version(VECTOR_1_XPRV, TESTNET.priv_legacy);
    let parsed = XPriv::from_base58(&tprv).unwrap();
    let info: &XKeyInfo = parsed.as_ref();
    assert_eq!(info.network, &TESTNET);
    assert_eq!(info.hint, Hint::Legacy);
    assert_eq!(parsed, XPriv::from_base58(VECTOR_1_XPRV).unwrap());
    assert_eq!(parsed.to_base58().as_str(), tprv);
}

#[test]
fn strict_parse_rejects_the_other_network() {
    assert!(matches!(
        XPriv::from_base58_with(VECTOR_1_XPRV, &TESTNET),
        Err(Bip32Error::BadXPrivVersionBytes(_))
    ));
    let tprv = with_version(VECTOR_1_XPRV, TESTNET.priv_legacy);
    assert!(matches!(
        XPriv::from_base58_with(&tprv, &MAINNET),
        Err(Bip32Error::BadXPrivVersionBytes(_))
    ));
    assert!(XPriv::from_base58_with(&tprv, &TESTNET).is_ok());
}

#[test]
fn unknown_prefix_is_rejected_with_its_bytes() {
    let s = with_version(VECTOR_1_XPRV, 0xDEAD_BEEF);
    assert!(matches!(
        XPriv::from_base58(&s),
        Err(Bip32Error::BadXPrivVersionBytes([0xde, 0xad, 0xbe, 0xef]))
    ));
    let s = with_version(VECTOR_1_XPUB, 0xDEAD_BEEF);
    assert!(matches!(
        XPub::from_base58(&s),
        Err(Bip32Error::BadXPubVersionBytes([0xde, 0xad, 0xbe, 0xef]))
    ));
}

#[test]
fn pub_prefix_into_priv_parser_and_back_are_rejected() {
    assert!(matches!(
        XPriv::from_base58(VECTOR_1_XPUB),
        Err(Bip32Error::BadXPrivVersionBytes(_))
    ));
    assert!(matches!(
        XPub::from_base58(VECTOR_1_XPRV),
        Err(Bip32Error::BadXPubVersionBytes(_))
    ));
}

#[test]
fn network_survives_derivation_and_verify_key() {
    let mut root = XPriv::root_from_seed(&[7u8; 32], None).unwrap();
    root.set_network(&TESTNET);
    let child = root.derive_child(0).unwrap();
    let child_pub = child.verify_key();
    let pub_child = root.verify_key().derive_child(0).unwrap();
    let infos: [&XKeyInfo; 3] = [child.as_ref(), child_pub.as_ref(), pub_child.as_ref()];
    for info in infos {
        assert_eq!(info.network, &TESTNET);
    }
}

#[test]
fn truncated_input_is_an_io_error() {
    let bytes = decode_b58_check(VECTOR_1_XPRV).unwrap();
    for len in [0, 3, 4, 45, 77] {
        assert!(
            matches!(XPriv::read(&mut &bytes[..len]), Err(Bip32Error::IoError(_))),
            "len {len}"
        );
    }
    let bytes = decode_b58_check(VECTOR_1_XPUB).unwrap();
    for len in [0, 3, 4, 45, 77] {
        assert!(
            matches!(XPub::read(&mut &bytes[..len]), Err(Bip32Error::IoError(_))),
            "len {len}"
        );
    }
}

#[test]
fn nonzero_padding_is_rejected() {
    let mut bytes = decode_b58_check(VECTOR_1_XPRV).unwrap();
    bytes[45] = 1;
    assert!(matches!(
        XPriv::read(&mut &bytes[..]),
        Err(Bip32Error::BadPadding(1))
    ));
}

#[test]
fn read_consumes_exactly_one_key() {
    let xpriv = XPriv::from_base58(VECTOR_1_XPRV).unwrap();
    let xpub = xpriv.verify_key();
    let mut buf = Vec::new();
    assert_eq!(xpriv.write(&mut buf).unwrap(), 78);
    assert_eq!(xpub.write(&mut buf).unwrap(), 78);
    let mut cursor = &buf[..];
    assert_eq!(XPriv::read(&mut cursor).unwrap(), xpriv);
    assert_eq!(XPub::read(&mut cursor).unwrap(), xpub);
    assert!(cursor.is_empty());
}

const OTHER: NetworkVersions = NetworkVersions {
    priv_legacy: 0x1111_1111,
    priv_compatibility: 0x2222_2222,
    priv_segwit: 0x3333_3333,
    pub_legacy: 0x4444_4444,
    pub_compatibility: 0x5555_5555,
    pub_segwit: 0x6666_6666,
};

fn other_xpriv<'de, D: serde::Deserializer<'de>>(d: D) -> Result<XPriv, D::Error> {
    deserialize_xpriv(d, &OTHER)
}

fn other_xpub<'de, D: serde::Deserializer<'de>>(d: D) -> Result<XPub, D::Error> {
    deserialize_xpub(d, &OTHER)
}

fn other_derived_xpriv<'de, D: serde::Deserializer<'de>>(d: D) -> Result<DerivedXPriv, D::Error> {
    deserialize_derived_xpriv(d, &OTHER)
}

fn other_derived_xpub<'de, D: serde::Deserializer<'de>>(d: D) -> Result<DerivedXPub, D::Error> {
    deserialize_derived_xpub(d, &OTHER)
}

#[derive(serde::Deserialize)]
struct Holder {
    #[serde(deserialize_with = "other_xpriv")]
    xpriv: XPriv,
    #[serde(deserialize_with = "other_xpub")]
    xpub: XPub,
    #[serde(deserialize_with = "other_derived_xpriv")]
    derived_xpriv: DerivedXPriv,
    #[serde(deserialize_with = "other_derived_xpub")]
    derived_xpub: DerivedXPub,
}

fn holder_json(key: &DerivedXPriv) -> serde_json::Value {
    let xpriv: &XPriv = key.as_ref();
    let key_pub = key.verify_key();
    let xpub: &XPub = key_pub.as_ref();
    serde_json::json!({
        "xpriv": xpriv.to_base58().as_str(),
        "xpub": xpub.to_base58(),
        "derived_xpriv": key,
        "derived_xpub": &key_pub,
    })
}

#[test]
fn helpers_accept_their_network() {
    let mut key = DerivedXPriv::root_from_seed(&[7u8; 32], None).unwrap();
    key.set_network(&OTHER);
    let holder: Holder = serde_json::from_str(&holder_json(&key).to_string()).unwrap();
    let infos: [&XKeyInfo; 4] = [
        holder.xpriv.as_ref(),
        holder.xpub.as_ref(),
        holder.derived_xpriv.as_ref(),
        holder.derived_xpub.as_ref(),
    ];
    for info in infos {
        assert_eq!(info.network, &OTHER);
    }
    assert_eq!(
        serde_json::to_string(&holder.derived_xpriv).unwrap(),
        serde_json::to_string(&key).unwrap()
    );
}

#[test]
fn helpers_reject_mainnet() {
    let key = DerivedXPriv::root_from_seed(&[7u8; 32], None).unwrap();
    let err = serde_json::from_str::<Holder>(&holder_json(&key).to_string())
        .err()
        .expect("mainnet keys must be rejected");
    assert!(err.to_string().contains("don't match any network"), "{err}");
}
