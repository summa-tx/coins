//! AI-written tests for extended key encoding. A submodule of `src/enc.rs`.

use super::*;

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
