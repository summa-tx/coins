//! This crate provides a simple interface for interacting with Litcoin mainnet, and testnet.

use bitcoins::{
    enc::{BitcoinEncoder, NetworkParams},
    nets::Bitcoin,
};

pub struct LTC;

impl NetworkParams for LTC {
    const HRP: &'static str = "ltc";
    const PKH_VERSION: u8 = 0x30;
    const SH_VERSION: u8 = 0x30;
}

pub struct LTCTest;

impl NetworkParams for LTCTest {
    const HRP: &'static str = "tltc";
    const PKH_VERSION: u8 = 0x6f;
    const SH_VERSION: u8 = 0x3a;
}

pub type LitecoinMainEncoder = BitcoinEncoder<LTC>;
pub type LitecoinTestEncoder = BitcoinEncoder<LTCTest>;

pub type LitecoinMainnet = Bitcoin<LitecoinMainEncoder>;
pub type LitecoinTestnet = Bitcoin<LitecoinTestEncoder>;
