//! This crate provides a simple interface for interacting with Litcoin mainnet, and testnet.

use bitcoins::{
    enc::{BitcoinEncoder, NetworkParams},
    nets::Bitcoin,
};

pub struct Ltc;

impl NetworkParams for Ltc {
    const HRP: &'static str = "ltc";
    const PKH_VERSION: u8 = 0x30;
    const SH_VERSION: u8 = 0x30;
}

pub struct LtcTest;

impl NetworkParams for LtcTest {
    const HRP: &'static str = "tltc";
    const PKH_VERSION: u8 = 0x6f;
    const SH_VERSION: u8 = 0x3a;
}

pub type LitecoinMainEncoder = BitcoinEncoder<Ltc>;
pub type LitecoinTestEncoder = BitcoinEncoder<LtcTest>;

pub type LitecoinMainnet = Bitcoin<LitecoinMainEncoder>;
pub type LitecoinTestnet = Bitcoin<LitecoinTestEncoder>;
