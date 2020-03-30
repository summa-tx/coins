use wasm_bindgen::prelude::*;

use crate::{
    builder::{MainnetLegacyBuilder, TestnetLegacyBuilder, SignetLegacyBuilder},
    enc::{Address, MainnetEncoder, TestnetEncoder, SignetEncoder},
};


impl_network!(BitcoinMainnet, MainnetLegacyBuilder, MainnetEncoder);
impl_network!(BitcoinTestnet, TestnetLegacyBuilder, TestnetEncoder);
impl_network!(BitcoinSignet, SignetLegacyBuilder, SignetEncoder);
