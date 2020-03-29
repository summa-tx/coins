use wasm_bindgen::prelude::*;

use riemann_core::{
    builder::{TxBuilder},
    enc::{AddressEncoder},
};

use riemann_bitcoin::{
    builder::{self, BitcoinBuilder, WitTxBuilder},
    enc,
    types::{script, txin, txout},
};

use crate::{
    errors::{WasmError},
    script::{TxWitness},
    txin::{BitcoinOutpoint, Vin},
    txout::{Vout},
    transactions::{LegacyTx, WitnessTx},
};

impl_builders!(MainnetLegacyBuilder, MainnetWitnessBuilder, MainnetEncoder);
impl_builders!(TestnetLegacyBuilder, TestnetWitnessBuilder, TestnetEncoder);
impl_builders!(SignetLegacyBuilder, SignetWitnessBuilder, SignetEncoder);
