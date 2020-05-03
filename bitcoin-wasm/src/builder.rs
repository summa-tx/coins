//! Implementations of the `TxBuilder` for Bitcoin transactions. This module includes both a
//! `LegacyBuilder` for legacy transactions, and a `WitnessBuilder` for Witness transactions
//! The two types are very similar, but a witness builder will always build witness transactions.
//! As soon as the caller adds a witness to a legacy builder, it is substituted behind-the-scenes
//! with a witness builder. This means that the caller doesn't typically need to worry about the
//! implementation details. They can simply use the builder transparently.
//!
//! The builder can also be explicitly converted using the `as_witness` and `as_legacy` functions.
//!
//! The builder is best accessed via the preconstructed network objects.

use wasm_bindgen::prelude::*;

use riemann_core::{builder::TxBuilder, enc::AddressEncoder};

use rmn_btc::{
    builder::{self, BitcoinBuilder, WitTxBuilder},
    enc,
    types::{script, txin, txout},
};

use crate::types::{
    errors::WasmError,
    script::TxWitness,
    transactions::{LegacyTx, WitnessTx},
    txin::{BitcoinOutpoint, Vin},
    txout::Vout,
};

impl_builders!(MainnetLegacyBuilder, MainnetWitnessBuilder, MainnetEncoder);
impl_builders!(TestnetLegacyBuilder, TestnetWitnessBuilder, TestnetEncoder);
impl_builders!(SignetLegacyBuilder, SignetWitnessBuilder, SignetEncoder);
