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

use riemann_core::{
    enc::AddressEncoder,
    builder::TxBuilder,
};

use crate::types::{
    script::TxWitness,
    txin::{BitcoinOutpoint, Vin},
    txout::Vout,
};

impl_builders!(MainnetBuilder, MainnetEncoder);
impl_builders!(TestnetBuilder, TestnetEncoder);
impl_builders!(SignetBuilder, SignetEncoder);
