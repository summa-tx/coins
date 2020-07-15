//! The `bitcoin::nets` module cotains Bitcoin network definitions. These are the main interface
//! for accessing the library.
//!
//! Expected user flow is to import the network and access the transaction builder through it.
//! This gives the user immediate access to the full bitcoin toolchain via a single import.

use wasm_bindgen::prelude::*;

use crate::{
    builder::{MainnetBuilder, SignetBuilder, TestnetBuilder},
    enc::{Address, MainnetEncoder, SignetEncoder, TestnetEncoder},
};

impl_network!(
    /// A fully-parameterized BitcoinMainnet. This is the main interface for accessing the library.
    BitcoinMainnet,
    MainnetBuilder,
    MainnetEncoder
);

impl_network!(
    /// A fully-parameterized BitcoinTestnet. This is the main interface for accessing the library.
    BitcoinTestnet,
    TestnetBuilder,
    TestnetEncoder
);

impl_network!(
    /// A fully-parameterized BitcoinSignet. This is the main interface for accessing the library.
    BitcoinSignet,
    SignetBuilder,
    SignetEncoder
);
