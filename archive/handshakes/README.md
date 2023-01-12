# handshakes

This crate provides an interface for interacting with the
[Handshake](https://github.com/handshake-org/hsd) network.
Build, serialize and deserialize transactions with full covenant support.
The [coins-bip32](https://crates.io/crates/coins-bip32/) crate can be used
with this crate to sign transactions.

This crate is under active development, and the API may change.

## Usage

Typically, you'll want to use a network as an entry point. It will ensure that
the correct network specific constants are used.
The `tx_builder` is useful for creating and serializing transactions.

```rust
use coins_core::{builder::TxBuilder, nets::Network, ByteFormat};
use std::convert::TryFrom;

use handshakes::{
    types::{Covenant, CovenantData, CovenantType, HandshakeTx, Outpoint},
    HandshakeMainnet,
};

// Create a covenant
let covenant = Covenant {
    covenant_type: CovenantType::try_from("NONE").unwrap(),
    covenant_data: CovenantData::null(),
};

// Create an address
let address = HandshakeMainnet::string_to_address("hs1qcu0cff5ma6uxgy0ffkmgsj28ucqwtqt9eqnp06").unwrap();

// Build a transaction
let tx = HandshakeMainnet::tx_builder()
    .spend(Outpoint::default(), 0x00000000)
    .pay_covenant(0x8000_0000, &address, covenant)
    .build()
    .unwrap();

let hex = tx.serialize_hex();
let serialized = HandshakeTx::deserialize_hex(&hex).unwrap();

assert_eq!(tx, serialized);
```

See the documentation for more details.

## Building & Running Tests

- `cargo build`
- `cargo test`
- build the docs: `$ cargo rustdoc`
