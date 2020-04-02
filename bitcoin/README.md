# rmn-btc

This crate provides a simple interface for interacting with Bitcoin mainnet,
testnet, and signet.

This crate is under active development, and the API may change.

## Usage

Typically, you'll want to use a pre-fabricated network as an entry point.

```rust
use riemann_core::{
    nets::Network,
    builder::TxBuilder,
    ser::Ser,
};

use riemann_bitcoin::{BitcoinMainnet, Outpoint};

// We can convert a string to an address
let address = BitcoinMainnet::string_to_address("bc1qvyyvsdcd0t9863stt7u9rf37wx443lzasg0usy").unwrap();

// And set up a transaction builder with a simple interface
let serialized_tx = BitcoinMainnet::tx_builder()
  .version(2)
  .spend(Outpoint::default(), 0xaabbccdd)
  .pay(0x8888_8888_8888_8888, &address).unwrap()
  .build()
  .serialize_hex();
```

See the documentation for more details. TODO: link the docs.

## Building & Running Tests

- `cargo build`
- `cargo test`
- build the docs: `$ cargo rustdoc`
