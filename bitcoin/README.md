# rmn-btc

This crate provides a simple interface for interacting with Bitcoin mainnet,
testnet, and signet.

## Usage

```rust
use riemann_bitcoin::{BitcoinMainnet, Address, Outpoint};
use riemann_core::{
    nets::Network,
    builder::TxBuilder,
    ser::Ser,
};
//!
let address = BitcoinMainnet::wrap_string("bc1qvyyvsdcd0t9863stt7u9rf37wx443lzasg0usy".to_owned());
//!
let b = BitcoinMainnet::tx_builder();
b.version(2)
 .spend(Outpoint::default(), 0xaabbccdd)
 .pay(0x8888_8888_8888_8888, &address).unwrap()
 .pay(0x7777_7777_7777_7777, &Address::SH("377mKFYsaJPsxYSB5aFfx8SW3RaN5BzZVh".to_owned())).unwrap()
 .build()
 .serialize_hex();
//!
let script = BitcoinMainnet::decode_address(&address).unwrap();
let re_encoded = BitcoinMainnet::encode_address(&script).unwrap();
assert_eq!(address, re_encoded);
```

See the documentation for more details. TODO: link
