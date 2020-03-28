## TODOs:

- clean up docs everywhere
- Write readmes and library intros

# Builder Interface Notes

Library Usage:
```rust
use riemann::{BitcoinMainnet};

let b = BitcoinMainnet::tx_builder()
    .version(2)
    .spend(Outpoint::default(), 0xaabbccdd)
    .pay(0x8888_8888_8888_8888, Address::WPKH("bc1qvyyvsdcd0t9863stt7u9rf37wx443lzasg0usy".to_owned()))
    .pay(0x7777_7777_7777_7777, Address::SH("377mKFYsaJPsxYSB5aFfx8SW3RaN5BzZVh".to_owned()))
    .build()
    .serialize_hex();

println!("{:?}", b);
```
