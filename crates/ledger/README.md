# coins-ledger

Communication library between Rust and Ledger Nano S/X devices

# Building

Windows is not yet supported.

This crate talks to the device over native HID via `hidapi`, and does not
build for `wasm32` targets. The JS/WASM transport shipped in versions before
0.16 was removed.

- Install dependencies
  - OSX
    - TODO
    - please file an issue if you know. I don't have a macbook :)
- `cargo build`

# Testing

- run the unit tests
  - `$ cargo test --lib`
- run the integration tests
  - Plug in a Ledger Nano S or X device
  - Unlock the device
  - Open the Ethereum application on the device
    - If you don't have the application, [install Ledger Live](https://support.ledger.com/hc/en-us/articles/360006395553) and follow [these instructions](https://support.ledger.com/hc/en-us/articles/360006523674-Install-or-uninstall-apps)
  - `$ cargo test`

# License Notes

This repo was forked from [Zondax's repo](https://github.com/Zondax/ledger-rs)
at commit [`7d40af96`](https://github.com/Zondax/ledger-rs/commit/7d40af9653d04e2d40f8b0c031675b6ff82d7f2c).
Their code is reproduced here under the terms of the Apache 2 License. Files
containing elements from their code maintain their original Apache 2 license
notice at the bottom of the file.

Further work by Summa is available under the GNU LGPLv3 license.

These changes are as follows:

- Remove bip44 crates
- Significant refactoring to all other crates
- Crates have been moved to be modules of a single crate
- Refactor APDUErrorCodes
- Refactor APDUCommand to move towards no_std support. They hold &'a [u8]
  instead of vectors
- Refactor APDUAnswer to move towards no_std support and avoid unnecessary
  copies. It is now a thin wrapper around a &[u8]
- Change exchange functions to accept a mutable buffer. The caller must allocate
  space for the response packet
- Break out integration tests
- Strip print logs
