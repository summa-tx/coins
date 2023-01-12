# bitcoins-ledger

Ledger Bitcoin App abstraction.

# Building

Windows is not yet supported.

### Native
- Install dependencies
  - Linux
    - `$ sudo apt-get install libudev-dev libusb-1.0-0-dev`
  - OSX
    - TODO
    - please file an issue if you know. I don't have a macbook :)
- Build with native transport
  - `cargo build`

### WASM
- Install wasm-pack
  - [Link here](https://rustwasm.github.io/wasm-pack/installer/)
- building for wasm
  - MUST disable default features
  - MUST select feature AT MOST ONE of `browser` and `node`
  - `browser`
    - usage env must be able to import
  - `node`

# Features

The `node` and `browser` features are mutually exclusive. You must specify
exactly one, as well as the `--no-default-features` flag.

When building for non-wasm architectures, a native HID transport is compiled
in. When building wasm via `wasm-pack`, you must specify whether you want the
node or browser wasm transport.

# Testing

- run the unit tests
  - `$ cargo test -- --lib`
- run the integration tests
  - Plug in a Ledger Nano S or X device
  - Unlock the device
  - Open the Bitcoin application on the device
    - If you don't have the application, [install Ledger Live](https://support.ledger.com/hc/en-us/articles/360006395553) and follow [these instructions](https://support.ledger.com/hc/en-us/articles/360006523674-Install-or-uninstall-apps)
  - `$ cargo test`
