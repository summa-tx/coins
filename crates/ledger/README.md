# coins-ledger

Communication library between Rust and Ledger Nano S/X devices

# Building

This crate talks to the device over native HID via `hidapi`, and does not
build for `wasm32` targets. The JS/WASM transport shipped in versions before
0.16 was removed. Windows is untested.

- Install dependencies
  - macOS: none. `hidapi` uses the system HID framework.
  - Linux: `libudev` and `pkg-config`. On Debian and Ubuntu that is
    `apt install libudev-dev pkg-config`. Install Ledger's
    [udev rules](https://github.com/LedgerHQ/udev-rules) so the device is
    accessible without root.
  - Android (Termux): `pkg install rust libusb pkg-config`. Android builds
    use hidapi's libusb backend so that `termux-usb -e <binary> <device>`
    can hand over the USB file descriptor. This path is untested.
- `cargo build`

# Testing

- run the unit tests
  - `$ cargo test --lib`
- run the integration tests
  - Plug in a Ledger Nano S or X device
  - Unlock the device
  - Open the Ethereum application on the device
    - If you don't have the application, [install Ledger Live](https://support.ledger.com/hc/en-us/articles/360006395553) and follow [these instructions](https://support.ledger.com/hc/en-us/articles/360006523674-Install-or-uninstall-apps)
  - `$ cargo test -p coins-ledger -- --ignored`

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
- Status words are an open `StatusWord` type covering the OS codes
- Commands and answers are fixed-size buffers; commands come from
  `CommandBuilder`
- Exchange runs on a dedicated I/O thread. Commands and answers are
  fixed-size buffers, so the only per-command allocation is the channel that
  returns the answer
- Break out integration tests
- Strip print logs
