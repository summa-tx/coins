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

## Testing against Speculos

The `speculos` feature adds a transport for the
[Speculos](https://github.com/LedgerHQ/speculos) emulator. Its integration
tests run Ledger's [app-boilerplate](https://github.com/LedgerHQ/app-boilerplate)
2.3.2 in Speculos, and skip unless `SPECULOS_APDU_ADDR` is set.

- Download the app for the model you want to emulate (`nanos2` is the Nano
  S Plus)
  - `$ gh release download 2.3.2 -R LedgerHQ/app-boilerplate -p 'app-2.3.2-nanos2.elf'`
- Start Speculos from the directory holding the app

  ```sh
  docker run -d --rm --name speculos -v "$PWD":/apps \
    -p 9999:9999 -p 5000:5000 \
    ghcr.io/ledgerhq/speculos:v0.27.1@sha256:028d1e368244631578537e7ca50b6f13ca2932b5f3fd220627289b559c07a886 \
    --model nanosp --display headless --apdu-port 9999 --api-port 5000 \
    /apps/app-2.3.2-nanos2.elf
  ```

  - For a Flex, use `--model flex` and `app-2.3.2-flex.elf`. `nanox` and
    `stax` work the same way.
  - On macOS, AirPlay Receiver holds port 5000. Map the API elsewhere, e.g.
    `-p 5001:5000`, and point `SPECULOS_API_URL` at it.
- Run the tests, with `SPECULOS_MODEL` matching `--model`
  - `$ SPECULOS_APDU_ADDR=127.0.0.1:9999 SPECULOS_API_URL=http://127.0.0.1:5000 SPECULOS_MODEL=nanosp cargo test -p coins-ledger --features speculos`
- `$ docker stop speculos`

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
