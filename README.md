<a href = "https://docs.rs/coins-bip32/latest/coins_bip32/" ><img alt="docs.rs" src="https://img.shields.io/docsrs/coins-bip32?label=bip32%20docs"></a>
<a href = "https://docs.rs/coins-bip39/latest/coins_bip39/" ><img alt="docs.rs" src="https://img.shields.io/docsrs/coins-bip39?label=bip39%20docs"></a>
<a href = "https://docs.rs/coins-ledger/latest/coins_ledger/" ><img alt="docs.rs" src="https://img.shields.io/docsrs/coins-ledger?label=ledger%20docs"></a>

# coins & bitcoins

`coins` aims to provide high-quality tooling for bip32, bip39, and ledger
device communication. It is a toolbox for building signers for blockchain
applications. `coins` runs natively and supports wasm targets for browser and
node.

This repo previously hosted a set of transaction construction libraries for
UTXO-based chains. You can find much of that work in the archive folder (for
now). [This is the last commit with that code in the main packages.](https://github.com/summa-tx/bitcoins-rs/tree/db28df1fb0d8dc71f149735bfa9a955d25b54f19)

## Building & running tests

- install [rustup](https://rustup.rs/)
- Run _all_ the tests `$ ./build.sh`
- build the docs: `$ cargo doc`

## Project Goals

- Support bip32, bip39, and Ledger device comms
- Provide basic tooling to support these use cases
- WASM compatibility in all packages

## Project Status

This project is used extensively in the ethers-rs ecosystem. However, much of
it is in an alpha/beta state. There will be rough edges, and the interfaces are
subject to change.

# License Notes

Some work in the `ledger` crate is reproduced under the APACHE 2.0 license. See
that README for specific info
