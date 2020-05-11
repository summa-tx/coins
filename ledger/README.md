# ledger-rs

Communication library between Rust and Ledger Nano S/X devices



# License Notes

This repo was forked from [Zondax's work](https://github.com/Zondax/ledger-rs)
at commit `7d40af9653d04e2d40f8b0c031675b6ff82d7f2c`. Their code is used under
the Apache 2 License. Files containing elements from their code maintain their
original Apache 2 license notice at the bottom of the file.

Further work by Summa is available under the GNU LGPLv3 license.

These changes are as follows:
- Remove bip44 crates
- Significant refactoring to all other crates
- Crates have been moved to be modules of a single crate
