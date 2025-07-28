//! # Coins Core
//!
//! `coins-core` contains utilities and traits used by the `coins-bip32` and
//! `coins-bip39` crates.
//!
//! ## Crate Layout
//!
//! ### Hashes
//!
//! The hashes module provides utilities for newtyping hash outputs, including
//! sha2, sha3, and ripemd160. These newtypes are called `Marked__` and are
//! intended to be used for a specific purpose. E.g. `Hash256` is a marked type
//! for Bitcoin's double-sha2, while `Hash160` is a marked type for Bitcoin's
//! `ripemd160(sha2(x))`.
//!
//! #### Ser trait
//!
//! The `Ser` trait is a simple serialization API using
//! `std::io::{Read, Write}`. Implementers define the binary serialization
//! format of the type, as well as the JSON serialization. The transaction type
//! must implement `Ser`, as the provided `txid` logic assumes access to the
//! `serialize` method.
//!
//! `Ser` has an associated `Error` type. Most basic types can simply use the
//! provided `SerError`. However, more complex (de)serialization will want to
//! implement a custom error type to handle (e.g.) invalid transactions. These
//! types must be easily instantiated from a `SerError` or an `std::io::Error`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(unused_extern_crates)]

#[macro_use]
pub mod macros;

pub mod hashes;
pub mod ser;
