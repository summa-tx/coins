//! Ledger utilites and transports

#![warn(missing_docs)]
#![warn(unused_extern_crates)]

/// APDU utilities.
pub mod common;

/// Ledger-related error enum
pub mod errors;

/// Ledger transports. Contains native HID and wasm-bindgen
pub mod transports;

pub use {
    common::{APDUAnswer, APDUCommand},
    errors::LedgerError,
    transports::Ledger,
};
