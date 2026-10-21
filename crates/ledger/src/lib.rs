//! Ledger utilities and transports

#![warn(
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    unreachable_pub,
    clippy::missing_const_for_fn,
    rustdoc::all
)]
#![deny(unused_must_use, rust_2018_idioms)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

/// APDU utilities.
pub mod common;

/// Ledger-related error enum
pub mod errors;

/// Ledger transports. Contains the native HID transport.
pub mod transports;

pub use {
    common::{ApduAnswer, ApduBuffer, ApduCommand, BufferFull, CommandBuilder, StatusWord},
    errors::LedgerError,
};

/// The Ledger connection.
mod ledger;
pub use ledger::Ledger;

/// Ledger hardware models.
mod model;
pub use model::Model;
