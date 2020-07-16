//! Ledger Bitcoin Application
//!
//! This application handles getting XPubs and signatures from the ledger device, and relies
//! heavily on the `coins_bip32` and `bitcoins` crates. Please see those crates for documentation
//! of their respective types.
//!
//!
//!
//! This app can be used in native and WASM applications. In native settings, it uses the `hidapi`
//! to acquire the lock, while in WASM applications it uses a ledger JS transport library.

#![warn(missing_docs)]
#![warn(unused_extern_crates)]

pub(crate) mod utils;

/// Core BTC APP.
pub mod app;

pub use app::{SigningInfo, LedgerBTC};

use thiserror::Error;

/// Error types
#[derive(Error, Debug)]
pub enum LedgerBTCError {
    /// Bip32 Error
    #[error(transparent)]
    Bip32Error(#[from] coins_bip32::Bip32Error),

    /// Derivation path too long for ledger
    #[error("Derivation Path is too long. Only 10 derivations allowed.")]
    DerivationTooLong,

    /// Underlying ledger transport error
    #[error(transparent)]
    LedgerError(#[from] coins_ledger::errors::LedgerError),

    /// Device response was unexpectedly none
    #[error("Received unexpected response from device. Expected data in response, found none.")]
    UnexpectedNullResponse,

    /// `get_tx_signatures` received an incorrect number of signing_info objects
    #[error(
        "Received the wrong number of prevouts/key derivtions while signing. Need 1 per witness."
    )]
    SigningInfoLengthMismatch,
}
