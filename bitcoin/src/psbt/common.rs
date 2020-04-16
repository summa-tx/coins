use std::{
    io::{Error as IOError},
    ops::{Index, IndexMut},
};

use thiserror::{Error};

use riemann_core::{
    ser::{SerError},
    types::primitives::{ConcretePrefixVec, PrefixVec},
};

use crate::types::transactions::{TxError};

/// An Error type for PSBT objects
#[derive(Debug, Error)]
pub enum PSBTError{
    /// Serialization-related errors
    #[error("Serialization-related error: {0}")]
    SerError(#[from] SerError),

    /// IOError bubbled up from a `Write` passed to a `Ser::serialize` implementation.
    #[error("IO-related error: {0}")]
    IOError(#[from] IOError),

    /// PSBT Prefix does not match the expected value
    #[error("Bad PSBT Prefix. Expected psbt with 0xff separator.")]
    BadPrefix,

    /// PSBT Global map tx value is not a valid legacy transaction.
    #[error("Global map contains invalid transaction")]
    InvalidTx(#[from] TxError),

    /// Returned by convenience functions that attempt to read a non-existant key
    #[error("Non-existant key")]
    MissingKey,

    /// Placeholder. TODO: Differentiate later
    #[error("Invalid PSBT. Unknown cause.")]
    InvalidPSBT,
}

wrap_prefixed_byte_vector!(
    /// A PSBT Key
    PSBTKey
);

wrap_prefixed_byte_vector!(
    /// A PSBT Value
    PSBTValue
);

impl PSBTKey {
    /// The BIP174 type of the key (its first byte)
    pub fn key_type(&self) -> u8 {
        self[0]
    }
}
