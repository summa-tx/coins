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
    #[error(transparent)]
    SerError(#[from] SerError),

    /// IOError bubbled up from a `Write` passed to a `Ser::serialize` implementation.
    #[error(transparent)]
    IOError(#[from] IOError),

    /// PSBT Prefix does not match the expected value
    #[error("Bad PSBT Prefix. Expected psbt with 0xff separator.")]
    BadPrefix,

    /// PSBT Global map tx value is not a valid legacy transaction.
    #[error(transparent)]
    InvalidTx(#[from] TxError),

    /// Returned by convenience functions that attempt to read a non-existant key
    #[error("Attempted to get missing singleton key {0}")]
    MissingKey(u8),

    /// Placeholder. TODO: Differentiate later
    #[error("Invalid PSBT. Unknown cause.")]
    InvalidPSBT,

    /// Returned when a key fails to pass a schema validation
    #[error("Key failed schema validation")]
    InvalidKeyFormat(PSBTKey),

    /// Returned when a value fails to pass a schema validation
    #[error("Value failed schema validation")]
    InvalidValueFormat(PSBTKey, PSBTValue),

    /// Returned from schema validation when the key size is unexpected
    #[error("Key failed validation. Wrong length. Expected {expected} bytes. Got {got} bytes")]
    WrongKeyLength{
        /// The expected key length
        expected: usize,
        /// The actual key length
        got: usize
    },

    /// Returned from schema validation when the value size is unexpected
    #[error("Value failed validation. Wrong length. Expected {expected} bytes. Got {got} bytes")]
    WrongValueLength{
        /// The expected value length
        expected: usize,
        /// The actual value length
        got: usize
    },

    /// Returned from schema validation when the key size is unexpected
    #[error("Key failed validation. Wrong type. Expected {expected}. Got {got}")]
    WrongKeyType{
        /// The expected key length
        expected: u8,
        /// The actual key length
        got: u8
    },

    /// Returned when a serialized bip32 derivation is invalid. This
    #[error("Invalid bip32 derivation.")]
    InvalidBIP32Path,
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
