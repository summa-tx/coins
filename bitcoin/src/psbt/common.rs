use std::{
    collections::btree_map,
    io::{Error as IOError},
    ops::{RangeBounds},
};

use thiserror::{Error};

use riemann_core::{
    ser::{SerError},
    types::primitives::{ConcretePrefixVec},
};

use crate::{
    psbt::schema,
    types::transactions::{TxError},
};

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

    /// Returned when a PSBT's `Input` map vec length doesn't match its transaction's vin length
    #[error("Vin length mismatch. Tx has {tx_ins} inputs. PSBT has {maps} input maps")]
    VinLengthMismatch{
        /// The number of inputs in the transaction.
        tx_ins: usize,
        /// The number of input maps in the PSBT
        maps: usize,
    },

    /// Returned when a PSBT's `Output` map vec length doesn't match its transaction's vout length
    #[error("Vout length mismatch. Tx has {tx_outs} outputs. PSBT has {maps} output maps")]
    VoutLengthMismatch{
        /// The number of outputs in the transaction.
        tx_outs: usize,
        /// The number of output maps in the PSBT
        maps: usize,
    },
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

/// Common methods for our Global, Input, and Output maps
pub trait PSTMap {
    /// Returns a reference to the value corresponding to the key.
    fn get(&self, key: &PSBTKey) -> Option<&PSBTValue>;

    /// Returns true if the map contains a value for the specified key.
    fn contains_key(&self, key: &PSBTKey) -> bool;

    /// Returns a range object over the specified range bounds.
    fn range<R>(&self, range: R) -> btree_map::Range<PSBTKey, PSBTValue>
    where
        R: RangeBounds<PSBTKey>;

    /// Returns a mutable reference to the value corresponding to the key.
    fn get_mut(&mut self, key: &PSBTKey) -> Option<&mut PSBTValue>;

    /// Gets an iterator over the entries of the map, sorted by key.
    fn iter(&self) -> btree_map::Iter<PSBTKey, PSBTValue>;

    /// Gets a mutable iterator over the entries of the map, sorted by key
    fn iter_mut(&mut self) -> btree_map::IterMut<PSBTKey, PSBTValue>;

    /// Gets an iterator over the entries of the map, sorted by key.
    fn insert(&mut self, key: PSBTKey, value: PSBTValue) -> Option<PSBTValue>;

    /// Return a range of KV pairs whose key type is `key_type`
    fn range_by_key_type(&self, key_type: u8) -> btree_map::Range<PSBTKey, PSBTValue> {
        let start: PSBTKey = vec![key_type].into();
        let end: PSBTKey = vec![key_type + 1].into();
        self.range(start..end)
    }

    /// Return the value or a MissingKey error
    fn must_get(&self, key: &PSBTKey) -> Result<&PSBTValue, PSBTError> {
        self.get(key).ok_or_else(|| PSBTError::MissingKey(key.key_type()))
    }

    /// Return a range containing any proprietary KV pairs
    fn proprietary(&self) -> btree_map::Range<PSBTKey, PSBTValue> {
        self.range_by_key_type(0xfc)
    }
}

/// Common methods for validating our PSBTMaps
pub trait PSBTValidate: PSTMap {
    /// Return a standard BIP174 KV-pair validation schema
    fn standard_schema() -> schema::KVTypeSchema;

    /// Check for consistency across multiple KV pairs
    fn consistency_checks(&self) -> Result<(), PSBTError>;

    /// Perform validation checks on the input
    fn validate_schema(&self, schema: schema::KVTypeSchema) -> Result<(), PSBTError> {
        // TODO:
        // Check that EITHER non_witness_utxo OR witness_utxo is present.
        // BOTH is NOT acceptable
        // NEITHER is acceptable
        for (key_type, predicate) in schema.0.iter() {
            let result: Result<Vec<_>, PSBTError> = self.range_by_key_type(*key_type)
                .map(|(k, v)| predicate(k, v))
                .collect();
            result?;
        }
        Ok(())
    }

    /// Run standard validation on the map
    fn validate(&self) -> Result<(), PSBTError> {
        self.validate_schema(Self::standard_schema())
    }
}
