use std::{collections::btree_map, io::Error as IOError, ops::RangeBounds};

use thiserror::Error;

use coins_core::{impl_hex_serde, ser::SerError, wrap_prefixed_byte_vector};

use bitcoins::types::{ScriptType, TxError};

use crate::schema;

/// An Error type for PSBT objects
#[derive(Debug, Error)]
pub enum PSBTError {
    /// Serialization-related errors
    #[error(transparent)]
    SerError(#[from] SerError),

    /// IOError bubbled up from a `Write` passed to a `Ser::serialize` implementation.
    #[error(transparent)]
    IOError(#[from] IOError),

    /// PSBT Global map tx value is not a valid legacy transaction.
    #[error(transparent)]
    TxError(#[from] TxError),

    /// Bubbled up from the BIP32 library
    #[error(transparent)]
    Bip32Error(#[from] coins_bip32::Bip32Error),

    /// Returned by convenience functions that attempt to read a non-existant key
    #[error("Attempted to get missing singleton key {0}")]
    MissingKey(u8),

    /// Returned when attempting to deserialize an invalid PSBT with duplicate keys
    #[error("Attempted to deserialize PSBT with duplicate key {0:?}")]
    DuplicateKey(PSBTKey),

    /// PSBT Prefix does not match the expected value
    #[error("Bad PSBT Prefix. Expected psbt with 0xff separator.")]
    BadPrefix,

    /// Placeholder. TODO: Differentiate later
    #[error("Invalid PSBT. Unknown cause.")]
    InvalidPSBT,

    /// The tx contained a non-empty scriptsig.
    #[error("PSBT tx contains non-empty scriptsig.")]
    ScriptSigInTx,

    /// An input map contained a non-witness prevout marked as a witness prevout.
    #[error("Non-witness TxOut under witness input key.")]
    InvalidWitnessTXO,

    /// Returned from schema validation when the key size is unexpected
    #[error("Key failed validation. Wrong length. Expected {expected} bytes. Got {got} bytes")]
    WrongKeyLength {
        /// The expected key length
        expected: usize,
        /// The actual key length
        got: usize,
    },

    /// Returned from schema validation when the value size is unexpected
    #[error("Value failed validation. Wrong length. Expected {expected} bytes. Got {got} bytes")]
    WrongValueLength {
        /// The expected value length
        expected: usize,
        /// The actual value length
        got: usize,
    },

    /// Returned from schema validation when the key size is unexpected
    #[error("Key failed validation. Wrong type. Expected {expected}. Got {got}")]
    WrongKeyType {
        /// The expected key length
        expected: u8,
        /// The actual key length
        got: u8,
    },

    /// Returned when a serialized bip32 derivation is invalid. This
    #[error("Invalid bip32 derivation.")]
    InvalidBip32Path,

    /// Returned when a PSBT_GLOBAL_XPUB's stated depth does not match its provided derivation path.
    #[error("Master pubkey depth did not match derivation path elements")]
    Bip32DepthMismatch,

    /// Returned when a PSBT's `Input` map vec length doesn't match its transaction's vin length
    #[error("Vin length mismatch. Tx has {tx_ins} inputs. PSBT has {maps} input maps")]
    VinLengthMismatch {
        /// The number of inputs in the transaction.
        tx_ins: usize,
        /// The number of input maps in the PSBT
        maps: usize,
    },

    /// Returned when a PSBT's `Output` map vec length doesn't match its transaction's vout length
    #[error("Vout length mismatch. Tx has {tx_outs} outputs. PSBT has {maps} output maps")]
    VoutLengthMismatch {
        /// The number of outputs in the transaction.
        tx_outs: usize,
        /// The number of output maps in the PSBT
        maps: usize,
    },

    /// Returned when an unexpected script type is found. E.g. when a redeem script is found,
    /// but the prevout script pubkey is not P2SH.
    #[error("Wrong prevout script_pubkey type. Got: {got:?}. Expected {expected:?}")]
    WrongPrevoutScriptType {
        /// The actual script type
        got: ScriptType,
        /// The expected script type
        expected: Vec<ScriptType>,
    },

    /// Attempted to extract a tx when at least 1 index is unfinalized. Contains the index of the
    /// first unfinalized input
    #[error("Can't extract Tx. Input {0} is not finalized.")]
    UnfinalizedInput(usize),

    /// Missing info for some processing step
    #[error("Missing required info: {0}")]
    MissingInfo(String),
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
        if self.is_empty() {
            0
        } else {
            self[0]
        }
    }
}

/// Common methods for our Global, Input, and Output maps
pub trait PSTMap {
    /// Returns a reference to the value corresponding to the key.
    fn get(&self, key: &PSBTKey) -> Option<&PSBTValue>;

    /// Returns true if the map contains a value for the specified key.
    fn contains_key(&self, key: &PSBTKey) -> bool;

    /// Return an iterator of the keys of the map
    fn keys(&self) -> btree_map::Keys<PSBTKey, PSBTValue>;

    /// Remove a key from the map
    fn remove(&mut self, key: &PSBTKey) -> Option<PSBTValue>;

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

    /// Insert a key into the map. Return the previous value if any
    fn insert(&mut self, key: PSBTKey, value: PSBTValue) -> Option<PSBTValue>;

    /// Return a range of KV pairs whose key type is `key_type`
    fn range_by_key_type(&self, key_type: u8) -> btree_map::Range<PSBTKey, PSBTValue> {
        let start: PSBTKey = vec![key_type].into();
        let end: PSBTKey = vec![key_type + 1].into();
        self.range(start..end)
    }

    /// Return the value or a MissingKey error
    fn must_get(&self, key: &PSBTKey) -> Result<&PSBTValue, PSBTError> {
        self.get(key)
            .ok_or_else(|| PSBTError::MissingKey(key.key_type()))
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
            let result: Result<Vec<_>, PSBTError> = self
                .range_by_key_type(*key_type)
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
