//! Partially Signed Bitcoin transactions (bip174)

/// Common data structures
pub mod common;
/// Global KV store
pub mod global;
/// Per-Input KV store
pub mod input;
/// Per-Output KV store
pub mod outputs;

pub use common::*;
pub use global::*;
pub use input::*;
pub use outputs::*;

use std::io::{Read, Write, Error as IOError};
use riemann_core::{
    primitives::{PrefixVec},
    ser::{Ser, SerError},
};
use thiserror::Error;

use crate::{
    types::{LegacyTx, TxError},
};

/// The magic PSBT version prefix
static MAGIC_BYTES: [u8; 4] = *b"psbt";

/// A BIP174 Partially Signed Bitcoin Transaction
pub struct PSBT {
    tx: LegacyTx,
    global: PSBTMap,
    inputs: Vec<PSBTMap>,
    outputs: Vec<PSBTMap>,
}

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


    /// Placeholder. TODO: Differentiate later
    #[error("Invalid PSBT. Unknown cause.")]
    InvalidPSBT,
}

impl Ser for PSBT {
    type Error = PSBTError;

    fn to_json(&self) -> String {
        unimplemented!("TODO")
    }

    fn serialized_length(&self) -> usize {
        let mut length: usize = 5;
        length += self.global.serialized_length();
        length += self.inputs.iter().map(|i| i.serialized_length()).sum::<usize>();
        length += self.outputs.iter().map(|o| o.serialized_length()).sum::<usize>();
        length
    }

    fn deserialize<R>(reader: &mut R, _limit: usize) -> Result<Self, PSBTError>
    where
        R: Read,
        Self: std::marker::Sized
    {
        let mut prefix = [0u8; 5];
        reader.read_exact(&mut prefix)?;
        if prefix[..4] != MAGIC_BYTES || prefix[4] != 0xff {
            return Err(PSBTError::BadPrefix);
        }

        let global = PSBTMap::deserialize(reader, 0)?;
        let tx_key: PSBTKey = vec![1u8, 0u8].into();
        let mut tx_bytes = global.get(&tx_key).ok_or(PSBTError::InvalidPSBT)?.items();
        let tx = LegacyTx::deserialize(&mut tx_bytes, 0)?;
        let inputs = vec![];
        let outputs = vec![];
        Ok(PSBT{
            tx,
            global,
            inputs,
            outputs,
        })
    }

    fn serialize<W>(&self, writer: &mut W) -> Result<usize, Self::Error>
    where
        W: Write
    {
        let mut len = writer.write(&MAGIC_BYTES)?;
        len += writer.write(&[0xffu8])?;
        len += self.global.serialize(writer)?;
        len += self.inputs.serialize(writer)?;
        len += self.outputs.serialize(writer)?;
        Ok(len)
    }
}
