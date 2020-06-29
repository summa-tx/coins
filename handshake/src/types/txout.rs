//! Handshake TxOut and Vout types.

use std::io::{Read, Write};
use crate::types::{
    LockingScript, LockingScriptType,
    WitnessProgram, Covenant
};
use riemann_core::{
    ser::{ByteFormat, SerError, SerResult},
    types::tx::Output
};

/// An Output. This describes a new UTXO to be created. The value is encoded as an LE u64.
/// The LockingScript encodes spending constraints.
///
/// `TxOut::null()` and `TxOut::default()` return the "null" TxOut, which has a value of
/// 0xffff_ffff_ffff_ffff, and an empty `script_pubkey`. This null output is used within legacy
/// sighash calculations.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TxOut {
    /// The value of the output in dollarydoos.
    pub value: u64,
    /// The `LockingScript` which locks the UTXO.
    pub locking_script: LockingScript,
    /// The `Covenant` which locks the way the UTXO can be spent.
    pub covenant: Covenant
}

impl Output for TxOut {
    type Value = u64;
    type RecipientIdentifier = LockingScript;
}

impl Default for TxOut {
    fn default() -> Self {
        Self::null()
    }
}

impl TxOut {
    /// Instantiate a new TxOut.
    pub fn new<T, I>(value: u64, LockingScript: T, Covenant: I) -> Self
    where
        T: Into<LockingScript>,
        I: Into<Covenant>
    {
        TxOut {
            value,
            locking_script: LockingScript.into(),
            covenant: Covenant.into()
        }
    }

    /// Instantiate the null TxOut, which is used SIGHASH_SINGLE
    pub fn null() -> Self {
        TxOut {
            value: 0xffff_ffff_ffff_ffff,
            locking_script: LockingScript::null(),
            covenant: Covenant::null()
        }
    }

    /// Instantiate an OP_RETURN output with some data. Discards all but the first 75 bytes.
    pub fn op_return(data: &[u8]) -> Self {
        let mut data = data.to_vec();
        data.truncate(40);

        let locking_script = LockingScript {
            version: 31,
            witness_program: WitnessProgram::from(data)
        };

        TxOut {
            value: 0,
            locking_script: locking_script,
            covenant: Covenant::null()
        }
    }

    /// Inspect the TxOut's script pubkey to determine its type.
    pub fn standard_type(&self) -> LockingScriptType {
        self.locking_script.standard_type()
    }

    /// Extract the op return payload. None if not an op return.
    pub fn extract_op_return_data(&self) -> Option<Vec<u8>> {
        self.locking_script.extract_op_return_data()
    }
}

impl ByteFormat for TxOut {
    type Error = SerError;

    fn serialized_length(&self) -> usize {
        let mut len = 8; // value
        len += self.locking_script.serialized_length();
        len
    }

    fn read_from<R>(reader: &mut R, _limit: usize) -> SerResult<Self>
    where
        R: Read,
        Self: std::marker::Sized,
    {
        let value = Self::read_u64_le(reader)?;
        let locking_script = LockingScript::read_from(reader, 0)?;
        let covenant = Covenant::read_from(reader, 0)?;

        Ok(Self {
            value,
            locking_script,
            covenant
        })
    }

    fn write_to<W>(&self, writer: &mut W) -> SerResult<usize>
    where
        W: Write,
    {
        let mut len = Self::write_u64_le(writer, self.value)?;
        len += self.locking_script.write_to(writer)?;
        len += self.covenant.write_to(writer)?;
        Ok(len)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use riemann_core::ser::ByteFormat;

    #[test]
    fn it_creates_null_output() {
        let txout = TxOut::null();
        println!("{:?}", txout);
    }
}
