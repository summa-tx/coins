//! Handshake TxOut and Vout types.

use crate::types::{Covenant, LockingScript, LockingScriptType, WitnessProgram};
use coins_core::{
    ser::{ByteFormat, SerError, SerResult},
    types::tx::Output,
};
use std::io::{Read, Write};

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
    pub covenant: Covenant,
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
    pub fn new<T, I>(value: u64, locking_script: T, covenant: I) -> Self
    where
        T: Into<LockingScript>,
        I: Into<Covenant>,
    {
        TxOut {
            value,
            locking_script: locking_script.into(),
            covenant: covenant.into(),
        }
    }

    /// Instantiate the null TxOut, which is used SIGHASH_SINGLE
    pub fn null() -> Self {
        TxOut {
            value: 0x00,
            locking_script: LockingScript::null(),
            covenant: Covenant::null(),
        }
    }

    /// Instantiate an OP_RETURN output with some data. Discards all but the first 40 bytes.
    pub fn op_return(data: &[u8]) -> Self {
        let mut data = data.to_vec();
        data.truncate(40);

        let locking_script = LockingScript {
            version: 31,
            witness_program: WitnessProgram::from(data),
        };

        TxOut {
            value: 0,
            locking_script,
            covenant: Covenant::null(),
        }
    }

    /// Inspect the TxOut's script pubkey to determine its type.
    pub fn standard_type(&self) -> LockingScriptType {
        self.locking_script.standard_type().unwrap_or(LockingScriptType::NonStandard)
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
        len += self.covenant.serialized_length();
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
            covenant,
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

/// Vout is a type alias for `Vec<TxOut>`. A transaction's Vout is the Vector of
/// OUTputs, with a length prefix.
pub type Vout = Vec<TxOut>;

#[cfg(test)]
mod test {
    use super::*;
    use coins_core::ser::ByteFormat;

    #[test]
    fn it_creates_null_output() {
        let null = TxOut::null();
        let expected = "0000000000000000001400000000000000000000000000000000000000000000";
        assert_eq!(null.serialize_hex(), expected);
    }

    #[test]
    fn it_serialized_and_deserialized_output() {
        let cases = [
            "b4ef3e77000000000014feee08a4329901bbc61ceced7ef78c1cfcc3b4b00000",
            "987d36770000000000146563bad4b48ce73d7bdefba8f0264db327047f460000",
            "c0d8a700000000000014149271b32ae5707624539d710de8e384a4d685c9040320f4922a48640cf43dcc0b2236304a05b12653035d4255598797bc98b6a352dd42044643000020c5222e1530215c52d4ed1db17dbbc2a21467b9a4c82c4c2b97a688871d780d55",
            "000000000000000000147f4f65e65f72de01ef6be2c69173e1c487b42c4a040320f4922a48640cf43dcc0b2236304a05b12653035d4255598797bc98b6a352dd420446430000208e507039765891b162941dd9a8728a6777048f21ba262d6c55d0a04fa0161e65",
            "108605000000000000148bb472116b682a4588aa739ee3b97a122d29ee670000",
            "200b20000000000000143686414504952ea8ffa873137ce8d270d9f0f9fb030420d8fe174a0bbaaadc1e340403bc51ae18c33e8b13229dcf52d53921298c9e033b049344000006706c65617365209a53b52114001717823b7de97a2534ea95782a021ba61ae4f533f4f64dc5a6cb",
            "603555b5050000000014648cf749c98fb59379028e97fb8c6e0eb0c6c0ec0000"
        ];

        for expected in cases.iter() {
            let utxo = TxOut::deserialize_hex(expected).unwrap();
            let hex = utxo.serialize_hex();
            assert_eq!(hex, *expected);
        }
    }

    #[test]
    fn it_computes_serialized_length_output() {
        let cases = [
            "3cee3577000000000014feee08a4329901bbc61ceced7ef78c1cfcc3b4b00000",
            "8096980000000000001442a277aa37cde1376cbd02f650d2cd3cc14e277b0604206b231c0805edfb826cfab8589e97c9951104073854ff0e047abe7d3ffb6141e90425410000130002036e73310465637070002ce706b701c0022000000000000000e4eadc42be16685f63402a073cfec8575840fb7e40a3f73e68",
            "8487e400000000000014cd922806ffc060e3d2dd8b014570f92ef0c8d6930000",
            "e0c1367700000000001400bfb1e341bb84a68dd0bc1781c5ece5e5dc32820000",
            "ce8b5f4301000000001486b2ccfa412e2cbd6df486cd27f4823e1dd7f7a20000",
            "e70a5cd2050000000014ae8645770dfd8eb3b0fe9a6a1d8ef6280480180a0000",
            "00000000000000000014af8b17b456738c3ac59843c9b92a7fe08cc1b246060420aca9035ad403c9897daee5e9278564daf16d19481f56998e06837410aa0be1d204af3f00001a0002036e73310b76697368616c6e61676172002ce706b701c002200000000000000093406ecb0183cb631e0ec504c0f2d8ac6172f35895cbcadde0",
            "aac495a92d0000000014b9fb83ead48e786d00a4daaeb024e16673ccdb380000",
            "00000000000000000014ea4158777c5fd598abcba154f13788e95d98d848060420b1c3c1b212444310447999b2a621d0bd783eef10fe71aef808d53729d972dc9d044f400000120002036e7331036d6733002ce706b701c0022000000000000000e4eadc42be16685f63402a073cfec8575840fb7e40a3f73e68",
            "189610000000000000147e3cf9904f4203c01a68298f3b4cb3ac391ed4980000"
        ];

        for expected in cases.iter() {
            let utxo = TxOut::deserialize_hex(expected).unwrap();
            let len = utxo.serialized_length();
            let hex = hex::decode(expected).unwrap();
            assert_eq!(len, hex.len());
        }
    }
}
