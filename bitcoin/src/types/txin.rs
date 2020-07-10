//! Bitcoin Outpoint, TxIn, and Vin types.

use std::io::{Read, Write};

use riemann_core::{
    hashes::marked::MarkedDigest,
    ser::{ByteFormat, SerError, SerResult},
    types::tx::{Input, TXOIdentifier},
};

use crate::{hashes::TXID, types::script::ScriptSig};
/// An Outpoint. This is a unique identifier for a UTXO, and is composed of a transaction ID (in
/// Bitcoin-style LE format), and the index of the output being spent within that transactions
/// output vectour (vout).
///
/// `Outpoint::null()` and `Outpoint::default()` return the null Outpoint, which references a txid
/// of all 0, and a index 0xffff_ffff. This null outpoint is used in every coinbase transaction.
#[derive(serde::Serialize, serde::Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Outpoint<M>
where
    M: MarkedDigest,
{
    /// The txid that created the UTXO being pointed to.
    pub txid: M,
    /// The index of that UTXO in the transaction's output vector.
    pub idx: u32,
}

impl<M> TXOIdentifier for Outpoint<M> where M: MarkedDigest {}

impl<M> Outpoint<M>
where
    M: MarkedDigest,
{
    /// Returns a new Outpoint from a digest and index
    pub fn new(txid: M, idx: u32) -> Self {
        Self { txid, idx }
    }

    /// Returns the `default`, or `null` Outpoint. This is used in the coinbase input.
    pub fn null() -> Self {
        Outpoint {
            txid: M::default(),
            idx: 0xffff_ffff,
        }
    }

    /// Return the BE txid as hex, suitable for block explorers
    pub fn txid_be_hex(&self) -> String {
        let mut buf = self.txid.bytes();
        buf.reverse();
        buf.serialize_hex()
    }

    /// Instantiate an outpoint from the Block Explore (big-endian) TXID format and integer index
    pub fn from_explorer_format(txid_be: M, idx: u32) -> Self {
        Self {
            txid: txid_be.reversed(),
            idx,
        }
    }
}

impl<M> Default for Outpoint<M>
where
    M: MarkedDigest,
{
    fn default() -> Self {
        Outpoint::null()
    }
}

impl<M> ByteFormat for Outpoint<M>
where
    M: MarkedDigest + ByteFormat,
{
    type Error = SerError;

    fn serialized_length(&self) -> usize {
        36
    }

    fn read_from<T>(reader: &mut T, _limit: usize) -> SerResult<Self>
    where
        T: Read,
        Self: std::marker::Sized,
    {
        Ok(Outpoint {
            txid: M::read_from(reader, 0)
                .map_err(|e| SerError::ComponentError(format!("{}", e)))?,
            idx: Self::read_u32_le(reader)?,
        })
    }

    fn write_to<T>(&self, writer: &mut T) -> SerResult<usize>
    where
        T: Write,
    {
        let mut len = self
            .txid
            .write_to(writer)
            .map_err(|e| SerError::ComponentError(format!("{}", e)))?;
        len += Self::write_u32_le(writer, self.idx)?;
        Ok(len)
    }
}

/// An TxInput. This data structure contains an outpoint referencing an existing UTXO, a
/// `script_sig`, which will contain spend authorization information (when spending a Legacy or
/// Witness-via-P2SH prevout), and a sequence number which may encode relative locktim semantics
/// in version 2+ transactions.
///
/// The `script_sig` is always empty (a null prefixed vector), for native Witness prevouts.
///
/// Sequence encoding is complex and the field also encodes information about locktimes and RBF.
/// See [my blogpost on the subject](https://prestwi.ch/bitcoin-time-locks/).
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq, Default)]
pub struct TxInput<M>
where
    M: MarkedDigest,
{
    /// The Outpoint identifying the UTXO being spent.
    pub outpoint: Outpoint<M>,
    /// For Legacy transactions, the authorization information necessary to spend the UTXO.
    pub script_sig: ScriptSig,
    /// The nSequence field
    pub sequence: u32,
}

impl<M> Input for TxInput<M>
where
    M: MarkedDigest,
{
    type TXOIdentifier = Outpoint<M>;
}

impl<M> TxInput<M>
where
    M: MarkedDigest,
{
    /// Instantiate a new TxInput
    pub fn new<T>(outpoint: Outpoint<M>, script_sig: T, sequence: u32) -> Self
    where
        T: Into<ScriptSig>,
    {
        TxInput {
            outpoint,
            script_sig: script_sig.into(),
            sequence,
        }
    }

    /// Copy the input, stripping the scriptsig information.
    pub fn unsigned(&self) -> TxInput<M> {
        Self::new(self.outpoint, vec![], self.sequence)
    }
}

impl<M> ByteFormat for TxInput<M>
where
    M: MarkedDigest + ByteFormat,
{
    type Error = SerError;

    fn serialized_length(&self) -> usize {
        let mut len = self.outpoint.serialized_length();
        len += self.script_sig.serialized_length();
        len += 4; // sequence
        len
    }

    fn read_from<T>(reader: &mut T, _limit: usize) -> SerResult<Self>
    where
        T: Read,
        Self: std::marker::Sized,
    {
        Ok(TxInput {
            outpoint: Outpoint::read_from(reader, 0)?,
            script_sig: ScriptSig::read_from(reader, 0)?,
            sequence: Self::read_u32_le(reader)?,
        })
    }

    fn write_to<T>(&self, writer: &mut T) -> SerResult<usize>
    where
        T: Write,
    {
        let mut len = self.outpoint.write_to(writer)?;
        len += self.script_sig.write_to(writer)?;
        len += Self::write_u32_le(writer, self.sequence)?;
        Ok(len)
    }
}

/// A simple type alias for an outpoint type that will be repeated throught the `bitcoin` module.
pub type BitcoinOutpoint = Outpoint<TXID>;

/// A simple type alias for an input type that will be repeated throughout the `bitcoin` module.
pub type BitcoinTxIn = TxInput<TXID>;

/// Vin is a type alias for `Vec<TxInput>`. A transaction's Vin is the Vector of
/// INputs, with a length prefix.
pub type Vin = Vec<BitcoinTxIn>;

#[cfg(test)]
mod test {
    use super::*;
    use riemann_core::ser::ByteFormat;

    static NULL_OUTPOINT: &str =
        "0000000000000000000000000000000000000000000000000000000000000000ffffffff";

    #[test]
    fn it_serializes_and_derializes_outpoints() {
        let cases = [
            (
                Outpoint::<TXID> {
                    txid: TXID::default(),
                    idx: 0,
                },
                (0..36).map(|_| "00").collect::<String>(),
            ),
            (Outpoint::<TXID>::null(), NULL_OUTPOINT.to_string()),
        ];
        for case in cases.iter() {
            assert_eq!(case.0.serialized_length(), case.1.len() / 2);
            assert_eq!(case.0.serialize_hex(), case.1);
            assert_eq!(Outpoint::<TXID>::deserialize_hex(&case.1).unwrap(), case.0);
        }
    }

    #[test]
    fn it_serializes_and_derializes_inputs() {
        let cases = [
            (
                BitcoinTxIn {
                    outpoint: Outpoint::null(),
                    script_sig: ScriptSig::null(),
                    sequence: 0x1234abcd,
                },
                format!("{}{}{}", NULL_OUTPOINT, "00", "cdab3412"),
            ),
            (
                BitcoinTxIn::new(Outpoint::null(), vec![], 0x11223344),
                format!("{}{}{}", NULL_OUTPOINT, "00", "44332211"),
            ),
        ];

        for case in cases.iter() {
            assert_eq!(case.0.serialized_length(), case.1.len() / 2);
            assert_eq!(case.0.serialize_hex(), case.1);
            assert_eq!(BitcoinTxIn::deserialize_hex(&case.1).unwrap(), case.0);
        }
    }
}
