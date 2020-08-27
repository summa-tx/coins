//! This module holds transaction inputs for Handshake transactions. Since
//! Handshake is a UTXO based blockchain, the transaction inputs point to a
//! UTXO by the transaction id and output index.
use std::io::{Read, Write};

use coins_core::{
    hashes::MarkedDigestOutput,
    ser::{self, ByteFormat, SerError, SerResult},
    types::tx::{Input, TXOIdentifier},
};

use crate::hashes::TXID;

/// An Outpoint. This is a unique identifier for a UTXO, and is composed of a transaction ID (in
/// Bitcoin-style LE format), and the index of the output being spent within that transactions
/// output vectour (vout).
///
/// `Outpoint::null()` and `Outpoint::default()` return the null Outpoint, which references a txid
/// of all 0, and a index 0xffff_ffff. This null outpoint is used in every coinbase transaction.
#[derive(serde::Serialize, serde::Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Outpoint<M>
where
    M: MarkedDigestOutput,
{
    /// The txid that created the UTXO being pointed to.
    pub txid: M,
    /// The index of that UTXO in the transaction's output vector.
    pub idx: u32,
}

impl<M> TXOIdentifier for Outpoint<M> where M: MarkedDigestOutput {}

impl<M> Outpoint<M>
where
    M: MarkedDigestOutput,
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
}

impl<M> Default for Outpoint<M>
where
    M: MarkedDigestOutput,
{
    fn default() -> Self {
        Outpoint::null()
    }
}

impl<M> ByteFormat for Outpoint<M>
where
    M: MarkedDigestOutput + ByteFormat,
{
    type Error = SerError;

    fn serialized_length(&self) -> usize {
        36
    }

    fn read_from<T>(reader: &mut T) -> SerResult<Self>
    where
        T: Read,
        Self: std::marker::Sized,
    {
        Ok(Outpoint {
            txid: M::read_from(reader).map_err(|e| SerError::ComponentError(format!("{}", e)))?,
            idx: ser::read_u32_le(reader)?,
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
        len += ser::write_u32_le(writer, self.idx)?;
        Ok(len)
    }
}

/// An TxInput. This data structure contains an outpoint referencing an existing UTXO,
/// a sequence number which may encode relative locktim semantics in version 2+ transactions.
///
/// Sequence encoding is complex and the field also encodes information about locktimes and RBF.
/// See [James' blogpost on the subject](https://prestwi.ch/bitcoin-time-locks/).
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TxInput<M>
where
    M: MarkedDigestOutput,
{
    /// The Outpoint identifying the UTXO being spent.
    pub outpoint: Outpoint<M>,
    /// The nSequence field
    pub sequence: u32,
}

impl<M> Input for TxInput<M>
where
    M: MarkedDigestOutput,
{
    type TXOIdentifier = Outpoint<M>;
}

impl<M> TxInput<M>
where
    M: MarkedDigestOutput,
{
    /// Instantiate a new TxInput
    pub fn new(outpoint: Outpoint<M>, sequence: u32) -> Self {
        TxInput { outpoint, sequence }
    }
}

impl<M> Default for TxInput<M>
where
    M: MarkedDigestOutput,
{
    fn default() -> Self {
        Self {
            outpoint: Outpoint::default(),
            sequence: 0xffffffff,
        }
    }
}

impl<M> ByteFormat for TxInput<M>
where
    M: MarkedDigestOutput + ByteFormat,
{
    type Error = SerError;

    fn serialized_length(&self) -> usize {
        let mut len = self.outpoint.serialized_length();
        len += 4; // sequence
        len
    }

    fn read_from<T>(reader: &mut T) -> SerResult<Self>
    where
        T: Read,
        Self: std::marker::Sized,
    {
        Ok(TxInput {
            outpoint: Outpoint::read_from(reader)?,
            sequence: ser::read_u32_le(reader)?,
        })
    }

    fn write_to<T>(&self, writer: &mut T) -> SerResult<usize>
    where
        T: Write,
    {
        let mut len = self.outpoint.write_to(writer)?;
        len += ser::write_u32_le(writer, self.sequence)?;
        Ok(len)
    }
}

/// A simple type alias for an input type that will be repeated throughout the `handshake` module.
pub type HandshakeTxIn = TxInput<TXID>;

/// A simple type alias for an outpoint type that will be repeated throught the `handshake` module.
pub type HandshakeOutpoint = Outpoint<TXID>;

/// Vin is a type alias for `Vec<TxInput>`. A transaction's Vin is the Vector of
/// INputs, with a length prefix.
pub type Vin = Vec<HandshakeTxIn>;

#[cfg(test)]
mod test {
    use super::*;
    use coins_core::ser::ByteFormat;

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
                HandshakeTxIn {
                    outpoint: Outpoint::null(),
                    sequence: 0x1234abcd,
                },
                format!("{}{}", NULL_OUTPOINT, "cdab3412"),
            ),
            (
                HandshakeTxIn::new(Outpoint::null(), 0x11223344),
                format!("{}{}", NULL_OUTPOINT, "44332211"),
            ),
        ];

        for case in cases.iter() {
            assert_eq!(case.0.serialized_length(), case.1.len() / 2);
            assert_eq!(case.0.serialize_hex(), case.1);
            assert_eq!(HandshakeTxIn::deserialize_hex(&case.1).unwrap(), case.0);
        }
    }
}
