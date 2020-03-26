//! Bitcoin Outpoint, TxIn, and Vin types.

use std::io::{Read, Write};

use crate::{
    bitcoin::{
        script::Script,
        hashes::TXID,
    },
    hashes::marked::{MarkedDigest},
    ser::{Ser, SerResult},
    types::primitives::{ConcretePrefixVec},
};

/// An Outpoint. This is a unique identifier for a UTXO, and is composed of a transaction ID (in
/// Bitcoin-style LE format), and the index of the output being spent within that transactions
/// output vectour (vout).
///
/// `Outpoint::null()` and `Outpoint::default()` return the null Outpoint, which references a txid
/// of all 0, and a index 0xffff_ffff. This null outpoint is used in every coinbase transaction.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Outpoint<M>
where
    M: MarkedDigest
{
    /// The txid that created the UTXO being pointed to.
    pub txid: M,
    /// The index of that UTXO in the transaction's output vector.
    pub idx: u32
}

impl<M> Outpoint<M>
where
    M: MarkedDigest
 {
    /// Returns the `default`, or `null` Outpoint. This is used in the coinbase input.
    pub fn null() -> Self {
        Outpoint{
            txid: M::default(),
            idx: 0xffff_ffff
        }
    }
}

impl<M> Default for Outpoint<M>
where
    M: MarkedDigest
{
    fn default() -> Self {
        Outpoint::null()
    }
}

impl<M> Ser for Outpoint<M>
where
    M: MarkedDigest + Ser
{
    fn serialized_length(&self) -> usize {
        36
    }

    fn deserialize<T>(reader: &mut T, _limit: usize) -> SerResult<Self>
    where
        T: Read,
        Self: std::marker::Sized
    {
        Ok(Outpoint{
            txid: M::deserialize(reader, 0)?,
            idx: u32::deserialize(reader, 0)?
        })
    }

    fn serialize<T>(&self, writer: &mut T) -> SerResult<usize>
    where
        T: Write
    {
        let mut len = self.txid.serialize(writer)?;
        len += self.idx.serialize(writer)?;
        Ok(len)
    }
}

/// An Input. This data structure contains an outpoint referencing an existing UTXO, a
/// `script_sig`, which will contain spend authorization information (when spending a Legacy or
/// Witness-via-P2SH prevout), and a sequence number which may encode relative locktim semantics
/// in version 2+ transactions.
///
/// The `script_sig` is always empty (a null prefixed vector), for native Witness prevouts.
///
/// Sequence encoding is complex and the field also encodes information about locktimes and RBF.
/// See [my blogpost on the subject](https://prestwi.ch/bitcoin-time-locks/).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Input<M>
where
    M: MarkedDigest
{
    /// The Outpoint identifying the UTXO being spent.
    pub outpoint: Outpoint<M>,
    /// For Legacy transactions, the authorization information necessary to spend the UTXO.
    pub script_sig: Script,
    /// The nSequence field
    pub sequence: u32
}

impl<M> Input<M>
where
    M: MarkedDigest
{
    /// Instantiate a new Input
    pub fn new<T>(outpoint: Outpoint<M>, script_sig: T, sequence: u32) -> Self
    where
        T: Into<Script>
    {
        Input{
            outpoint,
            script_sig: script_sig.into(),
            sequence
        }
    }
}

impl<M> Ser for Input<M>
where
    M: MarkedDigest + Ser
{
    fn serialized_length(&self) -> usize {
        let mut len = self.outpoint.serialized_length();
        len += self.script_sig.serialized_length();
        len += self.sequence.serialized_length();
        len
    }

    fn deserialize<T>(reader: &mut T, _limit: usize) -> SerResult<Self>
    where
        T: Read,
        Self: std::marker::Sized
    {
        Ok(Input{
            outpoint: Outpoint::deserialize(reader, 0)?,
            script_sig: Script::deserialize(reader, 0)?,
            sequence: u32::deserialize(reader, 0)?
        })
    }

    fn serialize<T>(&self, writer: &mut T) -> SerResult<usize>
    where
        T: Write
    {
        let mut len = self.outpoint.serialize(writer)?;
        len += self.script_sig.serialize(writer)?;
        len += self.sequence.serialize(writer)?;
        Ok(len)
    }
}

/// A simple type alias for an input type that will be repeated throughout the `bitcoin` module.
pub type TxIn = Input<TXID>;

/// Vin is a type alias for `ConcretePrefixVec<Input>`. A transaction's Vin is the Vector of
/// INputs, with a length prefix.
pub type Vin = ConcretePrefixVec<TxIn>;

#[cfg(test)]
mod test {
    use super::*;
    use crate::types::primitives::{Ser, PrefixVec};

    static NULL_OUTPOINT: &str = "0000000000000000000000000000000000000000000000000000000000000000ffffffff";

    #[test]
    fn it_serializes_and_derializes_outpoints() {
        let cases = [
        (Outpoint{txid: Hash256Digest::default(), idx: 0}, (0..36).map(|_| "00").collect::<String>()),
        (Outpoint::null(), NULL_OUTPOINT.to_string())
        ];
        for case in cases.iter() {
            assert_eq!(case.0.serialized_length(), case.1.len() / 2);
            assert_eq!(case.0.serialize_hex().unwrap(), case.1.to_owned());
            assert_eq!(Outpoint::deserialize_hex(case.1.to_owned()).unwrap(), case.0);
        }
    }

    #[test]
    fn it_serializes_and_derializes_inputs() {
        let cases = [
            (
                TxIn{
                    outpoint: Outpoint::null(),
                    script_sig: Script::null(),
                    sequence: 0x1234abcd
                },
                format!("{}{}{}", NULL_OUTPOINT, "00", "cdab3412")
            ),
            (
                TxIn{
                    outpoint: Outpoint::null(),
                    script_sig: Script::new_non_minimal(
                        vec![0x00, 0x14, 0x11, 0x00, 0x33, 0x00, 0x55, 0x00, 0x77, 0x00, 0x99, 0x00, 0xbb, 0x00, 0xdd, 0x00, 0xff, 0x11, 0x00, 0x33, 0x00, 0x55],
                        3
                    ).unwrap(),
                    sequence: 0x1234abcd

                },
                format!("{}{}{}", NULL_OUTPOINT, "fd1600001411003300550077009900bb00dd00ff1100330055", "cdab3412")
            ),
            (
                TxIn::new(
                    Outpoint::null(),
                    vec![],
                    0x11223344
                ),
                format!("{}{}{}", NULL_OUTPOINT, "00", "44332211")
            ),
        ];

        for case in cases.iter() {
            assert_eq!(case.0.serialized_length(), case.1.len() / 2);
            assert_eq!(case.0.serialize_hex().unwrap(), case.1.to_owned());
            assert_eq!(TxIn::deserialize_hex(case.1.to_owned()).unwrap(), case.0);
        }
    }
}
