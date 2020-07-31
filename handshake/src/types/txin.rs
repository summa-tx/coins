
use std::io::{Read, Write};

use coins_core::{
    hashes::marked::MarkedDigest,
    ser::{ByteFormat, SerError, SerResult},
    types::tx::Input,
};

use bitcoins::{hashes::TXID, types::txin::{Outpoint}};

// TODO: I need to change one public function on Outpoint
// from_explorer_format should not swap the endianness,
// because logic makes sense.

/// An TxInput. This data structure contains an outpoint referencing an existing UTXO,
/// a sequence number which may encode relative locktim semantics in version 2+ transactions.
///
/// Sequence encoding is complex and the field also encodes information about locktimes and RBF.
/// See [James' blogpost on the subject](https://prestwi.ch/bitcoin-time-locks/).
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TxInput<M>
where
    M: MarkedDigest,
{
    /// The Outpoint identifying the UTXO being spent.
    pub outpoint: Outpoint<M>,
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
    pub fn new(outpoint: Outpoint<M>, sequence: u32) -> Self {
        TxInput {
            outpoint,
            sequence,
        }
    }

    // TODO: remove this
    /// Copy the input, stripping the scriptsig information.
    pub fn unsigned(&self) -> TxInput<M> {
        Self::new(self.outpoint, self.sequence)
    }
}

impl<M> Default for TxInput<M>
where
    M: MarkedDigest,
{
    fn default() -> Self {
        Self {
            outpoint: Outpoint::default(),
            sequence: 0xffffffff
        }
    }

}

impl<M> ByteFormat for TxInput<M>
where
    M: MarkedDigest + ByteFormat,
{
    type Error = SerError;

    fn serialized_length(&self) -> usize {
        let mut len = self.outpoint.serialized_length();
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
            sequence: Self::read_u32_le(reader)?,
        })
    }

    fn write_to<T>(&self, writer: &mut T) -> SerResult<usize>
    where
        T: Write,
    {
        let mut len = self.outpoint.write_to(writer)?;
        len += Self::write_u32_le(writer, self.sequence)?;
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
