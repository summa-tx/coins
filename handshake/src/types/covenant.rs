//! Handshake Covenant Types

use std::io::{Read, Write};
use coins_core::{
    ser::{ByteFormat, SerError, SerResult, write_compact_int, prefix_byte_len}
};

wrap_prefixed_byte_vector!(
    /// Represents an item in the covenant data field
    CovenantItem
);

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
/// CovenantData represents the public data represented with the UTXO.
pub struct CovenantData(Vec<CovenantItem>);

impl CovenantData {
    /// Returns a null CovenantData
    pub fn null() -> Self {
        Self(vec![])
    }
}

impl ByteFormat for CovenantData {
    type Error = SerError;

    fn serialized_length(&self) -> usize {
        let mut size: usize = 0;
        size += prefix_byte_len(self.0.len() as u64) as usize;

        for item in self.0.clone() {
            size += item.serialized_length();
        }

        size
    }

    // TODO: fix this
    fn read_from<R>(reader: &mut R, _limit: usize) -> SerResult<Self>
    where
        R: Read,
        Self: std::marker::Sized,
    {
      let count = Self::read_compact_int(reader)?;

      let mut items = vec![];
      for _ in 0..count {
          // TODO: sane limit argument?
          let item = CovenantItem::read_from(reader, 256)?;
          items.push(item);
      }

      Ok(Self(items))
    }

    fn write_to<W>(&self, writer: &mut W) -> SerResult<usize>
    where
        W: Write,
    {
        let mut total: usize = 0;

        // TODO: ByteFormat::write_compact_int
        // gives compile error for necessary type annotation?
        total += write_compact_int(writer, self.0.len() as u64)?;

        for covenant_data in self.0.clone() {
            total += covenant_data.write_to(writer)?;
        }

        Ok(total)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
/// A Covenant is a part of a Handshake UTXO that restricts how the UTXO may
/// be spent over the period of multiple spends. It is able to maintain
/// data over time.
pub struct Covenant {
    /// The CovenantType restricts spending to other CovenantTypes that have
    /// a defined spending path. State machines can be constructed this way
    /// that enable the auction system.
    pub covenant_type: CovenantType,
    /// The CovenantData represents Covenant specific data that is attached to
    /// the UTXO. This data must be updated correctly as the UTXO is spent from
    /// one CovenantType to the next CovenantType.
    pub covenant_data: CovenantData
}

impl Covenant {
    /// Returns the null Covenant.
    pub fn null() -> Self {
        Self {
            covenant_type: CovenantType::NONE,
            covenant_data: CovenantData::null()
        }
    }
}

impl ByteFormat for Covenant {
    type Error = SerError;

    fn serialized_length(&self) -> usize {
        let mut size: usize = 1;
        size += prefix_byte_len(self.covenant_data.0.len() as u64) as usize;
        size += self.covenant_data.serialized_length();
        size
    }

    fn read_from<R>(reader: &mut R, _limit: usize) -> SerResult<Self>
    where
        R: Read,
        Self: std::marker::Sized,
    {

        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        let covenant_type = u8::from_le_bytes(buf);
        // Sane max?
        let covenant_data = CovenantData::read_from(reader, 1024)?;

        Ok(Self {
            covenant_type: covenant_type.into(),
            covenant_data
        })
    }

    fn write_to<W>(&self, writer: &mut W) -> SerResult<usize>
    where
        W: Write,
    {
        // TODO: write var bytes
        let mut total: usize = 0;

        let covenant_type: u8 = self.covenant_type.clone() as u8;
        total += writer.write(&[covenant_type])?;
        total += &self.covenant_data.write_to(writer)?;

        Ok(total)
    }
}


/// Covenant types
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CovenantType {
    /// Standard Bitcoin-like Output
    NONE = 0,
    /// Reserved Name Claim Output
    CLAIM = 1,
    /// Auction Opening Output
    OPEN = 2,
    /// Blinded Bid Output
    BID = 3,
    /// Reveal Output
    REVEAL = 4,
    /// Auction Losers Must Redeem
    REDEEM = 5,
    /// Auction Winners Must Register
    REGISTER = 6,
    /// Update Name State
    UPDATE = 7,
    /// Renew Name
    RENEW = 8,
    /// Begin to Transfer Name
    TRANSFER = 9,
    /// Finalize Name Transfer
    FINALIZE = 10,
    /// Burn Name When Key is Compromised
    REVOKE = 11,
    /// Unknown Type
    UNKNOWN = 255
}

impl From<u8> for CovenantType {
    fn from(u: u8) -> Self {
        match u {
            0x00 => return CovenantType::NONE,
            0x01 => return CovenantType::CLAIM,
            0x02 => return CovenantType::OPEN,
            0x03 => return CovenantType::BID,
            0x04 => return CovenantType::REVEAL,
            0x05 => return CovenantType::REDEEM,
            0x06 => return CovenantType::REGISTER,
            0x07 => return CovenantType::UPDATE,
            0x08 => return CovenantType::RENEW,
            0x09 => return CovenantType::TRANSFER,
            0x10 => return CovenantType::FINALIZE,
            0x11 => return CovenantType::REVOKE,
            _ => return CovenantType::UNKNOWN
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use coins_core::ser::ByteFormat;

    #[test]
    fn it_creates_null_covenant() {
        let covenant = Covenant::null();

        assert_eq!(covenant.covenant_type, CovenantType::NONE);
        assert_eq!(covenant.covenant_data, CovenantData::null());

        let hex = covenant.serialize_hex();
        assert_eq!(hex, "0000");
    }

    #[test]
    fn it_serialized_covenant() {
        // type, data, expect
        let cases = [
            (CovenantType::NONE, vec![], "0000"),
            (CovenantType::CLAIM, vec![], "0100")
        ];

        for case in cases.iter() {
            let covenant = Covenant {
                covenant_type: case.0.clone(),
                covenant_data: CovenantData(case.1.clone())
            };

            let hex = covenant.serialize_hex();
            assert_eq!(hex, case.2);
        }
    }

    #[test]
    fn it_deserialized_covenant() {
        //let covenant = Covenant::deserialize_hex("0000");
    }
}
