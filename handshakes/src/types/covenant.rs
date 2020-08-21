//! Handshake Covenant Types

use coins_core::{impl_hex_serde, ser::{prefix_byte_len, ByteFormat, SerError, SerResult}};
use std::convert::TryFrom;
use std::io::{Read, Write};
use thiserror::Error;

coins_core::wrap_prefixed_byte_vector!(
    /// Represents an item in the covenant data field
    CovenantItem
);

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
/// CovenantData represents the public data represented with the UTXO.
pub struct CovenantData(Vec<CovenantItem>);

/// An Error type for Covenants
#[derive(Debug, Error)]
pub enum CovenantError {
    /// Unknown Covenant Type
    #[error("Unknown Covenant Type")]
    UnknownCovenant,
}

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
        size += self::prefix_byte_len(self.0.len() as u64) as usize;

        for item in self.0.iter() {
            size += item.serialized_length();
        }

        size
    }

    fn read_from<R>(reader: &mut R, _limit: usize) -> SerResult<Self>
    where
        R: Read,
        Self: std::marker::Sized,
    {
        let count = Self::read_compact_int(reader)?;

        let mut items = vec![];
        for _ in 0..count {
            // TODO(mark): sane limit argument?
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
        total += Self::write_compact_int(writer, self.0.len() as u64)?;

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
    pub covenant_data: CovenantData,
}

impl Covenant {
    /// Returns the null Covenant.
    pub fn null() -> Self {
        Self {
            covenant_type: CovenantType::try_from("NONE").expect("Known covenant type"),
            covenant_data: CovenantData::null(),
        }
    }
}

impl ByteFormat for Covenant {
    type Error = SerError;

    fn serialized_length(&self) -> usize {
        let mut size: usize = 1; // covenant_type
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
        // TODO(mark): sane max?
        let covenant_data = CovenantData::read_from(reader, 1024)?;

        Ok(Self {
            covenant_type: CovenantType::new(covenant_type),
            covenant_data,
        })
    }

    fn write_to<W>(&self, writer: &mut W) -> SerResult<usize>
    where
        W: Write,
    {
        let mut total: usize = 0;
        let covenant_type: u8 = self.covenant_type.as_u8();
        total += writer.write(&[covenant_type])?;
        total += &self.covenant_data.write_to(writer)?;

        Ok(total)
    }
}

/// A Covenant Type defines the possible spend paths
/// for a UTXO.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct CovenantType(u8);

impl CovenantType {
    /// Create a new Covenant from a u8.
    pub fn new(u: u8) -> Self {
        Self(u)
    }

    /// Convert a CovenantType into a u8.
    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

impl TryFrom<&str> for CovenantType {
    type Error = CovenantError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "NONE" => Ok(Self(0)),
            "CLAIM" => Ok(Self(1)),
            "OPEN" => Ok(Self(2)),
            "BID" => Ok(Self(3)),
            "REVEAL" => Ok(Self(4)),
            "REDEEM" => Ok(Self(5)),
            "REGISTER" => Ok(Self(6)),
            "UPDATE" => Ok(Self(7)),
            "RENEW" => Ok(Self(8)),
            "TRANSFER" => Ok(Self(9)),
            "FINALIZE" => Ok(Self(10)),
            "REVOKE" => Ok(Self(11)),
            _ => Err(CovenantError::UnknownCovenant),
        }
    }
}

impl TryFrom<u8> for CovenantType {
    type Error = CovenantError;

    fn try_from(u: u8) -> Result<Self, Self::Error> {
        match u {
            0 => Ok(Self(0)),
            1 => Ok(Self(1)),
            2 => Ok(Self(2)),
            3 => Ok(Self(3)),
            4 => Ok(Self(4)),
            5 => Ok(Self(5)),
            6 => Ok(Self(6)),
            7 => Ok(Self(7)),
            8 => Ok(Self(8)),
            9 => Ok(Self(9)),
            10 => Ok(Self(10)),
            11 => Ok(Self(11)),
            _ => Err(CovenantError::UnknownCovenant),
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

        assert_eq!(
            covenant.covenant_type,
            CovenantType::try_from("NONE").unwrap()
        );
        assert_eq!(covenant.covenant_data, CovenantData::null());

        let hex = covenant.serialize_hex();
        assert_eq!(hex, "0000");
    }

    #[test]
    fn it_serialized_covenant() {
        // type, data, expect
        let cases = [
            (CovenantType::try_from("NONE").unwrap(), vec![], "0000"),
            (CovenantType::try_from("CLAIM").unwrap(), vec![], "0100"),
        ];

        for case in cases.iter() {
            let covenant = Covenant {
                covenant_type: case.0.clone(),
                covenant_data: CovenantData(case.1.clone()),
            };

            let hex = covenant.serialize_hex();
            assert_eq!(hex, case.2);
        }
    }

    #[test]
    fn it_serialized_and_deserialized_covenant() {
        let cases = [
            "030420c322c0bbf17b761284357008a67ee3bdd894ee476aba6d9ff1312e6d0d90b27a04885e000007726564726f636b2035102638ebab552b657fc4a956ed5e682b4ac62253742ffe40d031ba3d359b57",
            "0000",
            "0604206b231c0805edfb826cfab8589e97c9951104073854ff0e047abe7d3ffb6141e90425410000130002036e73310465637070002ce706b701c0022000000000000000e4eadc42be16685f63402a073cfec8575840fb7e40a3f73e68",
            "0203208eaabab5a5c4af6b1d950a1da5d1c4155cd3e209bce6c0b7c7321ebdb17352b504000000000d66756e6e656c736167656e6379",
            "030420f2e78cd64e4b7aadfe8101b7254be0c3df29a4e5a74d03722ebc17f2a627964e04154a000003717977208c8bdaea55c4fe233e002d647a59254010df7cc90b0ab1465661c0a622e8d6ca",
            "040320b4ce9cfd8b761d1b3e8f3faa80f2cfa80ad4880f88fe8a1808fd0844a184d1cd042f470000201bb9fe8681ac53b3f08151965ab25c19b8a0a0cc5f583a4622679bb87bd0b2b9",
            "050220ecdf3fe7154b363f41d4effb0fe32aa94de65d3ba9cbb81934ced890fb84e72404a9410000",
            "0803205f8eeb37f99ed63ced719c320f4f7501a38a37919b6fb3a00f8bd6384649570204183a000020000000000000027f29e85ccfaa70cacfafff106a06fcfa94cbc1f30a8ac6877f",
            "070320ce67c9bf503707595adedb0ad48248cfb932bf43a39ab87f979673d4bc9aaa34041e400000200002036e733103333138002ce706b701c00202036e7332c006b9afcb2d01c013",
            "010620f3c2b29889c638a0951f35ee7ce238962ad86b49cf10c846bbd0f2374b5ba89404354b00000c73747265616d626561636f6e0101200000000000a5e40e8ba291bd7e8649747fa7fb8a7af39f5bacdb7433cd2f59710401000000",
            "0904206b539eb5aacc3c76ebce2821e533e48cb63a41a079a166b448b3206bf727ea7c04214400000100145c1df758ac031995d4bf3b7b474ab1f97d14b025",
            "0a0720c89aefd198561e0b68c4bcaa3246dd0ea3955235e5e46f369a8b4831ddf37dd704bf3d00000e786e2d2d312d3773626c6c6535620100040000000004000000002000000000000003a6bd0e1db842fb76b243b5aee1c82fe4378e74e13d97871b91"
        ];

        for expected in cases.iter() {
            let covenant = Covenant::deserialize_hex(expected).unwrap();
            let result = covenant.serialize_hex();
            assert_eq!(*expected, result);
        }
    }

    #[test]
    fn it_computes_serialized_length_covenant() {
        let cases = [
            "0000",
            "05022036ece7a5ce73a3f81758695f12fe800f26eb5372b39808518ae8f646969535d004d2390000",
            "04032089f5c2073ed53430ae1ad6c3c3996fabd5b82698ce5296a03a344c188548441f045e3f0000209aa0bdda3972e42c51b0beed726c33e116e180751f698cfb9c92130ae159110a",
            "06042036ece7a5ce73a3f81758695f12fe800f26eb5372b39808518ae8f646969535d004d23900001f0002036e73311068616c6c736f667265736964656e6365002ce706b701c00220000000000000013bbf8684e74d3f07e90502e992f539cd589be58b392ab0c99f",
            "030420bd6441d7875def27472793950ad5f4fe96b90e1f356ba29592292511168a65ae04773f00000a6f70656e6d696e64656420f8266cfcee6746db5ee918b05cff72b847c945ecb02a03eb21016752a511980a",
            "0203203fddad9f6246d35fa90490df727f2dd151ee5313d454d5ade8c68c14e1a25f43040000000008676f6e616c766573",
            "070320a29215ec0656c9e29482831090d059ddb18fdd07fe2f3edce98378c5b45311ac0425370000210001036e73310e6e65776e616d657365727665727303636f6d0001036e7332c006",
            "0a0720d961dcb58511997dd253661a1b4de22be1bd92071a507152194f742ff008ffbf04a6330000186d616e6f735f5f7468655f68616e64735f6f665f666174650100040000000004020000002000000000000000e32502495ef20a3f485aa5786c9637766df60bfee9ce487c2f"
        ];

        for expected in cases.iter() {
            let covenant = Covenant::deserialize_hex(expected).unwrap();
            let len = covenant.serialized_length();
            let hex = hex::decode(expected).unwrap();
            assert_eq!(len, hex.len());
        }
    }

    #[test]
    fn it_correctly_handles_unknown_covenant() {
        for i in 0..u8::MAX {
            let covenant = Covenant {
                covenant_type: CovenantType::new(i),
                covenant_data: CovenantData::null(),
            };

            let hex = covenant.serialize_hex();
            let got = Covenant::deserialize_hex(&hex).unwrap();

            assert_eq!(covenant, got);
        }
    }
}
