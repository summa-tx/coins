//! Handshake Covenant Types

use coins_core::ser::{prefix_byte_len, ByteFormat, SerError, SerResult};
use std::io::{Read, Write};

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
            covenant_type: CovenantType::NONE,
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
            covenant_type: covenant_type.into(),
            covenant_data,
        })
    }

    fn write_to<W>(&self, writer: &mut W) -> SerResult<usize>
    where
        W: Write,
    {
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
    #[doc(hidden)]
    UNKNOWN12,
    #[doc(hidden)]
    UNKNOWN13,
    #[doc(hidden)]
    UNKNOWN14,
    #[doc(hidden)]
    UNKNOWN15,
    #[doc(hidden)]
    UNKNOWN16,
    #[doc(hidden)]
    UNKNOWN17,
    #[doc(hidden)]
    UNKNOWN18,
    #[doc(hidden)]
    UNKNOWN19,
    #[doc(hidden)]
    UNKNOWN20,
    #[doc(hidden)]
    UNKNOWN21,
    #[doc(hidden)]
    UNKNOWN22,
    #[doc(hidden)]
    UNKNOWN23,
    #[doc(hidden)]
    UNKNOWN24,
    #[doc(hidden)]
    UNKNOWN25,
    #[doc(hidden)]
    UNKNOWN26,
    #[doc(hidden)]
    UNKNOWN27,
    #[doc(hidden)]
    UNKNOWN28,
    #[doc(hidden)]
    UNKNOWN29,
    #[doc(hidden)]
    UNKNOWN30,
    #[doc(hidden)]
    UNKNOWN31,
    #[doc(hidden)]
    UNKNOWN32,
    #[doc(hidden)]
    UNKNOWN33,
    #[doc(hidden)]
    UNKNOWN34,
    #[doc(hidden)]
    UNKNOWN35,
    #[doc(hidden)]
    UNKNOWN36,
    #[doc(hidden)]
    UNKNOWN37,
    #[doc(hidden)]
    UNKNOWN38,
    #[doc(hidden)]
    UNKNOWN39,
    #[doc(hidden)]
    UNKNOWN40,
    #[doc(hidden)]
    UNKNOWN41,
    #[doc(hidden)]
    UNKNOWN42,
    #[doc(hidden)]
    UNKNOWN43,
    #[doc(hidden)]
    UNKNOWN44,
    #[doc(hidden)]
    UNKNOWN45,
    #[doc(hidden)]
    UNKNOWN46,
    #[doc(hidden)]
    UNKNOWN47,
    #[doc(hidden)]
    UNKNOWN48,
    #[doc(hidden)]
    UNKNOWN49,
    #[doc(hidden)]
    UNKNOWN50,
    #[doc(hidden)]
    UNKNOWN51,
    #[doc(hidden)]
    UNKNOWN52,
    #[doc(hidden)]
    UNKNOWN53,
    #[doc(hidden)]
    UNKNOWN54,
    #[doc(hidden)]
    UNKNOWN55,
    #[doc(hidden)]
    UNKNOWN56,
    #[doc(hidden)]
    UNKNOWN57,
    #[doc(hidden)]
    UNKNOWN58,
    #[doc(hidden)]
    UNKNOWN59,
    #[doc(hidden)]
    UNKNOWN60,
    #[doc(hidden)]
    UNKNOWN61,
    #[doc(hidden)]
    UNKNOWN62,
    #[doc(hidden)]
    UNKNOWN63,
    #[doc(hidden)]
    UNKNOWN64,
    #[doc(hidden)]
    UNKNOWN65,
    #[doc(hidden)]
    UNKNOWN66,
    #[doc(hidden)]
    UNKNOWN67,
    #[doc(hidden)]
    UNKNOWN68,
    #[doc(hidden)]
    UNKNOWN69,
    #[doc(hidden)]
    UNKNOWN70,
    #[doc(hidden)]
    UNKNOWN71,
    #[doc(hidden)]
    UNKNOWN72,
    #[doc(hidden)]
    UNKNOWN73,
    #[doc(hidden)]
    UNKNOWN74,
    #[doc(hidden)]
    UNKNOWN75,
    #[doc(hidden)]
    UNKNOWN76,
    #[doc(hidden)]
    UNKNOWN77,
    #[doc(hidden)]
    UNKNOWN78,
    #[doc(hidden)]
    UNKNOWN79,
    #[doc(hidden)]
    UNKNOWN80,
    #[doc(hidden)]
    UNKNOWN81,
    #[doc(hidden)]
    UNKNOWN82,
    #[doc(hidden)]
    UNKNOWN83,
    #[doc(hidden)]
    UNKNOWN84,
    #[doc(hidden)]
    UNKNOWN85,
    #[doc(hidden)]
    UNKNOWN86,
    #[doc(hidden)]
    UNKNOWN87,
    #[doc(hidden)]
    UNKNOWN88,
    #[doc(hidden)]
    UNKNOWN89,
    #[doc(hidden)]
    UNKNOWN90,
    #[doc(hidden)]
    UNKNOWN91,
    #[doc(hidden)]
    UNKNOWN92,
    #[doc(hidden)]
    UNKNOWN93,
    #[doc(hidden)]
    UNKNOWN94,
    #[doc(hidden)]
    UNKNOWN95,
    #[doc(hidden)]
    UNKNOWN96,
    #[doc(hidden)]
    UNKNOWN97,
    #[doc(hidden)]
    UNKNOWN98,
    #[doc(hidden)]
    UNKNOWN99,
    #[doc(hidden)]
    UNKNOWN100,
    #[doc(hidden)]
    UNKNOWN101,
    #[doc(hidden)]
    UNKNOWN102,
    #[doc(hidden)]
    UNKNOWN103,
    #[doc(hidden)]
    UNKNOWN104,
    #[doc(hidden)]
    UNKNOWN105,
    #[doc(hidden)]
    UNKNOWN106,
    #[doc(hidden)]
    UNKNOWN107,
    #[doc(hidden)]
    UNKNOWN108,
    #[doc(hidden)]
    UNKNOWN109,
    #[doc(hidden)]
    UNKNOWN110,
    #[doc(hidden)]
    UNKNOWN111,
    #[doc(hidden)]
    UNKNOWN112,
    #[doc(hidden)]
    UNKNOWN113,
    #[doc(hidden)]
    UNKNOWN114,
    #[doc(hidden)]
    UNKNOWN115,
    #[doc(hidden)]
    UNKNOWN116,
    #[doc(hidden)]
    UNKNOWN117,
    #[doc(hidden)]
    UNKNOWN118,
    #[doc(hidden)]
    UNKNOWN119,
    #[doc(hidden)]
    UNKNOWN120,
    #[doc(hidden)]
    UNKNOWN121,
    #[doc(hidden)]
    UNKNOWN122,
    #[doc(hidden)]
    UNKNOWN123,
    #[doc(hidden)]
    UNKNOWN124,
    #[doc(hidden)]
    UNKNOWN125,
    #[doc(hidden)]
    UNKNOWN126,
    #[doc(hidden)]
    UNKNOWN127,
    #[doc(hidden)]
    UNKNOWN128,
    #[doc(hidden)]
    UNKNOWN129,
    #[doc(hidden)]
    UNKNOWN130,
    #[doc(hidden)]
    UNKNOWN131,
    #[doc(hidden)]
    UNKNOWN132,
    #[doc(hidden)]
    UNKNOWN133,
    #[doc(hidden)]
    UNKNOWN134,
    #[doc(hidden)]
    UNKNOWN135,
    #[doc(hidden)]
    UNKNOWN136,
    #[doc(hidden)]
    UNKNOWN137,
    #[doc(hidden)]
    UNKNOWN138,
    #[doc(hidden)]
    UNKNOWN139,
    #[doc(hidden)]
    UNKNOWN140,
    #[doc(hidden)]
    UNKNOWN141,
    #[doc(hidden)]
    UNKNOWN142,
    #[doc(hidden)]
    UNKNOWN143,
    #[doc(hidden)]
    UNKNOWN144,
    #[doc(hidden)]
    UNKNOWN145,
    #[doc(hidden)]
    UNKNOWN146,
    #[doc(hidden)]
    UNKNOWN147,
    #[doc(hidden)]
    UNKNOWN148,
    #[doc(hidden)]
    UNKNOWN149,
    #[doc(hidden)]
    UNKNOWN150,
    #[doc(hidden)]
    UNKNOWN151,
    #[doc(hidden)]
    UNKNOWN152,
    #[doc(hidden)]
    UNKNOWN153,
    #[doc(hidden)]
    UNKNOWN154,
    #[doc(hidden)]
    UNKNOWN155,
    #[doc(hidden)]
    UNKNOWN156,
    #[doc(hidden)]
    UNKNOWN157,
    #[doc(hidden)]
    UNKNOWN158,
    #[doc(hidden)]
    UNKNOWN159,
    #[doc(hidden)]
    UNKNOWN160,
    #[doc(hidden)]
    UNKNOWN161,
    #[doc(hidden)]
    UNKNOWN162,
    #[doc(hidden)]
    UNKNOWN163,
    #[doc(hidden)]
    UNKNOWN164,
    #[doc(hidden)]
    UNKNOWN165,
    #[doc(hidden)]
    UNKNOWN166,
    #[doc(hidden)]
    UNKNOWN167,
    #[doc(hidden)]
    UNKNOWN168,
    #[doc(hidden)]
    UNKNOWN169,
    #[doc(hidden)]
    UNKNOWN170,
    #[doc(hidden)]
    UNKNOWN171,
    #[doc(hidden)]
    UNKNOWN172,
    #[doc(hidden)]
    UNKNOWN173,
    #[doc(hidden)]
    UNKNOWN174,
    #[doc(hidden)]
    UNKNOWN175,
    #[doc(hidden)]
    UNKNOWN176,
    #[doc(hidden)]
    UNKNOWN177,
    #[doc(hidden)]
    UNKNOWN178,
    #[doc(hidden)]
    UNKNOWN179,
    #[doc(hidden)]
    UNKNOWN180,
    #[doc(hidden)]
    UNKNOWN181,
    #[doc(hidden)]
    UNKNOWN182,
    #[doc(hidden)]
    UNKNOWN183,
    #[doc(hidden)]
    UNKNOWN184,
    #[doc(hidden)]
    UNKNOWN185,
    #[doc(hidden)]
    UNKNOWN186,
    #[doc(hidden)]
    UNKNOWN187,
    #[doc(hidden)]
    UNKNOWN188,
    #[doc(hidden)]
    UNKNOWN189,
    #[doc(hidden)]
    UNKNOWN190,
    #[doc(hidden)]
    UNKNOWN191,
    #[doc(hidden)]
    UNKNOWN192,
    #[doc(hidden)]
    UNKNOWN193,
    #[doc(hidden)]
    UNKNOWN194,
    #[doc(hidden)]
    UNKNOWN195,
    #[doc(hidden)]
    UNKNOWN196,
    #[doc(hidden)]
    UNKNOWN197,
    #[doc(hidden)]
    UNKNOWN198,
    #[doc(hidden)]
    UNKNOWN199,
    #[doc(hidden)]
    UNKNOWN200,
    #[doc(hidden)]
    UNKNOWN201,
    #[doc(hidden)]
    UNKNOWN202,
    #[doc(hidden)]
    UNKNOWN203,
    #[doc(hidden)]
    UNKNOWN204,
    #[doc(hidden)]
    UNKNOWN205,
    #[doc(hidden)]
    UNKNOWN206,
    #[doc(hidden)]
    UNKNOWN207,
    #[doc(hidden)]
    UNKNOWN208,
    #[doc(hidden)]
    UNKNOWN209,
    #[doc(hidden)]
    UNKNOWN210,
    #[doc(hidden)]
    UNKNOWN211,
    #[doc(hidden)]
    UNKNOWN212,
    #[doc(hidden)]
    UNKNOWN213,
    #[doc(hidden)]
    UNKNOWN214,
    #[doc(hidden)]
    UNKNOWN215,
    #[doc(hidden)]
    UNKNOWN216,
    #[doc(hidden)]
    UNKNOWN217,
    #[doc(hidden)]
    UNKNOWN218,
    #[doc(hidden)]
    UNKNOWN219,
    #[doc(hidden)]
    UNKNOWN220,
    #[doc(hidden)]
    UNKNOWN221,
    #[doc(hidden)]
    UNKNOWN222,
    #[doc(hidden)]
    UNKNOWN223,
    #[doc(hidden)]
    UNKNOWN224,
    #[doc(hidden)]
    UNKNOWN225,
    #[doc(hidden)]
    UNKNOWN226,
    #[doc(hidden)]
    UNKNOWN227,
    #[doc(hidden)]
    UNKNOWN228,
    #[doc(hidden)]
    UNKNOWN229,
    #[doc(hidden)]
    UNKNOWN230,
    #[doc(hidden)]
    UNKNOWN231,
    #[doc(hidden)]
    UNKNOWN232,
    #[doc(hidden)]
    UNKNOWN233,
    #[doc(hidden)]
    UNKNOWN234,
    #[doc(hidden)]
    UNKNOWN235,
    #[doc(hidden)]
    UNKNOWN236,
    #[doc(hidden)]
    UNKNOWN237,
    #[doc(hidden)]
    UNKNOWN238,
    #[doc(hidden)]
    UNKNOWN239,
    #[doc(hidden)]
    UNKNOWN240,
    #[doc(hidden)]
    UNKNOWN241,
    #[doc(hidden)]
    UNKNOWN242,
    #[doc(hidden)]
    UNKNOWN243,
    #[doc(hidden)]
    UNKNOWN244,
    #[doc(hidden)]
    UNKNOWN245,
    #[doc(hidden)]
    UNKNOWN246,
    #[doc(hidden)]
    UNKNOWN247,
    #[doc(hidden)]
    UNKNOWN248,
    #[doc(hidden)]
    UNKNOWN249,
    #[doc(hidden)]
    UNKNOWN250,
    #[doc(hidden)]
    UNKNOWN251,
    #[doc(hidden)]
    UNKNOWN252,
    #[doc(hidden)]
    UNKNOWN253,
    #[doc(hidden)]
    UNKNOWN254,
    #[doc(hidden)]
    UNKNOWN255,
}

impl From<u8> for CovenantType {
    fn from(u: u8) -> Self {
        match u {
            0x00 => CovenantType::NONE,
            0x01 => CovenantType::CLAIM,
            0x02 => CovenantType::OPEN,
            0x03 => CovenantType::BID,
            0x04 => CovenantType::REVEAL,
            0x05 => CovenantType::REDEEM,
            0x06 => CovenantType::REGISTER,
            0x07 => CovenantType::UPDATE,
            0x08 => CovenantType::RENEW,
            0x09 => CovenantType::TRANSFER,
            0x0a => CovenantType::FINALIZE,
            0x0b => CovenantType::REVOKE,
            0x0c => CovenantType::UNKNOWN12,
            0x0d => CovenantType::UNKNOWN13,
            0x0e => CovenantType::UNKNOWN14,
            0x0f => CovenantType::UNKNOWN15,
            0x10 => CovenantType::UNKNOWN16,
            0x11 => CovenantType::UNKNOWN17,
            0x12 => CovenantType::UNKNOWN18,
            0x13 => CovenantType::UNKNOWN19,
            0x14 => CovenantType::UNKNOWN20,
            0x15 => CovenantType::UNKNOWN21,
            0x16 => CovenantType::UNKNOWN22,
            0x17 => CovenantType::UNKNOWN23,
            0x18 => CovenantType::UNKNOWN24,
            0x19 => CovenantType::UNKNOWN25,
            0x1a => CovenantType::UNKNOWN26,
            0x1b => CovenantType::UNKNOWN27,
            0x1c => CovenantType::UNKNOWN28,
            0x1d => CovenantType::UNKNOWN29,
            0x1e => CovenantType::UNKNOWN30,
            0x1f => CovenantType::UNKNOWN31,
            0x20 => CovenantType::UNKNOWN32,
            0x21 => CovenantType::UNKNOWN33,
            0x22 => CovenantType::UNKNOWN34,
            0x23 => CovenantType::UNKNOWN35,
            0x24 => CovenantType::UNKNOWN36,
            0x25 => CovenantType::UNKNOWN37,
            0x26 => CovenantType::UNKNOWN38,
            0x27 => CovenantType::UNKNOWN39,
            0x28 => CovenantType::UNKNOWN40,
            0x29 => CovenantType::UNKNOWN41,
            0x2a => CovenantType::UNKNOWN42,
            0x2b => CovenantType::UNKNOWN43,
            0x2c => CovenantType::UNKNOWN44,
            0x2d => CovenantType::UNKNOWN45,
            0x2e => CovenantType::UNKNOWN46,
            0x2f => CovenantType::UNKNOWN47,
            0x30 => CovenantType::UNKNOWN48,
            0x31 => CovenantType::UNKNOWN49,
            0x32 => CovenantType::UNKNOWN50,
            0x33 => CovenantType::UNKNOWN51,
            0x34 => CovenantType::UNKNOWN52,
            0x35 => CovenantType::UNKNOWN53,
            0x36 => CovenantType::UNKNOWN54,
            0x37 => CovenantType::UNKNOWN55,
            0x38 => CovenantType::UNKNOWN56,
            0x39 => CovenantType::UNKNOWN57,
            0x3a => CovenantType::UNKNOWN58,
            0x3b => CovenantType::UNKNOWN59,
            0x3c => CovenantType::UNKNOWN60,
            0x3d => CovenantType::UNKNOWN61,
            0x3e => CovenantType::UNKNOWN62,
            0x3f => CovenantType::UNKNOWN63,
            0x40 => CovenantType::UNKNOWN64,
            0x41 => CovenantType::UNKNOWN65,
            0x42 => CovenantType::UNKNOWN66,
            0x43 => CovenantType::UNKNOWN67,
            0x44 => CovenantType::UNKNOWN68,
            0x45 => CovenantType::UNKNOWN69,
            0x46 => CovenantType::UNKNOWN70,
            0x47 => CovenantType::UNKNOWN71,
            0x48 => CovenantType::UNKNOWN72,
            0x49 => CovenantType::UNKNOWN73,
            0x4a => CovenantType::UNKNOWN74,
            0x4b => CovenantType::UNKNOWN75,
            0x4c => CovenantType::UNKNOWN76,
            0x4d => CovenantType::UNKNOWN77,
            0x4e => CovenantType::UNKNOWN78,
            0x4f => CovenantType::UNKNOWN79,
            0x50 => CovenantType::UNKNOWN80,
            0x51 => CovenantType::UNKNOWN81,
            0x52 => CovenantType::UNKNOWN82,
            0x53 => CovenantType::UNKNOWN83,
            0x54 => CovenantType::UNKNOWN84,
            0x55 => CovenantType::UNKNOWN85,
            0x56 => CovenantType::UNKNOWN86,
            0x57 => CovenantType::UNKNOWN87,
            0x58 => CovenantType::UNKNOWN88,
            0x59 => CovenantType::UNKNOWN89,
            0x5a => CovenantType::UNKNOWN90,
            0x5b => CovenantType::UNKNOWN91,
            0x5c => CovenantType::UNKNOWN92,
            0x5d => CovenantType::UNKNOWN93,
            0x5e => CovenantType::UNKNOWN94,
            0x5f => CovenantType::UNKNOWN95,
            0x60 => CovenantType::UNKNOWN96,
            0x61 => CovenantType::UNKNOWN97,
            0x62 => CovenantType::UNKNOWN98,
            0x63 => CovenantType::UNKNOWN99,
            0x64 => CovenantType::UNKNOWN100,
            0x65 => CovenantType::UNKNOWN101,
            0x66 => CovenantType::UNKNOWN102,
            0x67 => CovenantType::UNKNOWN103,
            0x68 => CovenantType::UNKNOWN104,
            0x69 => CovenantType::UNKNOWN105,
            0x6a => CovenantType::UNKNOWN106,
            0x6b => CovenantType::UNKNOWN107,
            0x6c => CovenantType::UNKNOWN108,
            0x6d => CovenantType::UNKNOWN109,
            0x6e => CovenantType::UNKNOWN110,
            0x6f => CovenantType::UNKNOWN111,
            0x70 => CovenantType::UNKNOWN112,
            0x71 => CovenantType::UNKNOWN113,
            0x72 => CovenantType::UNKNOWN114,
            0x73 => CovenantType::UNKNOWN115,
            0x74 => CovenantType::UNKNOWN116,
            0x75 => CovenantType::UNKNOWN117,
            0x76 => CovenantType::UNKNOWN118,
            0x77 => CovenantType::UNKNOWN119,
            0x78 => CovenantType::UNKNOWN120,
            0x79 => CovenantType::UNKNOWN121,
            0x7a => CovenantType::UNKNOWN122,
            0x7b => CovenantType::UNKNOWN123,
            0x7c => CovenantType::UNKNOWN124,
            0x7d => CovenantType::UNKNOWN125,
            0x7e => CovenantType::UNKNOWN126,
            0x7f => CovenantType::UNKNOWN127,
            0x80 => CovenantType::UNKNOWN128,
            0x81 => CovenantType::UNKNOWN129,
            0x82 => CovenantType::UNKNOWN130,
            0x83 => CovenantType::UNKNOWN131,
            0x84 => CovenantType::UNKNOWN132,
            0x85 => CovenantType::UNKNOWN133,
            0x86 => CovenantType::UNKNOWN134,
            0x87 => CovenantType::UNKNOWN135,
            0x88 => CovenantType::UNKNOWN136,
            0x89 => CovenantType::UNKNOWN137,
            0x8a => CovenantType::UNKNOWN138,
            0x8b => CovenantType::UNKNOWN139,
            0x8c => CovenantType::UNKNOWN140,
            0x8d => CovenantType::UNKNOWN141,
            0x8e => CovenantType::UNKNOWN142,
            0x8f => CovenantType::UNKNOWN143,
            0x90 => CovenantType::UNKNOWN144,
            0x91 => CovenantType::UNKNOWN145,
            0x92 => CovenantType::UNKNOWN146,
            0x93 => CovenantType::UNKNOWN147,
            0x94 => CovenantType::UNKNOWN148,
            0x95 => CovenantType::UNKNOWN149,
            0x96 => CovenantType::UNKNOWN150,
            0x97 => CovenantType::UNKNOWN151,
            0x98 => CovenantType::UNKNOWN152,
            0x99 => CovenantType::UNKNOWN153,
            0x9a => CovenantType::UNKNOWN154,
            0x9b => CovenantType::UNKNOWN155,
            0x9c => CovenantType::UNKNOWN156,
            0x9d => CovenantType::UNKNOWN157,
            0x9e => CovenantType::UNKNOWN158,
            0x9f => CovenantType::UNKNOWN159,
            0xa0 => CovenantType::UNKNOWN160,
            0xa1 => CovenantType::UNKNOWN161,
            0xa2 => CovenantType::UNKNOWN162,
            0xa3 => CovenantType::UNKNOWN163,
            0xa4 => CovenantType::UNKNOWN164,
            0xa5 => CovenantType::UNKNOWN165,
            0xa6 => CovenantType::UNKNOWN166,
            0xa7 => CovenantType::UNKNOWN167,
            0xa8 => CovenantType::UNKNOWN168,
            0xa9 => CovenantType::UNKNOWN169,
            0xaa => CovenantType::UNKNOWN170,
            0xab => CovenantType::UNKNOWN171,
            0xac => CovenantType::UNKNOWN172,
            0xad => CovenantType::UNKNOWN173,
            0xae => CovenantType::UNKNOWN174,
            0xaf => CovenantType::UNKNOWN175,
            0xb0 => CovenantType::UNKNOWN176,
            0xb1 => CovenantType::UNKNOWN177,
            0xb2 => CovenantType::UNKNOWN178,
            0xb3 => CovenantType::UNKNOWN179,
            0xb4 => CovenantType::UNKNOWN180,
            0xb5 => CovenantType::UNKNOWN181,
            0xb6 => CovenantType::UNKNOWN182,
            0xb7 => CovenantType::UNKNOWN183,
            0xb8 => CovenantType::UNKNOWN184,
            0xb9 => CovenantType::UNKNOWN185,
            0xba => CovenantType::UNKNOWN186,
            0xbb => CovenantType::UNKNOWN187,
            0xbc => CovenantType::UNKNOWN188,
            0xbd => CovenantType::UNKNOWN189,
            0xbe => CovenantType::UNKNOWN190,
            0xbf => CovenantType::UNKNOWN191,
            0xc0 => CovenantType::UNKNOWN192,
            0xc1 => CovenantType::UNKNOWN193,
            0xc2 => CovenantType::UNKNOWN194,
            0xc3 => CovenantType::UNKNOWN195,
            0xc4 => CovenantType::UNKNOWN196,
            0xc5 => CovenantType::UNKNOWN197,
            0xc6 => CovenantType::UNKNOWN198,
            0xc7 => CovenantType::UNKNOWN199,
            0xc8 => CovenantType::UNKNOWN200,
            0xc9 => CovenantType::UNKNOWN201,
            0xca => CovenantType::UNKNOWN202,
            0xcb => CovenantType::UNKNOWN203,
            0xcc => CovenantType::UNKNOWN204,
            0xcd => CovenantType::UNKNOWN205,
            0xce => CovenantType::UNKNOWN206,
            0xcf => CovenantType::UNKNOWN207,
            0xd0 => CovenantType::UNKNOWN208,
            0xd1 => CovenantType::UNKNOWN209,
            0xd2 => CovenantType::UNKNOWN200,
            0xd3 => CovenantType::UNKNOWN211,
            0xd4 => CovenantType::UNKNOWN212,
            0xd5 => CovenantType::UNKNOWN213,
            0xd6 => CovenantType::UNKNOWN214,
            0xd7 => CovenantType::UNKNOWN215,
            0xd8 => CovenantType::UNKNOWN216,
            0xd9 => CovenantType::UNKNOWN217,
            0xda => CovenantType::UNKNOWN218,
            0xdb => CovenantType::UNKNOWN219,
            0xdc => CovenantType::UNKNOWN220,
            0xdd => CovenantType::UNKNOWN221,
            0xde => CovenantType::UNKNOWN222,
            0xdf => CovenantType::UNKNOWN223,
            0xe0 => CovenantType::UNKNOWN224,
            0xe1 => CovenantType::UNKNOWN225,
            0xe2 => CovenantType::UNKNOWN226,
            0xe3 => CovenantType::UNKNOWN227,
            0xe4 => CovenantType::UNKNOWN228,
            0xe5 => CovenantType::UNKNOWN229,
            0xe6 => CovenantType::UNKNOWN230,
            0xe7 => CovenantType::UNKNOWN231,
            0xe8 => CovenantType::UNKNOWN232,
            0xe9 => CovenantType::UNKNOWN233,
            0xea => CovenantType::UNKNOWN234,
            0xeb => CovenantType::UNKNOWN235,
            0xec => CovenantType::UNKNOWN236,
            0xed => CovenantType::UNKNOWN237,
            0xee => CovenantType::UNKNOWN238,
            0xef => CovenantType::UNKNOWN239,
            0xf0 => CovenantType::UNKNOWN240,
            0xf1 => CovenantType::UNKNOWN241,
            0xf2 => CovenantType::UNKNOWN242,
            0xf3 => CovenantType::UNKNOWN243,
            0xf4 => CovenantType::UNKNOWN244,
            0xf5 => CovenantType::UNKNOWN245,
            0xf6 => CovenantType::UNKNOWN246,
            0xf7 => CovenantType::UNKNOWN247,
            0xf8 => CovenantType::UNKNOWN248,
            0xf9 => CovenantType::UNKNOWN249,
            0xfa => CovenantType::UNKNOWN250,
            0xfb => CovenantType::UNKNOWN251,
            0xfc => CovenantType::UNKNOWN252,
            0xfd => CovenantType::UNKNOWN253,
            0xfe => CovenantType::UNKNOWN254,
            0xff => CovenantType::UNKNOWN255,
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
            (CovenantType::CLAIM, vec![], "0100"),
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
                covenant_type: i.into(),
                covenant_data: CovenantData::null(),
            };

            let hex = covenant.serialize_hex();
            let got = Covenant::deserialize_hex(&hex).unwrap();

            assert_eq!(covenant, got);
        }
    }
}
