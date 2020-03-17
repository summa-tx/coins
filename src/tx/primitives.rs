use bitcoin_spv::{types};
use serde::de::{Deserialize, Deserializer};
use serde::ser::{self, Serialize, Serializer};

use crate::tx::format::{VarIntVisitor};

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct VarInt(pub u64, pub u8);   // number and byte-length

impl VarInt {
    pub fn new(number: u64) -> Self {
        let byte_len = VarInt::byte_len(number);
        VarInt(number, byte_len)
    }

    pub fn byte_len(number: u64) -> u8 {
        match number {
            0..=0xfc => 1,
            0xfd..=0xffff => 3,
            0x10000..=0xffff_ffff => 5,
            _ => 9
        }
    }

    pub fn len_from_prefix(number: u8) -> usize {
        match number {
            0..=0xfc => 1,
            0xfd => 3,
            0xfe => 5,
            0xff => 9
        }
    }
}

impl Serialize for VarInt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer,
    {
        let mut buf = [0u8; 9];
        buf[0] = match self.1 {
            1 => self.0 as u8,
            3 => 0xfd,
            5 => 0xfe,
            9 => 0xff,
            _ => return Err(ser::Error::custom("Bad VarInt in ser"))
        };
        buf[1..].copy_from_slice(&self.0.to_le_bytes());
        serializer.serialize_bytes(&buf[..self.1 as usize])
    }
}

impl<'de> Deserialize<'de> for VarInt {
    fn deserialize<D>(deserializer: D) -> Result<VarInt, D::Error>
    where
        D: Deserializer<'de>
    {
        Ok(deserializer.deserialize_bytes(VarIntVisitor)?)
    }
}

pub mod hash256_ser {
    use super::*;

    pub fn serialize<S>(d: &types::Hash256Digest, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(d)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<types::Hash256Digest, D::Error>
    where
        D: Deserializer<'de>,
    {
        let deser: [u8; 32] = Deserialize::deserialize(deserializer)?;
        let mut digest: types::Hash256Digest = Default::default();
        digest.copy_from_slice(&deser);
        Ok(digest)
    }
}

pub mod prefixed_vec_ser {

}
