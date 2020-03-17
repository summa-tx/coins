use bitcoin_spv::{types};

use serde::{de, ser};
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};


#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct LEU32(u32);

impl LEU32 {
    pub fn new(number: u32) -> Self{
        LEU32(number)
    }
}

impl Serialize for LEU32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer,
    {
        serializer.serialize_bytes(&self.0.to_le_bytes())
    }
}

impl<'de> Deserialize<'de> for LEU32 {
    fn deserialize<D>(deserializer: D) -> Result<LEU32, D::Error>
    where
        D: Deserializer<'de>
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.is_empty() || bytes.len() != 4 {
            return Err(de::Error::custom("Bad bytestring in LEU32 deser"));
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes);
        Ok(LEU32(u32::from_le_bytes(buf)))
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct LEU64(u64);

impl LEU64 {
    pub fn new(number: u64) -> Self{
        LEU64(number)
    }
}

impl Serialize for LEU64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer,
    {
        serializer.serialize_bytes(&self.0.to_le_bytes())
    }
}

impl<'de> Deserialize<'de> for LEU64 {
    fn deserialize<D>(deserializer: D) -> Result<LEU64, D::Error>
    where
        D: Deserializer<'de>
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.is_empty() || bytes.len() != 8 {
            return Err(de::Error::custom("Bad bytestring in LEU64 deser"));
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes);
        Ok(LEU64(u64::from_le_bytes(buf)))
    }
}

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
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;

        let expected_len = VarInt::len_from_prefix(bytes[0]);

        if bytes.is_empty() || expected_len > bytes.len() {
            return Err(de::Error::custom("Null bytestring in VarInt deser"));
        }

        match bytes[0] {
            0..=0xfc => Ok(VarInt(bytes[0] as u64, 1)),
            _ => {
                let mut total = 0u64;
                for (i, b) in bytes[1..expected_len].iter().enumerate() {
                    total += (*b as u64) << i;
                };
                Ok(VarInt(total, expected_len as u8))
            }
        }
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
        let deser: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if deser.len() != 32 {
            let err_string: String = format!("Expected 32 bytes, got {:?} bytes", deser.len());
            return Err(serde::de::Error::custom(err_string));
        }

        let mut digest: types::Hash256Digest = Default::default();
        digest.copy_from_slice(&deser);
        Ok(digest)
    }
}
