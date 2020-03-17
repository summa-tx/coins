use std::fmt;
use serde::de::{self, Visitor};

use crate::tx::VarInt;

pub struct VarIntVisitor;

impl<'de> Visitor<'de> for VarIntVisitor {
    type Value = VarInt;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a bitcoin VarInt")
    }

    fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error
    {
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
