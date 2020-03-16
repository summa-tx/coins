use serde::{de, ser, Serialize, Deserialize, Serializer, Deserializer};
use bitcoin_spv::utils;

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
        let s: &str = Deserialize::deserialize(deserializer)?;
        let bytes = utils::deserialize_hex(s).map_err(de::Error::custom)?;

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
