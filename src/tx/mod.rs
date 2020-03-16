use serde::{de, ser, Serialize, Deserialize, Serializer, Deserializer};
use bitcoin_spv::utils;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct VarInt(pub u64, pub u8);   // number and byte-length


impl VarInt {
    pub fn new(number: u64) -> Self {
        let byte_len = match number {
            0..=0xfc => 1,
            0xfd..=0xffff => 3,
            0x10000..=0xffffff => 5,
            _ => 9
        };
        VarInt(number, byte_len)
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
        let result = utils::deserialize_hex(s).map_err(|v| de::Error::custom(v))?;
        match (result.get(0), result.len()) {
            (None, _) => Err(de::Error::custom("Null bytestring in VarInt deser")),
            (Some(0..=0xfc), 1) => Ok(VarInt(result[0] as u64, 1)),
            (Some(0xfd), 3) => {
                let num: u64 =
                    result[1] as u64
                    + (result[2] as u64) << 1;
                Ok(VarInt(num, 3))
            },
            (Some(0xfe), 5) => {
                let num: u64 =
                    result[1] as u64
                    + (result[2] as u64) << 1
                    + (result[3] as u64) << 2
                    + (result[4] as u64) << 3;
                Ok(VarInt(num, 5))
            },
            (Some(0xff), 9) => {
                let num: u64 =
                    result[1] as u64
                    + (result[2] as u64) << 1
                    + (result[3] as u64) << 2
                    + (result[4] as u64) << 3
                    + (result[5] as u64) << 4
                    + (result[6] as u64) << 5
                    + (result[7] as u64) << 6
                    + (result[8] as u64) << 7;
                Ok(VarInt(num, 9))
            },
            _ => Err(de::Error::custom("Unknown Error in VarInt deser"))
        }
    }
}
