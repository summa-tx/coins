use bitcoin_spv::types::Hash256Digest;
use std::io::{Read, Write, Result as IOResult};

use crate::types::primitives::{Script, Ser, PrefixVec};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Outpoint{
    pub txid: Hash256Digest,
    pub idx: u32
}

impl Outpoint {
    pub fn null() -> Self {
        Outpoint{
            txid: Hash256Digest::default(),
            idx: 0xffff_ffff
        }
    }
}

impl Ser for Outpoint {
    fn serialized_length(&self) -> IOResult<usize> {
        Ok(36)
    }

    fn deserialize<T>(reader: &mut T, _limit: usize) -> IOResult<Self>
    where
        T: Read,
        Self: std::marker::Sized
    {
        Ok(Outpoint{
            txid: Hash256Digest::deserialize(reader, 0)?,
            idx: u32::deserialize(reader, 0)?
        })
    }

    fn serialize<T>(&self, writer: &mut T) -> IOResult<usize>
    where
        T: Write
    {
        let mut len = self.txid.serialize(writer)?;
        len += self.idx.serialize(writer)?;
        Ok(len)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxIn{
    pub outpoint: Outpoint,
    pub script_sig: Script,
    pub sequence: u32
}

impl TxIn{
    pub fn new<T>(outpoint: Outpoint, script_sig: T, sequence: u32) -> Self
    where
        T: Into<Script>
    {
        TxIn{
            outpoint,
            script_sig: script_sig.into(),
            sequence
        }
    }
}

impl Ser for TxIn {
    fn serialized_length(&self) -> IOResult<usize> {
        let mut len = self.outpoint.serialized_length()?;
        len += self.script_sig.serialized_length()?;
        len += self.sequence.serialized_length()?;
        Ok(len)
    }

    fn deserialize<T>(reader: &mut T, _limit: usize) -> IOResult<Self>
    where
        T: Read,
        Self: std::marker::Sized
    {
        Ok(TxIn{
            outpoint: Outpoint::deserialize(reader, 0)?,
            script_sig: Script::deserialize(reader, 0)?,
            sequence: u32::deserialize(reader, 0)?
        })
    }

    fn serialize<T>(&self, writer: &mut T) -> IOResult<usize>
    where
        T: Write
    {
        let mut len = self.outpoint.serialize(writer)?;
        len += self.script_sig.serialize(writer)?;
        len += self.sequence.serialize(writer)?;
        Ok(len)
    }
}

pub type Vin = PrefixVec<TxIn>;

// #[derive(Clone, Debug, Eq, PartialEq)]
// pub struct Vin{
//     pub length: VarInt,
//     pub inputs: Vec<TxIn>
// }
// impl Vin {
//     pub fn len(&self) -> usize {
//         self.length.0 as usize
//     }
//
//     pub fn is_empty(&self) -> bool {
//         self.len() == 0
//     }
//
//     pub fn new(inputs: Vec<TxIn>) -> Self {
//         Vin{
//             length: VarInt::new(inputs.len() as u64),
//             inputs
//         }
//     }
// }
//
// impl Ser for Vin {
//     fn serialized_length(&self) -> IOResult<usize> {
//         let mut len = self.length.serialized_length()?;
//         len += self.inputs.serialized_length()?;
//         Ok(len)
//     }
//
//     fn deserialize<T>(reader: &mut T, _limit: usize) -> IOResult<Self>
//     where
//         T: Read,
//         Self: std::marker::Sized
//     {
//         let length = VarInt::deserialize(reader, 0)?;
//         let limit = length.0;
//         Ok(Vin{
//             length,
//             inputs: Vec::<TxIn>::deserialize(reader, limit as usize)?
//         })
//     }
//
//     fn serialize<T>(&self, writer: &mut T) -> IOResult<usize>
//     where
//         T: Write
//     {
//         let mut len = self.length.serialize(writer)?;
//         len += self.inputs.serialize(writer)?;
//         Ok(len)
//     }
// }

#[cfg(test)]
mod test {
    use super::*;
    use crate::types::*;

    static NULL_OUTPOINT: &str = "0000000000000000000000000000000000000000000000000000000000000000ffffffff";

    #[test]
    fn it_serializes_and_derializes_outpoints() {
        let cases = [
        (Outpoint{txid: Hash256Digest::default(), idx: 0}, (0..36).map(|_| "00").collect::<String>()),
        (Outpoint::null(), NULL_OUTPOINT.to_string())
        ];
        for case in cases.iter() {
            assert_eq!(case.0.serialized_length().unwrap(), case.1.len() / 2);
            assert_eq!(case.0.serialize_hex().unwrap(), case.1.to_owned());
            assert_eq!(Outpoint::deserialize_hex(case.1.to_owned()).unwrap(), case.0);
        }
    }

    #[test]
    fn it_serializes_and_derializes_scripts() {
        let cases = [
        (Script::new(vec![0xaa, 0xbb, 0xcc, 0xdd]), "04aabbccdd"),
        (Script::new(vec![1u8; 256]), &format!("fd0001{}", (0..256).map(|_| "01").collect::<String>())),
        (
            Script::new(
                vec![0x00, 0x14, 0x11, 0x00, 0x33, 0x00, 0x55, 0x00, 0x77, 0x00, 0x99, 0x00, 0xbb, 0x00, 0xdd, 0x00, 0xff, 0x11, 0x00, 0x33, 0x00, 0x55]
            ),
            "16001411003300550077009900bb00dd00ff1100330055"
        ),
        (
            Script{
                length: VarInt(0x16, 3),
                items: vec![0x00, 0x14, 0x11, 0x00, 0x33, 0x00, 0x55, 0x00, 0x77, 0x00, 0x99, 0x00, 0xbb, 0x00, 0xdd, 0x00, 0xff, 0x11, 0x00, 0x33, 0x00, 0x55]
            },
            "fd1600001411003300550077009900bb00dd00ff1100330055"
        ),
        ];

        for case in cases.iter() {
            assert_eq!(case.0.serialized_length().unwrap(), case.1.len() / 2);
            assert_eq!(case.0.serialize_hex().unwrap(), case.1.to_owned());
            assert_eq!(Script::deserialize_hex(case.1.to_owned()).unwrap(), case.0);
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
                    script_sig: Script{
                        length: VarInt(0x16, 3),
                        items: vec![0x00, 0x14, 0x11, 0x00, 0x33, 0x00, 0x55, 0x00, 0x77, 0x00, 0x99, 0x00, 0xbb, 0x00, 0xdd, 0x00, 0xff, 0x11, 0x00, 0x33, 0x00, 0x55]
                    },
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
            assert_eq!(case.0.serialized_length().unwrap(), case.1.len() / 2);
            assert_eq!(case.0.serialize_hex().unwrap(), case.1.to_owned());
            assert_eq!(TxIn::deserialize_hex(case.1.to_owned()).unwrap(), case.0);
        }
    }
}
