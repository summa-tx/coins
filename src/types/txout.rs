use std::io::{Read, Write, Result as IOResult};

use crate::types::primitives::{Script, Ser, PrefixVec};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxOut{
    pub value: u64,
    pub script_pubkey: Script
}

impl TxOut{
    pub fn new<T>(value: u64, script_pubkey: T) -> Self
    where
        T: Into<Script>
    {
        TxOut{
            value,
            script_pubkey: script_pubkey.into()
        }
    }

    pub fn null() -> Self {
        TxOut{
            value: 0xffff_ffff_ffff_ffff,
            script_pubkey: Script::null()
        }
    }
}

impl Ser for TxOut {
    fn serialized_length(&self) -> IOResult<usize> {
        let mut len = self.value.serialized_length()?;
        len += self.script_pubkey.serialized_length()?;
        Ok(len)
    }

    fn deserialize<T>(reader: &mut T, _limit: usize) -> IOResult<Self>
    where
        T: Read,
        Self: std::marker::Sized
    {
        let value = u64::deserialize(reader, 0)?;
        Ok(TxOut{
            value,
            script_pubkey: Script::deserialize(reader, 0)?
        })
    }

    fn serialize<T>(&self, writer: &mut T) -> IOResult<usize>
    where
        T: Write
    {
        let mut len = self.value.serialize(writer)?;
        len += self.script_pubkey.serialize(writer)?;
        Ok(len)
    }
}

pub type Vout = PrefixVec<TxOut>;


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_serializes_and_derializes_outputs() {
        let cases = [
            (TxOut::new(0, ""), "000000000000000000", 9),
            (TxOut::null(), "ffffffffffffffff00", 9)
        ];
        for case in cases.iter() {
            assert_eq!(case.0.serialized_length().unwrap(), case.2);
            assert_eq!(case.0.serialize_hex().unwrap(), case.1.to_owned());
            assert_eq!(TxOut::deserialize_hex(case.1.to_owned()).unwrap(), case.0);
        }
    }
}
