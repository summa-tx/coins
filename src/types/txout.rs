use std::io::{Read, Write, Result as IOResult};

use crate::types::primitives::{Script, Ser, VarInt};

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Vout{
    pub length: VarInt,
    pub outputs: Vec<TxOut>
}

impl Ser for Vout {
    fn serialized_length(&self) -> IOResult<usize> {
        let mut len = self.length.serialized_length()?;
        len += self.outputs.serialized_length()?;
        Ok(len)
    }

    fn deserialize<T>(reader: &mut T, _limit: usize) -> IOResult<Self>
    where
        T: Read,
        Self: std::marker::Sized
    {
        let length = VarInt::deserialize(reader, 0)?;
        let limit = length.0;
        Ok(Vout{
            length,
            outputs: Vec::<TxOut>::deserialize(reader, limit as usize)?
        })
    }

    fn serialize<T>(&self, writer: &mut T) -> IOResult<usize>
    where
        T: Write
    {
        let mut len = self.length.serialize(writer)?;
        len += self.outputs.serialize(writer)?;
        Ok(len)
    }
}

impl Vout {
    pub fn len(&self) -> usize {
        self.length.0 as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    
    pub fn new(outputs: Vec<TxOut>) -> Self {
        Vout{
            length: VarInt::new(outputs.len() as u64),
            outputs
        }
    }
}
