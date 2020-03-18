use std::io::{Read, Write, Result as IOResult};

use crate::types::primitives::{Script, Ser, VarInt};

pub type WitnessStackItem = Script;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Witness{
    pub stack_items: VarInt,
    pub stack: Vec<WitnessStackItem>
}

impl Witness {
    pub fn new(stack: Vec<WitnessStackItem>) -> Self {
        Witness{
            stack_items: VarInt::new(stack.len() as u64),
            stack,
        }
    }

    pub fn null() -> Self {
        Witness::new(vec![])
    }
}

impl Ser for Witness {
    fn serialized_length(&self) -> IOResult<usize> {
        let mut len = self.stack_items.serialized_length()?;
        len += self.stack.serialized_length()?;
        Ok(len)
    }

    fn deserialize<T>(reader: &mut T, _limit: usize) -> IOResult<Self>
    where
        T: Read,
        Self: std::marker::Sized
    {
        let stack_items = VarInt::deserialize(reader, 0)?;
        let limit = stack_items.0;
        Ok(Witness{
            stack_items,
            stack: Vec::<WitnessStackItem>::deserialize(reader, limit as usize)?
        })
    }

    fn serialize<T>(&self, writer: &mut T) -> IOResult<usize>
    where
        T: Write
    {
        let mut len = self.stack_items.serialize(writer)?;
        len += self.stack.serialize(writer)?;
        Ok(len)
    }
}
