use std::io::{Read, Write, Result as IOResult};

use crate::types::primitives::{Script, Ser, VarInt};

/// Alias for Script, as both are opaque byte vectors
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

    pub fn len(&self) -> usize {
        self.stack_items.0 as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_serializes_and_derializes_witnesses() {
        let cases = [
            (
                Witness::new(vec![
                    WitnessStackItem::deserialize_hex("".to_owned()).unwrap(),
                    WitnessStackItem::deserialize_hex("304402201b1c2fc7d58870004c379575a47db60c3833174033f891ad5030cbf0c37c50c302206087d3ddc6f38da40e7eaf8c2af3f934a577de10e6ca75e00b4cdfbb34f5d40601".to_owned()).unwrap(),
                    WitnessStackItem::deserialize_hex("3045022100a7ecde342ccacd1159e385bcd41c947723a7ae3fcea66c76b5b09d02fee310f7022058ca21324fcd0c90e69630f13975d993e11f62ec8d7aa1a9a49036b9607e58fe01".to_owned()).unwrap(),
                    WitnessStackItem::deserialize_hex("52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae".to_owned()).unwrap(),
                ]),
                "040047304402201b1c2fc7d58870004c379575a47db60c3833174033f891ad5030cbf0c37c50c302206087d3ddc6f38da40e7eaf8c2af3f934a577de10e6ca75e00b4cdfbb34f5d40601483045022100a7ecde342ccacd1159e385bcd41c947723a7ae3fcea66c76b5b09d02fee310f7022058ca21324fcd0c90e69630f13975d993e11f62ec8d7aa1a9a49036b9607e58fe016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae",
                253
            ),
        ];
        for case in cases.iter() {
            let witness = Witness::deserialize_hex(case.1.to_owned()).unwrap();
            assert_eq!(witness, case.0);
            assert_eq!(witness.serialize_hex().unwrap(), case.1);
            assert_eq!(witness.len(), case.2);
            assert_eq!(witness.is_empty(), case.2 == 0);

            assert_eq!(case.0.serialize_hex().unwrap(), case.1);
            assert_eq!(case.0.len(), case.2);
            assert_eq!(case.0.is_empty(), case.2 == 0);
        }
    }
}
