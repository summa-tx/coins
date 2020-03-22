use super::primitives::{Script, PrefixVec};

/// Alias for Script, as both are opaque byte vectors
pub type WitnessStackItem = Script;

pub type Witness = PrefixVec<WitnessStackItem>;

#[cfg(test)]
mod test {
    use super::*;
    use crate::old_types::primitives::Ser;

    #[test]
    fn it_serializes_and_derializes_witnesses() {
        let cases = [
            (
                Witness::new(vec![
                    WitnessStackItem::null(),
                    WitnessStackItem::deserialize_hex("47304402201b1c2fc7d58870004c379575a47db60c3833174033f891ad5030cbf0c37c50c302206087d3ddc6f38da40e7eaf8c2af3f934a577de10e6ca75e00b4cdfbb34f5d40601".to_owned()).unwrap(),
                    WitnessStackItem::deserialize_hex("483045022100a7ecde342ccacd1159e385bcd41c947723a7ae3fcea66c76b5b09d02fee310f7022058ca21324fcd0c90e69630f13975d993e11f62ec8d7aa1a9a49036b9607e58fe01".to_owned()).unwrap(),
                    WitnessStackItem::deserialize_hex("6952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae".to_owned()).unwrap(),
                ]),
                "040047304402201b1c2fc7d58870004c379575a47db60c3833174033f891ad5030cbf0c37c50c302206087d3ddc6f38da40e7eaf8c2af3f934a577de10e6ca75e00b4cdfbb34f5d40601483045022100a7ecde342ccacd1159e385bcd41c947723a7ae3fcea66c76b5b09d02fee310f7022058ca21324fcd0c90e69630f13975d993e11f62ec8d7aa1a9a49036b9607e58fe016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae",
                4,
                253
            ),
            (
                Witness::null(),
                "00",
                0,
                1
            )
        ];
        for case in cases.iter() {
            let witness = Witness::deserialize_hex(case.1.to_owned()).unwrap();
            assert_eq!(witness, case.0);
            assert_eq!(witness.serialize_hex().unwrap(), case.1);
            assert_eq!(witness.len(), case.2);
            assert_eq!(witness.is_empty(), case.2 == 0);
            assert_eq!(witness.serialized_length().unwrap(), case.3);

            assert_eq!(case.0.serialize_hex().unwrap(), case.1);
            assert_eq!(case.0.len(), case.2);
            assert_eq!(case.0.is_empty(), case.2 == 0);
            assert_eq!(case.0.serialized_length().unwrap(), case.3);
        }
    }
}
