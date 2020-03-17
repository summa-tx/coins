use serde::{Serialize, Deserialize};
use bitcoin_spv::{types};

use crate::tx::primitives::{
    LEU32, LEU64, VarInt, hash256_ser
};


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Outpoint{
    #[serde(with = "hash256_ser")]
    pub txid: types::Hash256Digest,
    pub idx: LEU32
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Script {
    pub length: VarInt,
    pub body: Vec<u8>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxIn{
    pub outpoint: Outpoint,
    pub script_sig: Script,
    pub sequence: LEU32
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOut{
    pub value: LEU64,
    pub script_pubkey: Script
}

pub type WitnessStackItem = Script;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Witness{
    pub stack_items: VarInt,
    pub stack: Vec<WitnessStackItem>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vin{
    pub length: VarInt,
    pub inputs: Vec<TxIn>
}

impl Vin {
    pub fn new(inputs: Vec<TxIn>) -> Self {
        Vin{
            length: VarInt::new(inputs.len() as u64),
            inputs: inputs
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vout{
    pub length: VarInt,
    pub outputs: Vec<TxOut>
}

impl Vout {
    pub fn new(outputs: Vec<TxOut>) -> Self {
        Vout{
            length: VarInt::new(outputs.len() as u64),
            outputs: outputs
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TX{
    pub version: LEU32,
    pub flag: Option<[u8; 2]>,
    pub vin: Vin,
    pub vout: Vout,
    pub witnesses: Vec<Witness>,
    pub locktime: LEU32
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_assembles() {
        let prevout_txid = [0u8; 32];
        let outpoint = Outpoint{
            txid: prevout_txid,
            idx: LEU32::new(32u32)
        };
        let ss = Script{
            length: VarInt::new(0u64),
            body: vec![]
        };
        let txin = TxIn{
            outpoint: outpoint,
            script_sig: ss,
            sequence: LEU32::new(33u32)
        };
        let vin = Vin::new(vec![txin]);
        let spk = Script{
            length: VarInt::new(16),
            body: vec![0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        };
        let txout = TxOut{
            value: LEU64::new(888u64),
            script_pubkey: spk
        };
        let vout = Vout::new(vec![txout]);

        let tx = TX{
            version: LEU32::new(2),
            flag: Some([0x00, 0x01]),
            vin: vin,
            vout: vout,
            witnesses: vec![],
            locktime: LEU32::new(100)
        };
        print!("{:?}", &tx);
    }
}
