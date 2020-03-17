use serde::{Serialize, Deserialize};
use bitcoin_spv::{types};

use crate::tx::format::{Serializable};
use crate::tx::primitives::{
    VarInt, hash256_ser
};


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Outpoint{
    #[serde(with = "hash256_ser")]
    pub txid: types::Hash256Digest,
    pub idx: u32
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Script {
    pub length: VarInt,
    pub body: Vec<u8>
}

impl Script {
    pub fn new(script: Vec<u8>) -> Self {
        Script{
            length: VarInt::new(script.len() as u64),
            body: script
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxIn{
    pub outpoint: Outpoint,
    pub script_sig: Script,
    pub sequence: u32
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOut{
    pub value: u64,
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
    pub version: u32,
    pub flag: Option<[u8; 2]>,
    pub vin: Vin,
    pub vout: Vout,
    pub witnesses: Vec<Witness>,
    pub locktime: u32
}

// TODO: Derive these
impl Serializable for Outpoint {}
impl Serializable for Script {}
impl Serializable for TxIn {}
impl Serializable for TxOut {}
impl Serializable for Witness {}
impl Serializable for Vin {}
impl Serializable for Vout {}
impl Serializable for TX {}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_assembles() {
        let numbers: Vec<u8> = (0u8..32u8).collect();
        let mut prevout_txid = [0u8; 32];
        prevout_txid.copy_from_slice(&numbers);
        let outpoint = Outpoint{
            txid: prevout_txid,
            idx: 0xaabbccddu32
        };
        let ss = Script::new(vec![0, 1, 2, 3, 4]);
        let txin = TxIn{
            outpoint: outpoint,
            script_sig: ss,
            sequence: 0x33883388u32
        };
        let vin = Vin::new(vec![txin]);
        let spk = Script{
            length: VarInt::new(0x16),
            body: vec![0x00, 0x14, 0x11, 0x00, 0x33, 0x00, 0x55, 0x00, 0x77, 0x00, 0x99, 0x00, 0xbb, 0x00, 0xdd, 0x00, 0xff, 0x11, 0x00, 0x33, 0x00, 0x55]
        };
        let txout = TxOut{
            value: 888u64,
            script_pubkey: spk
        };
        let vout = Vout::new(vec![txout]);

        let tx = TX{
            version: 0x2u32,
            flag: Some([0x00, 0x01]),
            vin: vin,
            vout: vout,
            witnesses: vec![],
            locktime: 0x44332211u32
        };
        print!("{:?}", tx.to_hex());
    }
}
