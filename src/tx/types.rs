use serde::{Serialize, Deserialize};
use bitcoin_spv::{types};

use crate::tx::primitives::{
    LEU32, LEU64, VarInt, hash256_ser
};


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Outpoint{
    #[serde(with = "hash256_ser")]
    pub txid: types::Hash256Digest,
    pub index: LEU32
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vout{
    pub length: VarInt,
    pub outputs: Vec<TxOut>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TX{
    pub version: LEU32,
    pub vin: Vin,
    pub vout: Vout,
    pub witnesses: Vec<Witness>,
    pub locktime: LEU32
}
