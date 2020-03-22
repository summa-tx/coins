use std::io::{Read, Write};
use bitcoin_spv::types::{Hash256Digest};

use crate::{
    hashes::{
        hash256::Hash256Writer,
        marked::{MarkedHash, TXID, WTXID},
    },
    types::{
        primitives::{Ser, TxError, TxResult, PrefixVec},
        txin::{TxIn, Vin},
        txout::{TxOut, Vout},
        script::{Witness},
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Sighash{
    None,
    All,
    Single
}

pub fn sighash_type_to_flag(t: Sighash, anyone_can_pay: bool) -> u8 {
    let mut flag = match t {
        Sighash::None => 0x02,
        Sighash::All => 0x01,
        Sighash::Single => 0x03,
    };
    if anyone_can_pay { flag |= 0x80 };
    flag
}

trait Transaction<'a>: Ser {
   type TxIn;
   type TxOut;
   // type SighashArgs;
   type TXID: MarkedHash<Hash256Digest>;

   fn inputs(&'a self) -> &'a[Self::TxIn];
   fn outputs(&'a self) -> &'a[Self::TxOut];
   fn version(&self) -> u32;
   fn locktime(&self) -> u32;

   fn txid(&self) -> Self::TXID;

   fn legacy_sighash(&self, /*args: &Self::SighashArgs*/) -> Hash256Digest;
}

trait WitnessTransaction<'a>: Transaction<'a> {
    type WTXID: MarkedHash<Hash256Digest>;
    // type WitnessSighashArgs;

    fn wtxid(&self) -> Self::WTXID;
    fn witness_sighash(&self, /* args: &Self::WitnessSighashArgs*/) -> Hash256Digest;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyTx {
    version: u32,
    vin: Vin,
    vout: Vout,
    locktime: u32
}

impl<'a> Transaction<'a> for LegacyTx {
    type TxIn = TxIn;
    type TxOut = TxOut;
    // type SighashArgs;
    type TXID = TXID;

    fn inputs(&'a self) -> &'a[Self::TxIn] {
        &self.vin.items()
    }

    fn outputs(&'a self) -> &'a[Self::TxOut] {
        &self.vout.items()
    }

    fn version(&self) -> u32 {
        self.version
    }

    fn locktime(&self) -> u32 {
        self.locktime
    }

    fn txid(&self) -> Self::TXID {
        let mut w = Hash256Writer::default();
        self.serialize(&mut w).expect("No IOError from SHA2");
        w.finish()
    }

    fn legacy_sighash(&self, /* args: &Self::SighashArgs */) -> Hash256Digest {
        unimplemented!()
    }
}

impl Ser for LegacyTx
{
    fn serialized_length(&self) -> usize {
        let mut len = self.version().serialized_length();
        len += self.vin.serialized_length();
        len += self.vout.serialized_length();
        len += self.locktime().serialized_length();
        len
    }

    fn deserialize<R>(reader: &mut R, _limit: usize) -> TxResult<Self>
    where
        R: Read,
        Self: std::marker::Sized
    {
        let version = u32::deserialize(reader, 0)?;
        let vin = Vin::deserialize(reader, 0)?;
        let vout = Vout::deserialize(reader, 0)?;
        let locktime = u32::deserialize(reader, 0)?;
        Ok(Self{
            version,
            vin,
            vout,
            locktime,
        })
    }

    fn serialize<T>(&self, writer: &mut T) -> TxResult<usize>
    where
        T: Write
    {
        let mut len = self.version().serialize(writer)?;
        len += self.vin.serialize(writer)?;
        len += self.vout.serialize(writer)?;
        len += self.locktime().serialize(writer)?;
        Ok(len)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessTx {
    version: u32,
    vin: Vin,
    vout: Vout,
    witnesses: Vec<Witness>,
    locktime: u32
}

impl<'a> Transaction<'a> for WitnessTx {
    type TxIn = TxIn;
    type TxOut = TxOut;
    // type SighashArgs;
    type TXID = TXID;

    fn inputs(&'a self) -> &'a[Self::TxIn] {
        &self.vin.items()
    }

    fn outputs(&'a self) -> &'a[Self::TxOut] {
        &self.vout.items()
    }

    fn version(&self) -> u32 {
        self.version
    }

    fn locktime(&self) -> u32 {
        self.locktime
    }

    fn txid(&self) -> Self::TXID {
        let mut w = Hash256Writer::default();
        self.version().serialize(&mut w).expect("No IOError from SHA2");
        self.vin.serialize(&mut w).expect("No IOError from SHA2");
        self.vout.serialize(&mut w).expect("No IOError from SHA2");
        self.locktime().serialize(&mut w).expect("No IOError from SHA2");
        w.finish()
    }

    fn legacy_sighash(&self, /* args: &Self::SighashArgs */) -> Hash256Digest {
        Hash256Digest::default()
    }
}

impl<'a> WitnessTransaction<'a> for WitnessTx {
    type WTXID = WTXID;
    // type WitnessSighashArgs

    fn wtxid(&self) -> Self::WTXID {
        let mut w = Hash256Writer::default();
        self.serialize(&mut w).expect("No IOError from SHA2");
        w.finish()
    }

    fn witness_sighash(&self, /*w: &WitnessSighashArgs */) -> Hash256Digest {
        unimplemented!()
    }
}

impl Ser for WitnessTx
{
    fn serialized_length(&self) -> usize {
        let mut len = self.version().serialized_length();
        len += 2;  // Segwit Flag
        len += self.vin.serialized_length();
        len += self.vout.serialized_length();
        len += self.witnesses.serialized_length();
        len += self.locktime().serialized_length();
        len
    }

    fn deserialize<R>(reader: &mut R, _limit: usize) -> TxResult<Self>
    where
        R: Read,
        Self: std::marker::Sized
    {
        let version = u32::deserialize(reader, 0)?;
        let mut flag = [0u8; 2];
        reader.read_exact(&mut flag)?;
        if flag != [0u8, 1u8] { return Err(TxError::BadWitnessFlag(flag)); };
        let vin = Vin::deserialize(reader, 0)?;
        let vout = Vout::deserialize(reader, 0)?;
        let witnesses = Vec::<Witness>::deserialize(reader, vin.len())?;
        let locktime = u32::deserialize(reader, 0)?;
        Ok(Self{
            version,
            vin,
            vout,
            witnesses,
            locktime,
        })
    }

    fn serialize<T>(&self, writer: &mut T) -> TxResult<usize>
    where
        T: Write
    {
        let mut len = self.version().serialize(writer)?;
        len += writer.write(&[0u8, 1u8])?;
        len += self.vin.serialize(writer)?;
        len += self.vout.serialize(writer)?;
        len += self.witnesses.serialize(writer)?;
        len += self.locktime().serialize(writer)?;
        Ok(len)
    }
}
