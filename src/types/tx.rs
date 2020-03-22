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
        script::{Script, Witness},
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
   type SighashArgs;
   type TXID: MarkedHash<Hash256Digest>;
   // TODO: abstract the hash writer

   fn inputs(&'a self) -> &'a[Self::TxIn];
   fn outputs(&'a self) -> &'a[Self::TxOut];
   fn version(&self) -> u32;
   fn locktime(&self) -> u32;

   fn txid(&self) -> Self::TXID;

   fn write_legacy_sighash_preimage<W: Write>(&self, writer: &mut W, _args: &Self::SighashArgs) -> TxResult<()>;

   fn legacy_sighash(&self, args: &Self::SighashArgs) -> Hash256Digest {
       let mut w = Hash256Writer::default();
       self.write_legacy_sighash_preimage(&mut w, args).expect("No IOError from SHA2");
       w.finish()
   }
}

trait WitnessTransaction<'a>: Transaction<'a> {
    type WTXID: MarkedHash<Hash256Digest>;
    type WitnessSighashArgs;

    fn wtxid(&self) -> Self::WTXID;
    fn write_witness_sighash_preimage<W: Write>(&self, _writer: &mut W, args: &Self::WitnessSighashArgs) -> TxResult<()>;
    fn witness_sighash(&self, args: &Self::WitnessSighashArgs) -> Hash256Digest {
        let mut w = Hash256Writer::default();
        self.write_witness_sighash_preimage(&mut w, args).expect("No IOError from SHA2");
        w.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyTx {
    version: u32,
    vin: Vin,
    vout: Vout,
    locktime: u32
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacySighashArgs<'a> {
    pub index: usize,
    pub sighash_type: Sighash,
    pub prevout_script: &'a Script,
    pub anyone_can_pay: bool
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessSighashArgs<'a> {
    pub index: usize,
    pub sighash_type: Sighash,
    pub prevout_script: &'a Script,
    pub prevout_value: u64,
    pub anyone_can_pay: bool
}

impl LegacyTx {
    fn legacy_sighash_prep(&self, index: usize, prevout_script: &Script) -> Self
    {
        let mut copy_tx = self.clone();

        for i in 0..copy_tx.vin.len() {
            copy_tx.vin[i].script_sig = if i == index {
                prevout_script.clone()
            } else {
                Script::null()
            };
        };
        copy_tx
    }

    fn legacy_sighash_single(
        copy_tx: &mut Self,
        index: usize) -> TxResult<()>
    {
        let mut tx_outs: Vec<TxOut> = (0..index).map(|_| TxOut::null()).collect();
        tx_outs.push(copy_tx.vout[index].clone());
        copy_tx.vout = Vout::new(tx_outs);

        let mut vin = vec![];

        // let mut vin = copy_tx.vin.clone();
        for i in 0..copy_tx.vin.items().len() {
            let mut txin = copy_tx.vin[i].clone();
            if i != index { txin.sequence = 0; }
            vin.push(txin);
        }
        copy_tx.vin = vin.into();
        Ok(())
    }

    fn legacy_sighash_anyone_can_pay(
        copy_tx: &mut Self,
        index: usize) -> TxResult<()>
    {
        copy_tx.vin = Vin::new(vec![copy_tx.vin[index].clone()]);
        Ok(())
    }
}

impl<'a> Transaction<'a> for LegacyTx {
    type TxIn = TxIn;
    type TxOut = TxOut;
    type SighashArgs = LegacySighashArgs<'a>;
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
        w.finish_marked()
    }

    fn write_legacy_sighash_preimage<W: Write>(
        &self,
        writer: &mut W,
        args: &LegacySighashArgs
    ) -> TxResult<()> {
        let mut copy_tx: Self = self.legacy_sighash_prep(args.index, args.prevout_script);
        if args.sighash_type == Sighash::Single {
            Self::legacy_sighash_single(
                &mut copy_tx,
                args.index
            )?;
        }

        if args.anyone_can_pay {
            Self::legacy_sighash_anyone_can_pay(&mut copy_tx, args.index)?;
        }

        copy_tx.serialize(writer)?;
        (sighash_type_to_flag(args.sighash_type, args.anyone_can_pay) as u32).serialize(writer)?;

        Ok(())
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
    locktime: u32,
}

impl WitnessTx {
    pub fn without_witness(&self) -> LegacyTx {
        LegacyTx {
            version: self.version,
            vin: self.vin.clone(),
            vout: self.vout.clone(),
            locktime: self.locktime
        }
    }

    fn hash_prevouts(&self, anyone_can_pay: bool) -> TxResult<Hash256Digest> {
        if anyone_can_pay {
            Ok(Hash256Digest::default())
        } else {
            let mut w = Hash256Writer::default();
            for input in self.vin.items().iter() {
                input.outpoint.serialize(&mut w)?;
            }
            Ok(w.finish())
        }

    }

    fn hash_sequence(&self, sighash_type: Sighash, anyone_can_pay: bool) -> TxResult<Hash256Digest> {
        if anyone_can_pay || sighash_type == Sighash::Single {
            Ok(Hash256Digest::default())
        } else {
            let mut w = Hash256Writer::default();
            for input in self.vin.items().iter() {
                input.sequence.serialize(&mut w)?;
            }
            Ok(w.finish())
        }
    }

    fn hash_outputs(&self, index: usize, sighash_type: Sighash) -> TxResult<Hash256Digest> {
        match sighash_type {
            Sighash::All => {
                let mut w = Hash256Writer::default();
                for output in self.vout.items().iter() {
                    output.serialize(&mut w)?;
                }
                Ok(w.finish())
            },
            Sighash::Single => {
                let mut w = Hash256Writer::default();
                self.vout[index].serialize(&mut w)?;
                Ok(w.finish())
            },
            _ => Ok(Hash256Digest::default())
        }
    }
}

impl<'a> Transaction<'a> for WitnessTx {
    type TxIn = TxIn;
    type TxOut = TxOut;
    type SighashArgs = LegacySighashArgs<'a>;
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
        w.finish_marked()
    }

    fn write_legacy_sighash_preimage<W: Write>(
        &self,
        writer: &mut W,
        args: &LegacySighashArgs
    ) -> TxResult<()> {
        self.without_witness().write_legacy_sighash_preimage(writer, args)
    }
}

impl<'a> WitnessTransaction<'a> for WitnessTx {
    type WTXID = WTXID;
    type WitnessSighashArgs = WitnessSighashArgs<'a>;

    fn wtxid(&self) -> Self::WTXID {
        let mut w = Hash256Writer::default();
        self.serialize(&mut w).expect("No IOError from SHA2");
        w.finish_marked()
    }

    fn write_witness_sighash_preimage<W>(
        &self,
        writer: &mut W,
        args: &WitnessSighashArgs) -> TxResult<()>
    where
        W: Write
    {
        let input = &self.vin[args.index];

        self.version.serialize(writer)?;
        self.hash_prevouts(args.anyone_can_pay)?.serialize(writer)?;
        self.hash_sequence(args.sighash_type, args.anyone_can_pay)?.serialize(writer)?;
        input.outpoint.serialize(writer)?;
        args.prevout_script.serialize(writer)?;
        args.prevout_value.serialize(writer)?;
        input.sequence.serialize(writer)?;
        self.hash_outputs(args.index, args.sighash_type)?.serialize(writer)?;
        self.locktime.serialize(writer)?;
        (sighash_type_to_flag(args.sighash_type, args.anyone_can_pay) as u32).serialize(writer)?;
        Ok(())
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
