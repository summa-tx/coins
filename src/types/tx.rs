use std::io::{Read, Write, Result as IOResult, Error as IOError};

use bitcoin_spv::{types::Hash256Digest, btcspv::hash256};


use crate::types::txin::{Vin, TxIn};
use crate::types::txout::{Vout, TxOut};
use crate::types::wit::{Witness};
use crate::types::primitives::{
    VarInt,
    Script,
    Ser
};

#[derive(Debug)]
pub enum TxError{
    IOError(IOError),
    WrongNumberOfWitnesses,
    WitnessesWithoutSegwit,
    BadVersion,
    /// Sighash NONE is unsupported
    NoneUnsupported,
    /// Satoshi's sighash single bug. Throws an error here.
    SighashSingleBug

}

type TxResult<T> = Result<T, TxError>;

impl From<IOError> for TxError {
    fn from(error: IOError) -> Self {
        TxError::IOError(error)
    }
}

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tx{
    pub version: u32,
    pub segwit: bool,
    pub vin: Vin,
    pub vout: Vout,
    pub witnesses: Option<Vec<Witness>>,
    pub locktime: u32
}

impl Tx {
    pub fn without_witness(&self) -> Self {
        if !self.segwit { return self.clone() };
        Tx::new(
            self.version,
            self.vin.clone(),
            self.vout.clone(),
            None,
            self.locktime
        ).unwrap()
    }

    pub fn new_unsigned_witness(
        version: u32,
        vin: Vin,
        vout: Vout,
        locktime: u32
    ) -> Self {
        let n_ins = vin.len();
        Tx::new(
            version,
            vin,
            vout,
            Some((0..n_ins).map(|_| Witness::null()).collect()),
            locktime
        ).unwrap()
    }

    pub fn new(
        version: u32,
        vin: Vin,
        vout: Vout,
        witnesses: Option<Vec<Witness>>,
        locktime: u32
    ) -> TxResult<Self> {
        let segwit = if let Some(wit) = &witnesses {
            if wit.len() != vin.inputs.len() { return Err(TxError::WrongNumberOfWitnesses) };
            true
        } else {
            false
        };

        if version > 2 {
            return Err(TxError::BadVersion)
        }

        Ok(Tx{
            version,
            segwit,
            vin,
            vout,
            witnesses: witnesses.map(|v| v),
            locktime
        })
    }

    fn _hash_prevouts(&self, anyone_can_pay: bool) -> TxResult<Hash256Digest> {
        if anyone_can_pay {
            Ok(Hash256Digest::default())
        } else {
            let mut data: Vec<u8> = vec![];
            for input in self.vin.inputs.iter() {
                input.outpoint.serialize(&mut data)?;
            }
            Ok(hash256(&data))
        }

    }

    fn _hash_sequence(&self, sighash_type: &Sighash, anyone_can_pay: bool) -> TxResult<Hash256Digest> {
        if anyone_can_pay || *sighash_type == Sighash::Single {
            Ok(Hash256Digest::default())
        } else {
            let mut data: Vec<u8> = vec![];
            for input in self.vin.inputs.iter() {
                input.sequence.serialize(&mut data)?;
            }
            Ok(hash256(&data))
        }
    }

    fn _hash_outputs(&self, index: usize, sighash_type: &Sighash) -> TxResult<Hash256Digest> {
        match sighash_type {
            Sighash::All => {
                let mut data: Vec<u8> = vec![];
                for output in self.vout.outputs.iter() {
                    output.serialize(&mut data)?;
                }
                Ok(hash256(&data))
            },
            Sighash::Single => {
                let mut data: Vec<u8> = vec![];
                self.vout.outputs[index].serialize(&mut data)?;
                Ok(hash256(&data))
            },
            _ => Ok(Hash256Digest::default())
        }
    }

    fn _tx_id(&self) -> TxResult<Hash256Digest> {
        let mut data = vec![];
        self.without_witness().serialize(&mut data)?;
        Ok(hash256(&data))
    }

    pub fn write_segwit_sighash_preimage<T, U>(
        &self,
        writer: &mut U,
        index: usize,
        sighash_type: Sighash,
        prevout_value: u64,
        prevout_script: T,
        anyone_can_pay: bool) -> TxResult<()>
    where
        T: Into<Script>,
        U: Write
    {
        let script: Script = prevout_script.into();
        let input = &self.vin.inputs[index];

        self.version.serialize(writer)?;
        self._hash_prevouts(anyone_can_pay)?.serialize(writer)?;
        self._hash_sequence(&sighash_type, anyone_can_pay)?.serialize(writer)?;
        input.outpoint.serialize(writer)?;
        script.serialize(writer)?;
        prevout_value.serialize(writer)?;
        input.sequence.serialize(writer)?;
        self._hash_outputs(index, &sighash_type)?.serialize(writer)?;
        self.locktime.serialize(writer)?;
        (sighash_type_to_flag(sighash_type, anyone_can_pay) as u32).serialize(writer)?;
        Ok(())
    }

    pub fn segwit_sighash<T>(
        &self,
        index: usize,
        sighash_type: Sighash,
        prevout_value: u64,
        prevout_script: T,
        anyone_can_pay: bool) -> TxResult<Hash256Digest>
    where
        T: Into<Script>
    {
        let mut data = vec![];
        self.write_segwit_sighash_preimage(&mut data, index, sighash_type, prevout_value, prevout_script, anyone_can_pay)?;
        Ok(hash256(&data))
    }

    fn _legacy_sighash_prep(&self, index: usize, prevout_script: &Script) -> Self
    {
        let mut copy_tx = self.clone();

        for mut input in &mut copy_tx.vin.inputs {
            input.script_sig = Script::null();
        }

        copy_tx.vin.inputs[index].script_sig = prevout_script.clone();

        copy_tx
    }

    fn _legacy_sighash_single(
        copy_tx: &mut Self,
        index: usize) -> TxResult<()>
    {
        let mut tx_outs: Vec<TxOut> = (0..index - 1).map(|_| TxOut::null()).collect();
        tx_outs.push(copy_tx.vout.outputs[index].clone());
        copy_tx.vout = Vout::new(tx_outs);

        let mut vin = copy_tx.vin.clone();
        for (i, mut input) in vin.inputs.iter_mut().enumerate() {
            if i != index { input.sequence = 0; }
        }
        copy_tx.vin = vin;

        Ok(())
    }

    fn _legacy_sighash_anyone_can_pay(
        copy_tx: &mut Self,
        index: usize) -> TxResult<()>
    {
        copy_tx.vin = Vin::new(vec![copy_tx.vin.inputs[index].clone()]);
        Ok(())
    }

    pub fn write_legacy_sighash_preimage<T, U>(
        &self,
        writer: &mut U,
        index: usize,
        sighash_type: Sighash,
        prevout_script: T,
        anyone_can_pay: bool) -> TxResult<()>
    where
        T: Into<Script>,
        U: Write
    {
        let script: Script = prevout_script.into();
        let mut copy_tx: Self = self._legacy_sighash_prep(index, &script);

        if sighash_type == Sighash::Single {
            Tx::_legacy_sighash_single(
                &mut copy_tx,
                index
            )?;
        }

        if anyone_can_pay {
            Tx::_legacy_sighash_anyone_can_pay(&mut copy_tx, index)?;
        }

        copy_tx.serialize(writer)?;
        (sighash_type_to_flag(sighash_type, anyone_can_pay) as u32).serialize(writer)?;

        Ok(())
    }

    pub fn legacy_sighash<T>(
        &self,
        index: usize,
        sighash_type: Sighash,
        prevout_script: T,
        anyone_can_pay: bool) -> TxResult<Hash256Digest>
    where
        T: Into<Script>
    {
        let mut data = vec![];
        self.write_legacy_sighash_preimage(&mut data, index, sighash_type, prevout_script, anyone_can_pay)?;
        Ok(hash256(&data))
    }
}

impl Ser for Tx {
    fn serialized_length(&self) -> IOResult<usize> {
        let mut len = self.version.serialized_length()?;
        len += if self.segwit { 2 } else { 0 };
        len += self.vin.serialized_length()?;
        len += self.vout.serialized_length()?;
        if let Some(wits) = &self.witnesses {
            len += wits.serialized_length()?;
        };
        len += self.locktime.serialized_length()?;
        Ok(len)
    }

    fn deserialize<T>(reader: &mut T, _limit: usize) -> IOResult<Self>
    where
        T: Read,
        Self: std::marker::Sized
    {
        let version = u32::deserialize(reader, 0)?;

        // if the serialized tx is segwit, it'll be a 0. we want to
        // if it is 0, the next byte is 1, then the vin starts
        // So if the flag byte is NOT 0, then we read the
        let flag_or_vin_len = VarInt::deserialize(reader, 0)?;
        let segwit = match flag_or_vin_len.0 { 0 => true, _ => false };

        let vin_len = if segwit {
            reader.read_exact(&mut [0u8])?;
            VarInt::deserialize(reader, 0)?
        } else {
            flag_or_vin_len
        };
        let limit = vin_len.0 as usize;
        let vin = Vin {
            length: vin_len,
            inputs: Vec::<TxIn>::deserialize(reader, limit)?
        };
        let vout = Vout::deserialize(reader, 0)?;

        let witnesses = if segwit {
            Some(Vec::<Witness>::deserialize(reader, limit)?)
        } else {
            None
        };
        let locktime = u32::deserialize(reader, 0)?;
        Ok(Tx{
            version,
            segwit,
            vin,
            vout,
            witnesses,
            locktime,
        })
    }

    fn serialize<T>(&self, writer: &mut T) -> IOResult<usize>
    where
        T: Write
    {
        let mut len = self.version.serialize(writer)?;
        if self.segwit {
            len += writer.write(&[0x00, 0x01])?;
        }
        len += self.vin.serialize(writer)?;
        len += self.vout.serialize(writer)?;
        if self.segwit {
            if let Some(wits) = &self.witnesses {
                len += wits.serialize(writer)?;
            }
        }
        len += self.locktime.serialize(writer)?;
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    #[test]
    fn it_assembles_legacy() {
        let numbers: Vec<u8> = (0u8..32u8).collect();
        let mut prevout_txid = [0u8; 32];
        prevout_txid.copy_from_slice(&numbers);
        let outpoint = Outpoint{
            txid: prevout_txid,
            idx: 2864434397
        };
        let spk = Script::new(
            vec![0x00, 0x14, 0x11, 0x00, 0x33, 0x00, 0x55, 0x00, 0x77, 0x00, 0x99, 0x00, 0xbb, 0x00, 0xdd, 0x00, 0xff, 0x11, 0x00, 0x33, 0x00, 0x55]
        );
        let txin = TxIn{
            outpoint,
            script_sig: spk.clone(),
            sequence: 0x33883388
        };
        let vin = Vin::new(vec![txin]);
        let txout = TxOut{
            value: 888u64,
            script_pubkey: spk
        };
        let vout = Vout::new(vec![txout]);
        let tx = Tx::new(
            0x2u32,
            vin,
            vout,
            None,
            0x44332211u32
        ).unwrap();
        let ser_str = tx.serialize_hex().unwrap();
        // println!("serialized {:?}", &ser_str);
        assert_eq!(
            "0200000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fddccbbaa16001411003300550077009900bb00dd00ff11003300558833883301780300000000000016001411003300550077009900bb00dd00ff110033005511223344",
            ser_str
        );
        assert_eq!(
            Tx::deserialize_hex(ser_str).unwrap(),
            tx
        );
    }

    #[test]
    fn it_assembles_witness() {
        let numbers: Vec<u8> = (0u8..32u8).collect();
        let mut prevout_txid = [0u8; 32];
        prevout_txid.copy_from_slice(&numbers);
        let outpoint = Outpoint{
            txid: prevout_txid,
            idx: 2864434397
        };
        let spk = Script::new(
            vec![0x00, 0x14, 0x11, 0x00, 0x33, 0x00, 0x55, 0x00, 0x77, 0x00, 0x99, 0x00, 0xbb, 0x00, 0xdd, 0x00, 0xff, 0x11, 0x00, 0x33, 0x00, 0x55]
        );
        let txin = TxIn{
            outpoint,
            script_sig: spk.clone(),
            sequence: 0x33883388
        };
        let vin = Vin::new(vec![txin]);
        let txout = TxOut{
            value: 888u64,
            script_pubkey: spk
        };
        let vout = Vout::new(vec![txout]);
        let tx = Tx::new(
            0x2u32,
            vin,
            vout,
            Some(vec![Witness::null()]),
            0x44332211u32
        ).unwrap();
        let ser_str = tx.serialize_hex().unwrap();
        // println!("serialized {:?}", &ser_str);
        assert_eq!(
            "02000000000101000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fddccbbaa16001411003300550077009900bb00dd00ff11003300558833883301780300000000000016001411003300550077009900bb00dd00ff11003300550011223344",
            ser_str
        );
        assert_eq!(
            Tx::deserialize_hex(ser_str).unwrap(),
            tx
        );
    }
}
