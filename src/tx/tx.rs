use std::io::{Read, Write, Result as IOResult};

use crate::tx::txin::{Vin, TxIn};
use crate::tx::txout::{Vout};
use crate::tx::wit::{Witness};
use crate::tx::primitives::{
    VarInt,
    Ser
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TxError{
    WrongNumberOfWitnesses,
    WitnessesWithoutSegwit
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
    ) -> Result<Self, TxError> {
        let segwit = if let Some(wit) = &witnesses {
            if wit.len() != vin.inputs.len() { return Err(TxError::WrongNumberOfWitnesses) };
            true
        } else {
            false
        };
        Ok(Tx{
            version,
            segwit,
            vin,
            vout,
            witnesses,
            locktime
        })
    }
}

impl Ser for Tx {
    fn serialized_length(&self) -> IOResult<usize> {
        let mut len = self.version.serialized_length()?;
        len += match self.segwit { true => 2, false => 0 };
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
        let vin_len = match segwit {
            true => {
                reader.read(&mut [0u8])?;
                VarInt::deserialize(reader, 0)?
            },
            false => {
                flag_or_vin_len
            }
        };
        let limit = vin_len.0 as usize;
        let vin = Vin {
            length: vin_len,
            inputs: Vec::<TxIn>::deserialize(reader, limit)?
        };
        let vout = Vout::deserialize(reader, 0)?;

        let witnesses = match segwit {
            // as many witnesses as inputs
            true => Some(Vec::<Witness>::deserialize(reader, limit)?),
            false => None
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
    use crate::tx::*;

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
