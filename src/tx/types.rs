use bitcoin_spv::types::Hash256Digest;
use std::io::{Read, Write, Result as IOResult};

// use crate::tx::format::{Serializable};
use crate::tx::primitives::{
    VarInt,
    Ser
};


#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Outpoint{
    pub txid: Hash256Digest,
    pub idx: u32
}

impl Outpoint {
    pub fn null() -> Self {
        Outpoint{
            txid: Hash256Digest::default(),
            idx: 0xffffffff
        }
    }
}

impl Ser for Outpoint {
    fn serialized_length(&self) -> IOResult<usize> {
        Ok(36)
    }

    fn deserialize<T>(reader: &mut T, _limit: usize) -> IOResult<Self>
    where
        T: Read,
        Self: std::marker::Sized
    {
        Ok(Outpoint{
            txid: Hash256Digest::deserialize(reader, 0)?,
            idx: u32::deserialize(reader, 0)?
        })
    }

    fn serialize<T>(&self, writer: &mut T) -> IOResult<usize>
    where
        T: Write
    {
        let mut len = self.txid.serialize(writer)?;
        len += self.idx.serialize(writer)?;
        Ok(len)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Script {
    pub length: VarInt,
    pub body: Vec<u8>
}

impl Script {
    pub fn null() -> Self {
        Script::new(vec![])
    }

    pub fn new(script: Vec<u8>) -> Self {
        Script{
            length: VarInt::new(script.len() as u64),
            body: script
        }
    }
}

impl Ser for Script {
    fn serialized_length(&self) -> IOResult<usize> {
        let mut len = self.length.serialized_length()?;
        len += self.body.serialized_length()?;
        Ok(len)
    }

    fn deserialize<T>(reader: &mut T, _limit: usize) -> IOResult<Self>
    where
        T: Read,
        Self: std::marker::Sized
    {
        let length = VarInt::deserialize(reader, 0)?;
        let limit = length.0;
        Ok(Script{
            length: length,
            body: Vec::<u8>::deserialize(reader, limit as usize)?
        })
    }

    fn serialize<T>(&self, writer: &mut T) -> IOResult<usize>
    where
        T: Write
    {
        let mut len = self.length.serialize(writer)?;
        len += self.body.serialize(writer)?;
        Ok(len)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxIn{
    pub outpoint: Outpoint,
    pub script_sig: Script,
    pub sequence: u32
}

impl Ser for TxIn {
    fn serialized_length(&self) -> IOResult<usize> {
        let mut len = self.outpoint.serialized_length()?;
        len += self.script_sig.serialized_length()?;
        len += self.sequence.serialized_length()?;
        Ok(len)
    }

    fn deserialize<T>(reader: &mut T, _limit: usize) -> IOResult<Self>
    where
        T: Read,
        Self: std::marker::Sized
    {
        Ok(TxIn{
            outpoint: Outpoint::deserialize(reader, 0)?,
            script_sig: Script::deserialize(reader, 0)?,
            sequence: u32::deserialize(reader, 0)?
        })
    }

    fn serialize<T>(&self, writer: &mut T) -> IOResult<usize>
    where
        T: Write
    {
        let mut len = self.outpoint.serialize(writer)?;
        len += self.script_sig.serialize(writer)?;
        len += self.sequence.serialize(writer)?;
        Ok(len)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxOut{
    pub value: u64,
    pub script_pubkey: Script
}

impl Ser for TxOut {
    fn serialized_length(&self) -> IOResult<usize> {
        let mut len = self.value.serialized_length()?;
        len += self.script_pubkey.serialized_length()?;
        Ok(len)
    }

    fn deserialize<T>(reader: &mut T, _limit: usize) -> IOResult<Self>
    where
        T: Read,
        Self: std::marker::Sized
    {
        let value = u64::deserialize(reader, 0)?;
        Ok(TxOut{
            value,
            script_pubkey: Script::deserialize(reader, 0)?
        })
    }

    fn serialize<T>(&self, writer: &mut T) -> IOResult<usize>
    where
        T: Write
    {
        let mut len = self.value.serialize(writer)?;
        len += self.script_pubkey.serialize(writer)?;
        Ok(len)
    }
}

pub type WitnessStackItem = Script;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Witness{
    pub stack_items: VarInt,
    pub stack: Vec<WitnessStackItem>
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Vin{
    pub length: VarInt,
    pub inputs: Vec<TxIn>
}

impl Vin {
    pub fn new(inputs: Vec<TxIn>) -> Self {
        Vin{
            length: VarInt::new(inputs.len() as u64),
            inputs
        }
    }
}

impl Ser for Vin {
    fn serialized_length(&self) -> IOResult<usize> {
        let mut len = self.length.serialized_length()?;
        len += self.inputs.serialized_length()?;
        Ok(len)
    }

    fn deserialize<T>(reader: &mut T, _limit: usize) -> IOResult<Self>
    where
        T: Read,
        Self: std::marker::Sized
    {
        let length = VarInt::deserialize(reader, 0)?;
        let limit = length.0;
        Ok(Vin{
            length,
            inputs: Vec::<TxIn>::deserialize(reader, limit as usize)?
        })
    }

    fn serialize<T>(&self, writer: &mut T) -> IOResult<usize>
    where
        T: Write
    {
        let mut len = self.length.serialize(writer)?;
        len += self.inputs.serialize(writer)?;
        Ok(len)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Vout{
    pub length: VarInt,
    pub outputs: Vec<TxOut>
}

impl Ser for Vout {
    fn serialized_length(&self) -> IOResult<usize> {
        let mut len = self.length.serialized_length()?;
        len += self.outputs.serialized_length()?;
        Ok(len)
    }

    fn deserialize<T>(reader: &mut T, _limit: usize) -> IOResult<Self>
    where
        T: Read,
        Self: std::marker::Sized
    {
        let length = VarInt::deserialize(reader, 0)?;
        let limit = length.0;
        Ok(Vout{
            length,
            outputs: Vec::<TxOut>::deserialize(reader, limit as usize)?
        })
    }

    fn serialize<T>(&self, writer: &mut T) -> IOResult<usize>
    where
        T: Write
    {
        let mut len = self.length.serialize(writer)?;
        len += self.outputs.serialize(writer)?;
        Ok(len)
    }
}

impl Vout {
    pub fn new(outputs: Vec<TxOut>) -> Self {
        Vout{
            length: VarInt::new(outputs.len() as u64),
            outputs
        }
    }
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TxError{
    WrongNumberOfWitnesses,
    WitnessesWithoutSegwit
}

impl Tx {

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

    static NULL_OUTPOINT: &str = "0000000000000000000000000000000000000000000000000000000000000000ffffffff";

    #[test]
    fn it_serializes_and_derializes_outpoints() {
        let cases = [
            (Outpoint{txid: Hash256Digest::default(), idx: 0}, (0..36).map(|_| "00").collect::<String>()),
            (Outpoint::null(), NULL_OUTPOINT.to_string())
        ];
        for case in cases.iter() {
            assert_eq!(case.0.serialized_length().unwrap(), case.1.len() / 2);
            assert_eq!(case.0.serialize_hex().unwrap(), case.1.to_owned());
            assert_eq!(Outpoint::deserialize_hex(case.1.to_owned()).unwrap(), case.0);
        }
    }

    #[test]
    fn it_serializes_and_derializes_scripts() {
        let cases = [
            (Script::new(vec![0xaa, 0xbb, 0xcc, 0xdd]), "04aabbccdd"),
            (Script::new(vec![1u8; 256]), &format!("fd0001{}", (0..256).map(|_| "01").collect::<String>())),
            (
                Script::new(
                    vec![0x00, 0x14, 0x11, 0x00, 0x33, 0x00, 0x55, 0x00, 0x77, 0x00, 0x99, 0x00, 0xbb, 0x00, 0xdd, 0x00, 0xff, 0x11, 0x00, 0x33, 0x00, 0x55]
                ),
                "16001411003300550077009900bb00dd00ff1100330055"
            ),
            (
                Script{
                    length: VarInt(0x16, 3),
                    body: vec![0x00, 0x14, 0x11, 0x00, 0x33, 0x00, 0x55, 0x00, 0x77, 0x00, 0x99, 0x00, 0xbb, 0x00, 0xdd, 0x00, 0xff, 0x11, 0x00, 0x33, 0x00, 0x55]
                },
                "fd1600001411003300550077009900bb00dd00ff1100330055"
            ),
        ];

        for case in cases.iter() {
            assert_eq!(case.0.serialized_length().unwrap(), case.1.len() / 2);
            assert_eq!(case.0.serialize_hex().unwrap(), case.1.to_owned());
            assert_eq!(Script::deserialize_hex(case.1.to_owned()).unwrap(), case.0);
        }
    }

    #[test]
    fn it_serializes_and_derializes_inputs() {
        let cases = [
            (
                TxIn{
                    outpoint: Outpoint::null(),
                    script_sig: Script::null(),
                    sequence: 0x1234abcd
                },
                format!("{}{}{}", NULL_OUTPOINT, "00", "cdab3412")
            ),
            (
                TxIn{
                    outpoint: Outpoint::null(),
                    script_sig: Script{
                        length: VarInt(0x16, 3),
                        body: vec![0x00, 0x14, 0x11, 0x00, 0x33, 0x00, 0x55, 0x00, 0x77, 0x00, 0x99, 0x00, 0xbb, 0x00, 0xdd, 0x00, 0xff, 0x11, 0x00, 0x33, 0x00, 0x55]
                    },
                    sequence: 0x1234abcd
                },
                format!("{}{}{}", NULL_OUTPOINT, "fd1600001411003300550077009900bb00dd00ff1100330055", "cdab3412")
            ),
        ];

        for case in cases.iter() {
            assert_eq!(case.0.serialized_length().unwrap(), case.1.len() / 2);
            assert_eq!(case.0.serialize_hex().unwrap(), case.1.to_owned());
            assert_eq!(TxIn::deserialize_hex(case.1.to_owned()).unwrap(), case.0);
        }
    }

    #[test]
    fn it_assembles() {
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
}
