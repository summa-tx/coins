//! Handshake LockingScript and WitnessProgram

use std::io::{Read, Write};

use riemann_core::{
    ser::ByteFormat,
    types::tx::RecipientIdentifier
};

wrap_prefixed_byte_vector!(
    WitnessProgram
);

impl From<[u8; 20]> for WitnessProgram {
    fn from(v: [u8; 20]) -> Self {
        let hash = vec![0x14];
        hash.append(&mut v.to_vec());
        WitnessProgram::new(hash)
    }
}

impl From<WitnessProgram> for [u8; 20] {
    fn from(w: WitnessProgram) -> [u8; 20] {
        let data = [0; 20];
        data.clone_from_slice(&w.0[..]);
        data
    }
}

impl From<WitnessProgram> for [u8; 32] {
    fn from(w: WitnessProgram) -> [u8; 32] {
        let data = [0; 32];
        data.clone_from_slice(&w.0[..]);
        data
    }
}

impl From<WitnessProgram> for Vec<u8> {
    fn from(w: WitnessProgram) -> Vec<u8> {
        w.0[1..].to_vec()
    }
}

pub struct LockingScript {
    pub version: u8,
    pub witness_program: WitnessProgram
}

impl LockingScript {
    pub fn null() -> Self {
        LockingScript {
            version: 0,
            witness_program: WitnessProgram::null()
        }
    }
}

impl riemann_core::ser::ByteFormat for LockingScript {
    type Error = riemann_core::ser::SerError;

    fn serialized_length(&self) -> usize {
        let mut length = 1;
        length += self.witness_program.len() as usize;
        length
    }

    fn read_from<R>(reader: &mut R, limit: usize) -> Result<Self, Self::Error>
    where
        R: Read
    {
        let mut version = [0; 1];
        reader.read_exact(&mut version)?;

        Ok(LockingScript{
            version: version[0],
            witness_program: WitnessProgram::read_prefix_vec(reader)?.into()
        })
    }

    fn write_to<W>(&self, writer: &mut W) -> Result<usize, <Self as ByteFormat>::Error>
    where
        W: Write
    {
        let mut total: usize = 0;
        total += writer.write(std::slice::from_mut(&mut self.version))?;
        total += &self.witness_program.write_to(writer)?;
        Ok(total)
    }
}

impl From<Vec<u8>> for LockingScript {
    fn from(raw: Vec<u8>) -> Self {
        let version = raw[0];
        let witness_program = raw.split_off(1);

        LockingScript {
            version: version,
            witness_program: WitnessProgram::from(witness_program)
        }
    }
}

impl RecipientIdentifier for LockingScript {}

// need to implement RecipientIdentifier

/// Standard script types, and a non-standard type for all other scripts.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum LockingScriptType {
    /// Pay to Witness Pubkeyhash.
    WPKH([u8; 20]),
    /// Pay to Witness Scripthash.
    WSH([u8; 32]),
    /// OP_RETURN
    #[allow(non_camel_case_types)]
    OP_RETURN(Vec<u8>),
    /// Nonstandard or unknown `Script` type. May be a newer witness version.
    NonStandard,
}

impl LockingScript {
    /// Instantiate a standard p2wpkh script pubkey from a pubkey.
    pub fn p2wpkh<'a, T, B>(key: &T) -> Self
    where
        B: rmn_bip32::curve::Secp256k1Backend<'a>,
        T: rmn_bip32::model::HasPubkey<'a, B>,
    {
        let mut v: Vec<u8> = vec![];
        v.extend(&key.pubkey_blake2b160());
        v.into()
    }

    /// Instantiate a standard p2wsh script pubkey from a script.
    pub fn p2wsh(script: &WitnessProgram) -> Self {
        let mut v: Vec<u8> = vec![];
        // TODO: will this work?
        v.extend(<sha3::Sha3_256 as sha3::Digest>::digest(script.as_ref()));
        v.into()
    }

    pub fn extract_op_return_data(&self) -> Option<Vec<u8>> {
        if self.version != 31 {
            return None;
        }

        if self.witness_program.len() < 2 || self.witness_program.len() > 40 {
            return None;
        }

        let mut v: Vec<u8> = vec![];
        v.extend(self.witness_program);

        Some(v)
    }

    pub fn standard_type(&self) -> LockingScriptType {
        if self.version == 31 {
            return LockingScriptType::OP_RETURN(self.witness_program.into());
        }

        if self.version == 0 {
            match self.witness_program.len() {
                20 => {
                    return LockingScriptType::WPKH(self.witness_program.into());
                }

                32 => {
                    return LockingScriptType::WSH(self.witness_program.into());
                }
            }
        }
    
        // fallthrough
        LockingScriptType::NonStandard
    }
}
