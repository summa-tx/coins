//! Handshake LockingScript and WitnessProgram

use crate::{hashes::blake2b160, types::Script};
use coins_core::{
    hashes::{Digest, DigestOutput, Sha3_256},
    impl_hex_serde,
    ser::{self, ByteFormat},
    types::tx::RecipientIdentifier,
};
use std::io::{Read, Write};
use thiserror::Error;

coins_core::wrap_prefixed_byte_vector!(
    /// A WitnessStackItem is a marked `Vec<u8>` intended for use in witnesses. Each
    /// Witness is a `PrefixVec<WitnessStackItem>`. The Transactions `witnesses` is a non-prefixed
    /// `Vec<Witness>.`
    ///
    /// `WitnessStackItem::null()` and `WitnessStackItem::default()` return the empty byte vector
    /// with a 0 prefix, which represents numerical 0, or null bytestring.
    ///
    WitnessStackItem
);

/// A Witness is a `PrefixVec` of `WitnessStackItem`s. This witness corresponds to a single input.
///
/// # Note
///
/// The transaction's witness is composed of many of these `Witness`es in an UNPREFIXED vector.
pub type Witness = Vec<WitnessStackItem>;

/// Errors associated with WitnessProgram
#[derive(Debug, Error)]
pub enum LockingScriptError {
    /// Indicates a WitnessProgram with an invalid size.
    #[error("Invalid size of WitnessProgram")]
    InvalidWitnessProgramSizeError,
}

coins_core::wrap_prefixed_byte_vector!(
    /// A WitnessProgram represents the data field of a LockingScript.
    /// Since Handshake is segwit only, the WitnessProgram doesn't contain
    /// opcodes itself, it is templated into a script at runtime. The
    /// size of the WitnessProgram determines how it is interpreted for
    /// version 0 LockingScripts.
    WitnessProgram
);

/// The WitnessProgram is a 20 or 32 byte hash. When network serialized,
/// it is a prefixed length byte vector.
impl WitnessProgram {
    /// Split the WitnessProgram into a tuple with of version,
    /// length and data.
    pub fn split(&self) -> (u8, Vec<u8>) {
        let length = self.0.len();

        let mut data = Vec::with_capacity(length);
        data.clone_from_slice(&self.0[..]);

        (length as u8, data)
    }
}

impl From<[u8; 20]> for WitnessProgram {
    fn from(v: [u8; 20]) -> Self {
        Self::new(v.to_vec())
    }
}

impl From<[u8; 32]> for WitnessProgram {
    fn from(v: [u8; 32]) -> Self {
        Self::new(v.to_vec())
    }
}

impl From<DigestOutput<Sha3_256>> for WitnessProgram {
    fn from(v: DigestOutput<Sha3_256>) -> Self {
        Self::new(v.as_slice().to_vec())
    }
}

impl From<WitnessProgram> for [u8; 20] {
    fn from(w: WitnessProgram) -> [u8; 20] {
        let mut data = [0; 20];
        data.clone_from_slice(&w.0[..]);
        data
    }
}

impl From<WitnessProgram> for [u8; 32] {
    fn from(w: WitnessProgram) -> [u8; 32] {
        let mut data = [0; 32];
        data.clone_from_slice(&w.0[..]);
        data
    }
}

impl From<WitnessProgram> for Vec<u8> {
    fn from(w: WitnessProgram) -> Vec<u8> {
        w.0[..].to_vec()
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
/// A LockingScript
pub struct LockingScript {
    /// The version field determines how the Witness Program is interpreted
    /// by the virtual machine.
    pub version: u8,
    /// The witness_program is generally a committment to some data that is required
    /// for virtual machine execution. For version 0, a witness_program that is 20
    /// bytes is interpreted as a pay-to-witness-pubkeyhash and data that is 32 bytes
    /// is interpreted as a pay-to-witness-scripthash.
    pub witness_program: WitnessProgram,
}

impl LockingScript {
    /// Returns a null LockingScript
    pub fn null() -> Self {
        Self {
            version: 0,
            witness_program: WitnessProgram(vec![0x00; 20]),
        }
    }

    /// Create a new LockingScript
    pub fn new(v: Vec<u8>) -> Result<Self, LockingScriptError> {
        let (version_and_size, data) = v.split_at(2);
        let version = version_and_size[0];
        let size = version_and_size[1];

        if size != data.len() as u8 {
            return Err(LockingScriptError::InvalidWitnessProgramSizeError);
        }

        Ok(Self {
            version,
            witness_program: WitnessProgram::from(data),
        })
    }
}

impl coins_core::ser::ByteFormat for LockingScript {
    type Error = coins_core::ser::SerError;

    fn serialized_length(&self) -> usize {
        let mut length = 2; // version and length
        length += self.witness_program.len() as usize;
        length
    }

    fn read_from<R>(reader: &mut R) -> Result<Self, Self::Error>
    where
        R: Read,
    {
        let mut version = [0; 1];
        reader.read_exact(&mut version)?;

        Ok(LockingScript {
            version: version[0],
            witness_program: ser::read_prefix_vec(reader)?.into(),
        })
    }

    fn write_to<W>(&self, writer: &mut W) -> Result<usize, <Self as ByteFormat>::Error>
    where
        W: Write,
    {
        let mut total: usize = 0;
        total += writer.write(&self.version.to_le_bytes())?;
        total += &self.witness_program.write_to(writer)?;
        Ok(total)
    }
}

impl From<Vec<u8>> for LockingScript {
    fn from(mut raw: Vec<u8>) -> Self {
        let version = raw[0];
        let witness_program = raw.split_off(2);

        LockingScript {
            version,
            witness_program: WitnessProgram::from(witness_program),
        }
    }
}

impl RecipientIdentifier for LockingScript {}

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
        B: coins_bip32::curve::Secp256k1Backend,
        T: coins_bip32::model::HasPubkey<'a, B>,
    {
        Self {
            version: 0,
            witness_program: blake2b160(&key.pubkey_bytes()).into(),
        }
    }

    /// Instantiate a standard p2wsh script pubkey from a script.
    pub fn p2wsh(script: &Script) -> Self {
        let mut w = Sha3_256::default();
        w.write_all(script.items()).expect("No i/o error");
        let digest = w.finalize();

        Self {
            version: 0,
            witness_program: digest.into(),
        }
    }

    /// Extract data from an op_return output. In Handshake, the version must be
    /// 31 for the output to be an op_return output.
    pub fn extract_op_return_data(&self) -> Option<Vec<u8>> {
        if self.version != 31 {
            return None;
        }

        if self.witness_program.len() < 2 || self.witness_program.len() > 40 {
            return None;
        }

        let mut v: Vec<u8> = vec![];
        v.extend(self.witness_program.clone());

        Some(v)
    }

    /// Get the type of the LockingScript based on its version and the size of
    /// the WitnessProgram.
    pub fn standard_type(&self) -> Result<LockingScriptType, LockingScriptError> {
        if self.version == 31 {
            return Ok(LockingScriptType::OP_RETURN(
                self.witness_program.clone().into(),
            ));
        }

        if self.version == 0 {
            match self.witness_program.len() {
                20 => {
                    let mut wpkh = [0x00; 20];
                    wpkh.copy_from_slice(self.witness_program.items());
                    return Ok(LockingScriptType::WPKH(wpkh));
                }

                32 => {
                    let mut wsh = [0x00; 32];
                    wsh.copy_from_slice(self.witness_program.items());
                    return Ok(LockingScriptType::WSH(wsh));
                }
                _ => return Err(LockingScriptError::InvalidWitnessProgramSizeError),
            }
        }

        // fallthrough
        Ok(LockingScriptType::NonStandard)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use coins_bip32::{curve::model::*, model::*, XPriv};
    use coins_core::ser::ByteFormat;

    #[test]
    fn it_creates_null_locking_script() {
        let script = LockingScript::null();

        assert_eq!(script.version, 0);
        assert_eq!(script.witness_program, WitnessProgram(vec![00; 20]));
    }

    #[test]
    fn it_generates_p2wpkh_locking_script() {
        let xpriv_str = "xprv9s21ZrQH143K24iSk4AuKHKkRzWQBqPHV3bB7n1fFxQxitybVXAixpB72Um9DhrNumiR9YAmmXvPCdqM8s1XMM2inRiCvgND9cy7uHs1FCa";
        let xpriv: XPriv = xpriv_str.parse().unwrap();
        let xpub = xpriv.derive_verifying_key().unwrap();

        let pubkey = xpriv.derive_pubkey().unwrap();
        let mut vec = Vec::new();
        vec.extend(pubkey.pubkey_array().iter());
        assert_eq!(
            "026180c26fb38078b5d5c717cd70e4b774f4ef56b8ae994599764a9156909aa437",
            hex::encode(vec)
        );

        let p2wpkh = LockingScript::p2wpkh(&xpub);
        assert_eq!(
            "c5b0e4d623918b128716e588781cc277b003cda2",
            hex::encode(p2wpkh.clone().witness_program)
        );

        let expected = LockingScript {
            version: 0,
            witness_program: hex::decode("c5b0e4d623918b128716e588781cc277b003cda2")
                .unwrap()
                .into(),
        };

        assert_eq!(expected, p2wpkh);
    }

    #[test]
    fn it_generates_p2wsh_locking_script() {
        // very simple Script bytecode
        let script = hex::decode("0087635168").unwrap();
        let locking_script = LockingScript::p2wsh(&script.into());

        // sha3 of the script bytecode
        let expect = "fdeefecb572acb4b4a86f568deb19bf8c872cce555d4e234e3a36235de2588d7";
        assert_eq!(expect, hex::encode(locking_script.witness_program));
    }

    #[test]
    fn it_serialized_locking_script() {
        let hash = hex::decode("ae42d6793bd518239c1788ff28e7ed0c9ed06e56").unwrap();

        let script = LockingScript {
            version: 0,
            witness_program: hash.into(),
        };

        let hex = script.serialize_hex();
        // version, size of witness program, witness program
        assert_eq!(hex, "0014ae42d6793bd518239c1788ff28e7ed0c9ed06e56");
    }

    #[test]
    fn it_creates_witness_program_from_slice_u8_20() {
        let witness_program = WitnessProgram::from([
            0x62, 0xf4, 0x40, 0xc8, 0xea, 0x82, 0x6c, 0x59, 0x6a, 0x6f, 0x89, 0x39, 0x42, 0x43,
            0x59, 0x90, 0x30, 0xd3, 0xb2, 0x21,
        ]);

        assert_eq!(
            hex::encode(witness_program.0.clone()),
            "62f440c8ea826c596a6f89394243599030d3b221"
        );

        let mut prefix_actual = vec![];
        witness_program.write_to(&mut prefix_actual).unwrap();

        assert_eq!(
            hex::encode(prefix_actual),
            "1462f440c8ea826c596a6f89394243599030d3b221"
        );
    }

    #[test]
    fn it_creates_witness_program_from_slice_u8_32() {
        let witness_program = WitnessProgram::from([
            0xe3, 0xcd, 0x22, 0x5e, 0xdd, 0xa8, 0x5b, 0x9b, 0xda, 0x94, 0x7a, 0x5c, 0x4c, 0xe0,
            0x8e, 0x9d, 0x4d, 0x1e, 0x11, 0x90, 0xc2, 0x47, 0x03, 0xf7, 0x56, 0x8e, 0x8e, 0x83,
            0x37, 0xfc, 0x7e, 0x34,
        ]);

        assert_eq!(
            hex::encode(witness_program.0.clone()),
            "e3cd225edda85b9bda947a5c4ce08e9d4d1e1190c24703f7568e8e8337fc7e34"
        );

        let mut prefix_actual = vec![];
        witness_program.write_to(&mut prefix_actual).unwrap();

        assert_eq!(
            hex::encode(prefix_actual),
            "20e3cd225edda85b9bda947a5c4ce08e9d4d1e1190c24703f7568e8e8337fc7e34"
        );
    }

    #[test]
    fn it_creates_slice_u8_20_from_witness_program() {
        let expected = [
            0x62, 0xf4, 0x40, 0xc8, 0xea, 0x82, 0x6c, 0x59, 0x6a, 0x6f, 0x89, 0x39, 0x42, 0x43,
            0x59, 0x90, 0x30, 0xd3, 0xb2, 0x21,
        ];

        let witness_program = WitnessProgram::from(expected);
        let actual: [u8; 20] = witness_program.into();

        assert_eq!(expected, actual);
    }

    #[test]
    fn it_creates_slice_u8_32_from_witness_program() {
        let expected = [
            0xe3, 0xcd, 0x22, 0x5e, 0xdd, 0xa8, 0x5b, 0x9b, 0xda, 0x94, 0x7a, 0x5c, 0x4c, 0xe0,
            0x8e, 0x9d, 0x4d, 0x1e, 0x11, 0x90, 0xc2, 0x47, 0x03, 0xf7, 0x56, 0x8e, 0x8e, 0x83,
            0x37, 0xfc, 0x7e, 0x34,
        ];

        let witness_program = WitnessProgram::from(expected);
        let actual: [u8; 32] = witness_program.into();

        assert_eq!(expected, actual);
    }

    #[test]
    fn it_creates_vec_u8_20_from_witness_program() {
        let expected = vec![
            0x62, 0xf4, 0x40, 0xc8, 0xea, 0x82, 0x6c, 0x59, 0x6a, 0x6f, 0x89, 0x39, 0x42, 0x43,
            0x59, 0x90, 0x30, 0xd3, 0xb2, 0x21,
        ];

        let witness_program = WitnessProgram::from(expected.clone());
        let actual: Vec<u8> = witness_program.into();

        assert_eq!(expected, actual);
    }

    #[test]
    fn it_creates_vec_u8_32_from_witness_program() {
        let expected = vec![
            0xe3, 0xcd, 0x22, 0x5e, 0xdd, 0xa8, 0x5b, 0x9b, 0xda, 0x94, 0x7a, 0x5c, 0x4c, 0xe0,
            0x8e, 0x9d, 0x4d, 0x1e, 0x11, 0x90, 0xc2, 0x47, 0x03, 0xf7, 0x56, 0x8e, 0x8e, 0x83,
            0x37, 0xfc, 0x7e, 0x34,
        ];

        let witness_program = WitnessProgram::from(expected.clone());
        let actual: Vec<u8> = witness_program.into();

        assert_eq!(expected, actual);
    }

    #[test]
    fn it_creates_locking_script_from_vec_u8() {
        let version = 0x00;
        let raw_witness_program = vec![
            0xe3, 0xcd, 0x22, 0x5e, 0xdd, 0xa8, 0x5b, 0x9b, 0xda, 0x94, 0x7a, 0x5c, 0x4c, 0xe0,
            0x8e, 0x9d, 0x4d, 0x1e, 0x11, 0x90, 0xc2, 0x47, 0x03, 0xf7, 0x56, 0x8e, 0x8e, 0x83,
            0x37, 0xfc, 0x7e, 0x34,
        ];

        let raw_locking_script = vec![
            0x00, 0x20, 0xe3, 0xcd, 0x22, 0x5e, 0xdd, 0xa8, 0x5b, 0x9b, 0xda, 0x94, 0x7a, 0x5c,
            0x4c, 0xe0, 0x8e, 0x9d, 0x4d, 0x1e, 0x11, 0x90, 0xc2, 0x47, 0x03, 0xf7, 0x56, 0x8e,
            0x8e, 0x83, 0x37, 0xfc, 0x7e, 0x34,
        ];

        let expected = LockingScript {
            version,
            witness_program: WitnessProgram::from(raw_witness_program.clone()),
        };

        let actual = LockingScript::from(raw_locking_script);
        assert_eq!(actual, expected);
    }
}
