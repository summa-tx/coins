//! Handshake transaction types and associated sighash arguments.
use std::io::{Error as IOError, Read, Write};
use thiserror::Error;

use crate::hashes::{TXID, WTXID};

use coins_core::{
    hashes::{
        blake2b256::{Blake2b256Digest, Blake2b256Writer},
        marked::{MarkedDigest, MarkedDigestWriter},
    },
    ser::{ByteFormat, SerError},
    types::tx::Transaction,
};

use crate::types::{
    txin::{HandshakeTxIn, Vin},
    txout::{TxOut, Vout},
    Witness,
};

/// Trait that describes a Handshake Transaction
pub trait HandshakeTransaction: Transaction {
    /// The MarkedDigest type for the Transaction's Witness TXID
    type WTXID: MarkedDigest<Digest = Self::Digest>;
    /// A type that represents this transactions per-input `Witness`.
    type Witness;

    /// Instantiate a new WitnessTx from the arguments.
    fn new<I, O, W>(version: u32, vin: I, vout: O, witnesses: W, locktime: u32) -> Self
    where
        I: Into<Vec<Self::TxIn>>,
        O: Into<Vec<Self::TxOut>>,
        W: Into<Vec<Self::Witness>>;

    /// Calculates the witness txid of the transaction.
    fn wtxid(&self) -> Self::WTXID;

    /// Calculates the BIP143 sighash given the sighash args. See the
    /// `WitnessSighashArgsSigh` documentation for more in-depth discussion of sighash.
    fn signature_hash(&self, args: &Self::SighashArgs) -> Result<Self::Digest, Self::TxError> {
        let mut w = Self::HashWriter::default();
        self.write_sighash_preimage(&mut w, args)?;
        Ok(w.finish())
    }

    /// Computes the txid preimage.
    fn write_txid_preimage<W: Write>(&self, writer: &mut W) -> Result<usize, Self::Error>;

    /// Computes the wtxid preimage.
    fn write_wtxid_preimage<W: Write>(&self, writer: &mut W) -> Result<usize, Self::Error>;
}

/// A struct that represents a Handshake Transaction
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct HandshakeTx {
    /// The version number. Usually 1 or 2.
    pub(crate) version: u32,
    /// The vector of inputs
    pub(crate) vin: Vin,
    /// The vector of outputs
    pub(crate) vout: Vout,
    /// The nLocktime field.
    pub(crate) locktime: u32,
    /// The vector of witnesses.
    pub(crate) witnesses: Vec<Witness>,
}

impl Default for HandshakeTx {
    fn default() -> Self {
        Self {
            version: 0,
            vin: vec![],
            vout: vec![],
            locktime: 0,
            witnesses: vec![],
        }
    }
}

impl ByteFormat for HandshakeTx {
    type Error = TxError; // Ser associated error

    fn serialized_length(&self) -> usize {
        let mut len = 4; // version
        len += coins_core::ser::prefix_byte_len(self.vin.len() as u64) as usize;
        len += self.vin.serialized_length();
        len += coins_core::ser::prefix_byte_len(self.vout.len() as u64) as usize;
        len += self.vout.serialized_length();
        len += 4; // locktime
        for witness in self.witnesses.iter() {
            len += coins_core::ser::prefix_byte_len(self.witnesses.len() as u64) as usize;
            len += witness.serialized_length();
        }
        len
    }

    fn read_from<R>(reader: &mut R, _limit: usize) -> Result<Self, Self::Error>
    where
        R: Read,
        Self: std::marker::Sized,
    {
        let version = Self::read_u32_le(reader)?;
        let vin = Self::read_prefix_vec(reader)?;
        let vout = Self::read_prefix_vec(reader)?;
        let mut witnesses = vec![];
        let locktime = Self::read_u32_le(reader)?;

        for _ in vin.iter() {
            witnesses.push(Self::read_prefix_vec(reader)?);
        }

        Ok(Self {
            version,
            vin,
            vout,
            locktime,
            witnesses,
        })
    }

    fn write_to<W>(&self, writer: &mut W) -> Result<usize, Self::Error>
    where
        W: Write,
    {
        let mut len = Self::write_u32_le(writer, self.version())?;

        len += Self::write_prefix_vec(writer, &self.vin)?;
        len += Self::write_prefix_vec(writer, &self.vout)?;
        len += Self::write_u32_le(writer, self.locktime())?;

        for wit in self.witnesses.iter() {
            len += Self::write_prefix_vec(writer, &wit)?;
        }

        Ok(len)
    }
}

impl HandshakeTransaction for HandshakeTx {
    type WTXID = WTXID;
    type Witness = Witness;

    /// Instantiate a new WitnessTx from the arguments.
    fn new<I, O, W>(version: u32, vin: I, vout: O, witnesses: W, locktime: u32) -> Self
    where
        I: Into<Vec<Self::TxIn>>,
        O: Into<Vec<Self::TxOut>>,
        W: Into<Vec<Self::Witness>>,
    {
        Self {
            version,
            vin: vin.into(),
            vout: vout.into(),
            locktime,
            witnesses: witnesses.into(),
        }
    }

    fn wtxid(&self) -> WTXID {
        let mut w = Self::HashWriter::default();
        self.write_wtxid_preimage(&mut w)
            .expect("No IOError from hash functions");
        w.finish_marked()
    }

    fn write_txid_preimage<W: Write>(&self, writer: &mut W) -> Result<usize, Self::Error> {
        let mut len = Self::write_u32_le(writer, self.version())?;

        len += Self::write_prefix_vec(writer, &self.vin)?;
        len += Self::write_prefix_vec(writer, &self.vout)?;
        len += Self::write_u32_le(writer, self.locktime())?;

        Ok(len)
    }

    fn write_wtxid_preimage<W: Write>(&self, writer: &mut W) -> Result<usize, Self::Error> {
        let mut witness_hash = Blake2b256Writer::default();

        for wit in self.witnesses.iter() {
            Self::write_prefix_vec(&mut witness_hash, &wit)?;
        }

        let hash: Blake2b256Digest = witness_hash.finish();
        let txid = self.txid();

        let mut len = writer.write(&txid.0)?;
        len += writer.write(&hash)?;

        Ok(len)
    }
}

impl HandshakeTx {
    /// Get the witnesses from the underlying tx
    pub fn witnesses(&self) -> &[Witness] {
        &self.witnesses
    }

    /// Calculates `hash_prevouts` according to BIP143 semantics.`
    ///
    /// For BIP143 (Witness and Compatibility sighash) documentation, see here:
    ///
    /// - https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    ///
    /// TODO: memoize
    fn hash_prevouts(&self, sighash_flag: Sighash) -> TxResult<Blake2b256Digest> {
        if (sighash_flag as u8 & Sighash::ACP as u8) == Sighash::ACP as u8 {
            Ok(Blake2b256Digest::default())
        } else {
            let mut w = Blake2b256Writer::default();
            for input in self.vin.iter() {
                input.outpoint.write_to(&mut w)?;
            }
            Ok(w.finish())
        }
    }

    /// Calculates `hash_sequence` according to BIP143 semantics.`
    ///
    /// For BIP143 (Witness and Compatibility sighash) documentation, see here:
    ///
    /// - https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    ///
    /// TODO: memoize
    fn hash_sequence(&self, sighash_flag: Sighash) -> TxResult<Blake2b256Digest> {
        let flag = sighash_flag as u8;
        if (flag & Sighash::ACP as u8) == Sighash::ACP as u8
            || (flag & 0x1f) == Sighash::Single as u8
            || (flag & 0x1f) == Sighash::SingleReverse as u8
            || (flag & 0x1f) == Sighash::None as u8
        {
            Ok(Blake2b256Digest::default())
        } else {
            let mut w = Blake2b256Writer::default();
            for input in self.vin.iter() {
                Self::write_u32_le(&mut w, input.sequence)?;
            }
            Ok(w.finish())
        }
    }

    /// Calculates `hash_outputs` according to BIP143 semantics.`
    ///
    /// For BIP143 (Witness and Compatibility sighash) documentation, see here:
    ///
    /// - https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    ///
    /// TODO: memoize
    fn hash_outputs(&self, index: usize, sighash_flag: Sighash) -> TxResult<Blake2b256Digest> {
        match sighash_flag {
            Sighash::All | Sighash::AllACP | Sighash::AllNoInput | Sighash::AllNoInputACP => {
                let mut w = Blake2b256Writer::default();
                for output in self.vout.iter() {
                    output.write_to(&mut w)?;
                }
                Ok(w.finish())
            }
            Sighash::Single
            | Sighash::SingleACP
            | Sighash::SingleNoInput
            | Sighash::SingleNoInputACP => {
                if index < self.vout.len() {
                    let mut w = Blake2b256Writer::default();
                    self.vout[index].write_to(&mut w)?;
                    Ok(w.finish())
                } else {
                    Ok(Blake2b256Digest::default())
                }
            }
            Sighash::SingleReverse
            | Sighash::SingleReverseACP
            | Sighash::SingleReverseNoInput
            | Sighash::SingleReverseNoInputACP => {
                if index < self.vout.len() {
                    let mut w = Blake2b256Writer::default();
                    self.vout[self.vout.len() - 1 - index].write_to(&mut w)?;
                    Ok(w.finish())
                } else {
                    Ok(Blake2b256Digest::default())
                }
            }
            _ => Ok(Blake2b256Digest::default()),
        }
    }
}

impl Transaction for HandshakeTx {
    type Digest = Blake2b256Digest;
    type TxError = TxError;
    type TXID = TXID;
    type TxOut = TxOut;
    type TxIn = HandshakeTxIn;
    type HashWriter = Blake2b256Writer;
    type SighashArgs = SighashArgs;

    /// Instantiate a new `BitcoinTx`. This always returns a `BitcoinTx::Legacy`
    fn new<I, O>(version: u32, vin: I, vout: O, locktime: u32) -> Self
    where
        I: Into<Vec<HandshakeTxIn>>,
        O: Into<Vec<TxOut>>,
    {
        Self {
            version,
            vin: vin.into(),
            vout: vout.into(),
            locktime,
            witnesses: vec![],
        }
    }

    /// Get the version number from the underlying tx
    fn version(&self) -> u32 {
        self.version
    }

    /// Get the inputs from the underlying tx
    fn inputs(&self) -> &[HandshakeTxIn] {
        &self.vin
    }

    /// Get the outputs from the underlying tx
    fn outputs(&self) -> &[TxOut] {
        &self.vout
    }

    /// Get the locktime from the underlying tx
    fn locktime(&self) -> u32 {
        self.locktime
    }

    /// Return the TXID of the transaction
    fn txid(&self) -> TXID {
        let mut w = Self::HashWriter::default();
        self.write_txid_preimage(&mut w)
            .expect("No IOError from hash functions");
        w.finish_marked()
    }

    /// Return the signature digest preimage
    fn write_sighash_preimage<W: Write>(
        &self,
        writer: &mut W,
        args: &Self::SighashArgs,
    ) -> Result<(), Self::TxError> {
        let input = {
            let noinput = Sighash::NoInput as u8;
            if (args.sighash_flag as u8 & noinput) == noinput {
                Self::TxIn::default()
            } else {
                self.vin[args.index].clone()
            }
        };

        Self::write_u32_le(writer, self.version)?;
        self.hash_prevouts(args.sighash_flag)?.write_to(writer)?;
        self.hash_sequence(args.sighash_flag)?.write_to(writer)?;
        input.outpoint.write_to(writer)?;
        args.prevout_script.write_to(writer)?;
        Self::write_u64_le(writer, args.prevout_value)?;
        Self::write_u32_le(writer, input.sequence)?;
        self.hash_outputs(args.index, args.sighash_flag)?
            .write_to(writer)?;
        Self::write_u32_le(writer, self.locktime)?;
        Self::write_u32_le(writer, args.sighash_flag as u32)?;

        Ok(())
    }
}

/// An Error type for transaction objects
#[derive(Debug, Error)]
pub enum TxError {
    /// Serialization-related errors
    #[error(transparent)]
    SerError(#[from] SerError),

    /// IOError bubbled up from a `Write` passed to a `ByteFormat::serialize` implementation.
    #[error(transparent)]
    IOError(#[from] IOError),

    /// Caller provided an unknown sighash type to `Sighash::from_u8`
    #[error("Unknown Sighash: {}", .0)]
    UnknownSighash(u8),
}

/// Type alias for result with TxError
pub type TxResult<T> = Result<T, TxError>;

/// Signature hash args
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SighashArgs {
    /// The index of the input we'd like to sign
    pub index: usize,
    /// The sighash mode to use.
    pub sighash_flag: Sighash,
    /// The script used in the prevout, which must be signed. In complex cases involving
    /// `OP_CODESEPARATOR` this must be the subset of the script containing the `OP_CHECKSIG`
    /// currently being executed.
    /// TODO: create a script type
    pub prevout_script: Vec<u8>,
    /// The value of the prevout.
    pub prevout_value: u64,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// All possible Sighash modes including flags.
pub enum Sighash {
    /// Sign ALL inputs and ALL outputs
    All = 0x01,
    /// Sign ALL inputs and NO outputs
    None = 0x02,
    /// Sign ALL inputs and ONE output
    Single = 0x03,
    /// Sign ALL inputs and ONE output (opposite index)
    SingleReverse = 0x04,
    /// Modifier: Don't commit to the input
    NoInput = 0x40,
    /// Sign ALL inputs and ALL outputs
    AllNoInput = 0x41,
    /// Sign ALL inputs and NO outputs
    NoneNoInput = 0x42,
    /// Sign ALL inputs and ONE output
    SingleNoInput = 0x43,
    /// Sign ALL inputs and ONE output (opposite index)
    SingleReverseNoInput = 0x44,
    /// Modifier: Only commit to to a single input
    ACP = 0x80,
    /// Sign ONE input and ALL outputs
    AllACP = 0x81,
    /// Sign ONE input and NO outputs
    NoneACP = 0x82,
    /// Sign ONE input and ONE output
    SingleACP = 0x83,
    /// Sign ONE input and ONE output (opposite index)
    SingleReverseACP = 0x84,
    /// Sign ONE input and ALL outputs
    AllNoInputACP = 0xc1,
    /// Sign NO inputs and NO outputs
    NoneNoInputACP = 0xc2,
    /// Sign NO inputs and ONE output
    SingleNoInputACP = 0xc3,
    /// Sign NO inputs and ONE output (opposite index)
    SingleReverseNoInputACP = 0xc4,
}

/// Methods for the Sighash flags/modifiers.
impl Sighash {
    /// Covert a Sighash flag into a u8.
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Convert a u8 into a Sighash flag or an error.
    pub fn from_u8(flag: u8) -> Result<Sighash, TxError> {
        match flag {
            0x01 => Ok(Sighash::All),
            0x02 => Ok(Sighash::None),
            0x03 => Ok(Sighash::Single),
            0x04 => Ok(Sighash::SingleReverse),
            0x40 => Ok(Sighash::NoInput),
            0x41 => Ok(Sighash::AllNoInput),
            0x42 => Ok(Sighash::NoneNoInput),
            0x43 => Ok(Sighash::SingleNoInput),
            0x44 => Ok(Sighash::SingleReverseNoInput),
            0x80 => Ok(Sighash::ACP),
            0x81 => Ok(Sighash::AllACP),
            0x82 => Ok(Sighash::NoneACP),
            0x83 => Ok(Sighash::SingleACP),
            0x84 => Ok(Sighash::SingleReverseACP),
            0xc1 => Ok(Sighash::AllNoInputACP),
            0xc2 => Ok(Sighash::NoneNoInputACP),
            0xc3 => Ok(Sighash::SingleNoInputACP),
            0xc4 => Ok(Sighash::SingleReverseNoInputACP),
            _ => Err(TxError::UnknownSighash(flag)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_serialized_and_deserialized_tx() {
        let cases = [
            "000000000356d467a42beb935be1074ec3d8fd6a6b562b9aa23430ee748bed1fdc4710409b00000000ffffffff56d467a42beb935be1074ec3d8fd6a6b562b9aa23430ee748bed1fdc4710409b01000000ffffffffca9ce7c38ee3dbcc5cd603ceffa639b1d0d4230e8084973fd6ec14bd5997280801000000ffffffff03200b2000000000000014469da9e591a07b29eeef6ae12a3dc9bfcae043a80502203baa8478536a140099fd5940b55fa2045e26beade98ab9be518200de12d2f62304d2390000005a6202000000000014d86ea1db1bf0e7f7db41883ed45164072af54c5a0502203baa8478536a140099fd5940b55fa2045e26beade98ab9be518200de12d2f62304d23900007b54cb25060000000014416e3b4984bf055c8f49ddaf140f9daf5293653d0000000000000241e00d4e46f178eb36ceae25863ddf792217d051204d514b3198252c04fa35362c093ebbe06f4a93d00ffb84f60a590ab245275f3309238c0336e2ca4fcccd6ae40121033e56cf5178c7249523b7cecd9e97ae211260161d215844198f2b9d14ecf009910241c0011ba9de845e8f30c0935b219a9bbdb44567aa4859f90d9f24703af25344fe1062005139b2abb770cd6250f394186d5d99f1e1c755f3428c5994f2c27102f80121027c7b682cb54baf0cf8294efbeec7ad73df87e39ed2d648d51bf53229d855da7c0241105bd296cac55986094540237987452f3855810dae04f80c4f76c1dc0d4829d732defc8ec997fd2369154d3ce6b5c9dd59fb531a0d81b87d5095e851e861ce2f01210382c0fc0a676f1761602a8ade7c915926f064ac70d67019e470a3fa4ccb3f9b69"
        ];

        for expected in cases.iter() {
            let tx = HandshakeTx::deserialize_hex(expected).unwrap();
            let hex = tx.serialize_hex();
            assert_eq!(hex, *expected);
        }
    }

    #[test]
    fn it_computes_txid_and_wtxid() {
        let hex = "0000000001c20eb4c0e10f2d4bad4240968df43c2a3b2563a331f42ab2841d17d373bd2e6c00000000ffffffff0200093d0000000000001400e749452f8e6734811180df5c6119baddbae2e80000d3cff5301000000000141989e94966116f96a0ed862f49e114c456878fee00000000000002411a5c86ccab5a1d6fbbb72b254002def32429af6cd18948a0ec1038c820a7a7f2716f26980261b6ef63d5234528be7dbe802e3e0cc7c81e2f050471b0adf232d4012103d9e518a74e89eb42b24fc6806dd14ad6309433667de7a7e4dfc1039ad4938384";

        let tx = HandshakeTx::deserialize_hex(hex).unwrap();
        let txid = tx.txid();
        let wtxid = tx.wtxid();

        assert_eq!(hex::encode(txid.0), "6de399beeec5c2e9993f2c58351c57535025a991d5f1242c15f1cc18d1358981");
        assert_eq!(hex::encode(wtxid.0), "911f4ad0616acad31f8a36313d02b746835b39f3910a32eeb37a99a55181430c");
    }

    #[test]
    fn it_computes_tx_serialized_length() {
        let hex = "0000000001540a3351ba0ba4fcc41c59e0403d722e3d7b122dc0c85db640137fd3c9742bd601000000ffffffff02c0cf6a000000000000142128655de4b7bccb7f445b267bea2dcb7f4ef419030420cabb19a9afecfa05b7c5e662c9902f9a73edc024876b8e4297825f48745ebad10413650000086661757374756e6f20f2479e48358e692b20af91f6140daf18b52328046674c5035d04feb93ca484795c358002000000000014613dfb072400ef78c39d61d835dbd189fce3c966000000000000024180faf07597460da0c22ad3471fe425bcc10c053cbb42704a6843ad1fdbd60c885a7b43f7d675a2539a54f8fc26e28a9355715e8591780ad0080a80729a9b2a42012102e3aeda586bf35e7afc3687c91a332cc8bbf28d18ceba5c2e76962338b9087a54";

        let tx = HandshakeTx::deserialize_hex(hex).unwrap();
        let size = tx.serialized_length();

        assert_eq!(size, hex::decode(hex).unwrap().len());
    }

    #[test]
    fn it_computes_signature_hash_sighash_all() {
        let hex = "000000000359741074e7e43facc55c3ae1a644a22561a59f4aabf31dde696649e01a9a0ea801000000ffffffff66a4c373c7c8044a1c76e818c74e5afdcdc4c474be81117bb47bb9fa60c167f601000000fffffffff6d6018a06b684e9690878e1a08ed9f89d17576ed318188d5c7433de875ee7de01000000ffffffff02b3b58311000000000014269ad5908a45b718e1c758603d40a50ede49f3b200000000127a000000000014cf2958d6d7a2e5d1597e30bcc6930eeb7227c77203042004306304c779b5a60d02ff55a6fd337f00961daab78838a28a9a0f37d4b2b80e047e5f000008786e2d2d366f3868200ec0b3671a9915869ce08b809a2eed90072dea6644d4258301947d72e6c2e0f7000000000241f3f2c41bfca7aa1284b59032a1242bc2310b455a9d2ac32db34c5d78b249f155093172334263d400a191fa9b3fbe049ea60ae70c0c830162371c9266bfa62d55012102471bd11ad149e58256a23594f93050eae947913dc48895022fa339261b058c7102410b68bb338918623912e75c063a2e782853c472ac962e69a5f23b07c9b5ab718e32ffbc6d2bad91a60509b62cca233deae39e349aba4ee204cb5118e887c870c1012102cd7938c7817e757ca5844bcd15673ccdf2ce13e93b58e04262204d75fcc8a6c10241ebbc15a3a3ec74430bd94d8c8f4ea36bd28ba7c3125fcaef031a38788053e4da2e443a3087a093fdfc63631424645316e4f52c4b0fa700adea783f2cd1526ead012102b8619b8d174552ff061c4c83636f4d7f163546e61194b73e90b7f8d23c84bb91";

        let tx = HandshakeTx::deserialize_hex(hex).unwrap();
        let args = SighashArgs {
            index: 0,
            prevout_script: hex::decode("1976c0146d7428ea0c83eee3a74edc53a1f9a7f26ca5d5c988ac")
                .unwrap(),
            sighash_flag: Sighash::All,
            prevout_value: 503306619,
        };

        let expected = "c4f226db5b21a0948f43c856f6441f1776c3c38d4530c25006fa0bdd48e5af7e";
        let signature_hash = tx.signature_hash(&args).unwrap();
        assert_eq!(expected, hex::encode(signature_hash));
    }

    #[test]
    fn it_computes_signature_hash_sighash_none() {
        let hex = "0000000001c386080506bea816cb4039aa8ffddc8ea030fb6b63688e772d99ac9b50804efd02000000ffffffff02000000000000000000149329051e96615297625c4458b7409f2159a5a3a8060420deabd82d18f0565c889f0c1c66139197b8a46f39597c1f81b968aef6b03918510449160000010020000000000000008c6be2b16b237719616592a6bc9e45fee83089957e9cf4ecac5bba001e000000000014218fdfd77674e9017bbcfb1a08c210e9e7ea91990000000000000241013095fc724e76882e35b26cdfad6cf4709f8f220e0b544d1bc825d355d0ad804e74c60d1b5c8cd030bd6b25d6279088d2f1cfb07f2cb57d87c663411bdb11d10121034cffab06e667f062efcd04e09e77180327e57b7d1ff397f528199cbcd1f4ebf9";

        let tx = HandshakeTx::deserialize_hex(hex).unwrap();
        let args = SighashArgs {
            index: 0,
            prevout_script: hex::decode("1976c0149329051e96615297625c4458b7409f2159a5a3a888ac")
                .unwrap(),
            sighash_flag: Sighash::None,
            prevout_value: 503385487,
        };

        let expected = "cc28298ea955eaff411b0ac41f1501fd5686373d1c0d364d9ed70a6cde83e081";
        let signature_hash = tx.signature_hash(&args).unwrap();
        assert_eq!(expected, hex::encode(signature_hash));
    }

    #[test]
    fn it_computes_signature_hash_sighash_single() {
        let hex = "0000000001aff76228d91bf52f7a98abeda3dbc6fbd5be27f203548ff6bd4f20ccdb364caf01000000ffffffff02000000000000000000149f47b488384800241a78d5bdbde617793e7a29d30203207c2281715d76b07d095bff217a6ab814bfa8bc404ca882029ad3814449d06c27040000000006676f64736f6ee25b0e01010000000014bac40ffed48c922fae735684344ec9c82a4b9f21000000000000024143b9ac90498c72f95300a05876efbdb6dff598974e12fc7305934701624b0dd35e380c9e0c529146af347347ec8167a03451b1bbbef0e498f800f2daaf583e38012102dced47acc9fa655459349a35cf66d4348006d58fdcd3c2ff91b310e8e41dd9eb";

        let tx = HandshakeTx::deserialize_hex(hex).unwrap();
        let args = SighashArgs {
            index: 0,
            prevout_script: hex::decode("1976c0149ef33fdf7c4a2e6b37bf462c55de2dc945b5bedd88ac")
                .unwrap(),
            sighash_flag: Sighash::Single,
            prevout_value: 4312704038,
        };

        let expected = "c286ea11df23aebbede3dbc06daf9a93c348f2e4182d047a47f73d503e1d7d91";
        let signature_hash = tx.signature_hash(&args).unwrap();
        assert_eq!(expected, hex::encode(signature_hash));
    }

    #[test]
    fn it_computes_signature_hash_sighash_singlereverse() {
        let hex = "000000000257ae2ab7b9e1b0db12153ea5b950e6dec09e50bf5c5462a6055834cd7641bb9d00000000ffffffff6a7b2a7a009830a0c443fcaa85c2d23cbed36d9178e0dfba0b5110da414afe6f00000000ffffffff0340420f00000000000014dcf0d847d82f44a99617c9874dbee61be407f77b040320a8517d813dff442cda98ab3de307a036c71bbc917bc79597838ec473346c42f704a062000020ad15a53dbd23f0d8c331aa062bb1729e32750ecd0c55c435911db14da2aa53f980841e000000000000141ecdea54e9d6368f57dbf20c7c64a1edb7abeb6c040320a8517d813dff442cda98ab3de307a036c71bbc917bc79597838ec473346c42f704a0620000201fbab5be2b624e4a8076ea374d132567964aabf61be1129405b157622fa98597f04e1600000000000014040e3d0b4e919766bb325a3c9e22b571b90f291000000000000002413bd7f713cf93bc2ccddb97b50c41b81564880ba932528bd6971e8388cecab3aa1b682e0d0b471606e3629145eb86631e3f088962630e5e972a4b03da9ae40980012103f293988837beafa996e7c9d8a2c402dda5ea69ffa945ffb2f74dac06324cee6502419ca51afb85a7c1a45434fc6c31a587be34971c86e9a248470632b7ee04d90ad55f16439960fed232858ca5c195a1e4da1dedc0e5d1e374d2d01a60fbad306896012102bffb1c9205fb1f690366149a6bcc45858801381f68b6ba72cdd656a47a938bc3";

        let tx = HandshakeTx::deserialize_hex(hex).unwrap();
        let args = SighashArgs {
            index: 0,
            prevout_script: hex::decode("1976c014dcf0d847d82f44a99617c9874dbee61be407f77b88ac")
                .unwrap(),
            sighash_flag: Sighash::SingleReverse,
            prevout_value: 1500000,
        };

        let expected = "9f4320c7874118ffbbc1ae8af9d57e98a3c04aa1bdecbefd52f077047f5da861";
        let signature_hash = tx.signature_hash(&args).unwrap();
        assert_eq!(expected, hex::encode(signature_hash));
    }

    #[test]
    fn it_computes_signature_hash_sighash_all_noinput() {
        let hex = "000000000651f62efaa04642f5b22212907206662e2e8fa70ad77853632fda741cfbd1c07d00000000ffffffff833b38a2860df9f7876dc98fced731c7f61db725749719434623b8437e94080200000000ffffffff6d09cb87f7ccd8e4a3990c34fc20a7485c59c8048831c4736aca301bae27168300000000ffffffff4a9217969024349ba4d4f70968247c8598083da056408eb63ed98580c633767600000000ffffffff9b8727257fab721377879f58aeface3ef3c8f8e9b258ea3d97ad6f5b64e59ab300000000ffffffff866aa970627dc1d86c60fe495505c1c5cfeb67a5843883788aedcca54f391d6600000000ffffffff024d4631cc0200000000143ef6a017a2671a4e6b45f5adc0676df02e5162dc0000c2730100000000000014b572753e278326781765320a2509f0b1a1d71ab40000000000000241ac866a8c87e3b65568a08bd9e498b6588ab5689f814748ba91d7e0019363da28611dc5b0b28e0711e9b9ac49f331331ec875f4cecd99b3bda3ea7b145cbf041d0121030ab22a041ba8eb1a6567d250bc313f32e3b3c13ee0c719110b76f93df8b61b7e0241cc6a48edaf4559aba8b18c8296d9f37959c963120c0d5de353b026732265a3ad07f8850002d18b2864054a8cb8fb998042be35bbcb870c974c4dc8661caf15b90121030ab22a041ba8eb1a6567d250bc313f32e3b3c13ee0c719110b76f93df8b61b7e0241bccfc58850279198f116997d247a8881fbd12c26e2bc4c0fe6595cd364e341bc66a89e06d9b9bb3f7c25dc31895b79f0f64b8bd8b268934fbe7ddbaeebff023c0121030ab22a041ba8eb1a6567d250bc313f32e3b3c13ee0c719110b76f93df8b61b7e024116e244c0730fa62f4ef7e6c045d24e958750cc5e1c3fb6e5548de3d6b5d800e8107fb9b039687e676f8425dc5ea5dae39a55adbac736367d0fd03f37630527880121030ab22a041ba8eb1a6567d250bc313f32e3b3c13ee0c719110b76f93df8b61b7e0241fa68cdcdc55e993a50d5ea8094aed5fbc85d6fc5127f4e28bcd0bdd28bec92fe7062c59916e420e373455dfcfb1ecc70f7c5c42ad2e70df2bbc8b9b1d5cbe4f80121030ab22a041ba8eb1a6567d250bc313f32e3b3c13ee0c719110b76f93df8b61b7e02414d8914605bc58683330472f1f81b6092c80f580147d9d5700ac738537b19398b2fb07883968bec56b3b3daa423e6a1b64449f0786931856d3389cc97953d8daf0121030ab22a041ba8eb1a6567d250bc313f32e3b3c13ee0c719110b76f93df8b61b7e";

        let tx = HandshakeTx::deserialize_hex(hex).unwrap();
        let args = SighashArgs {
            index: 0,
            prevout_script: hex::decode("1976c01498c8297a67eb81ec36253828b5621a601ba2328a88ac")
                .unwrap(),
            sighash_flag: Sighash::AllNoInput,
            prevout_value: 2005260900,
        };

        let expected = "3eb4a929e0283c7e3d6757637ebd58c5524cc74a787a2b66a798c0462e2b14d4";
        let signature_hash = tx.signature_hash(&args).unwrap();
        assert_eq!(expected, hex::encode(signature_hash));
    }

    #[test]
    fn it_computes_signature_hash_sighash_none_noinput() {
        let hex = "00000000035ea36f1c424c2197c67aa6a917a05f9dd9aa6f70fa2e5efeecef0c2b4a1caf5f00000000ffffffff5ea36f1c424c2197c67aa6a917a05f9dd9aa6f70fa2e5efeecef0c2b4a1caf5f01000000ffffffffe8346f0da97a47de4721db44c7aad088f1bf0afd830164c6a5b8f175e54bf95103000000ffffffff03102700000000000000142d355655e690be3f4aadbbff13622dc0226f991f050220a2a6575baeab5044bc7a44e39bdc9fae9c59648186c1320527237a52da00760404cb5c000020a107000000000000148828a327f926cd070ced136e9891a0bb5e056b10050220a2a6575baeab5044bc7a44e39bdc9fae9c59648186c1320527237a52da00760404cb5c000063cb85350000000000140f9d67354b027aba882a2fc53bc25d2f00c3aedd00000000000002418817b0f7e48c39eb735a63dc54e4d56eef3fab783526c7a267bfe906f0dc70c55cf57c0acd2f7ee0e5fcc86a773721276ccbe9003378f79b76edf79f98f24df2012103a26eef827f8a6bcb2778e53e4e92ab2b6bc69ee91d25ce291a5018dd8e1c2a840241c33cf6ccd4eda6ca4bdc44399a9cff53274089a9ee8fe5fdc142e463837019d00517f2bfcf11575439a5fad28de751f1ff8aa46587fd560c39adcc51b82f81970121021aa2ccfd94cf63886e4bfa234ca8fd92979ffd2cee52f4b71e6342dffb2b4a8d0241a27e12c14b3f5837b4e98ded9c77e913c4e6572e3b36a0371ade7aee1dafc2f605b59a93fc660a60584cc789233e717953536c8be7d1e67ef4d539350cc65e62012102fdffd36225e6f566fe104c1ff65c02a3f3dec209c16bfefbe7b5fd435b43c828";

        let tx = HandshakeTx::deserialize_hex(hex).unwrap();
        let args = SighashArgs {
            index: 0,
            prevout_script: hex::decode("1976c0142d355655e690be3f4aadbbff13622dc0226f991f88ac")
                .unwrap(),
            sighash_flag: Sighash::NoneNoInput,
            prevout_value: 10000,
        };

        let expected = "18799a272c12589cd703967ee94c73d1be97649c0d1340391fa09795f50d549b";
        let signature_hash = tx.signature_hash(&args).unwrap();
        assert_eq!(expected, hex::encode(signature_hash));
    }

    #[test]
    fn it_computes_signature_hash_sighash_single_noinput() {
        let hex = "000000000234f727e5972ba3880494a3ed492edfbf4aef9ab774fea8fb00502ce6c5aec25e00000000ffffffff278e718537f6370323f640fa55c44f126f0182a431e2615f01899e3adcfd35d101000000ffffffff02c75e4c00000000000014c0113093a59a0eb6f4854d92ed3c8e0477d5bdea040320ac500b43e157caf2b13384659a372058debecaf90aa8878bde5d82292a7b0cff045263000020269329db0a02eecb01344162db9d7d99e8d15bcf70690b11f82341edf94edad36025a9f408000000001429b09108318823ac5d043f7a74dee51ef52e1f230000000000000241cc971ca92e2f7dbbd4a94824f8ca16a19148038c801f6a5083dfb3fa3df5d40065246f86df1a6388e0baff5e9196f17aedbf252b51d34bbf4a7652475b292087012103c192e7ccc68b41f8951a897a739fdf08e43cfeafd19b2952c728df4dd13ff7770241a9f0cdfdd731d3c1e951fcabe5abdb894666a2cded0eee7bf01d214fc70188e83e6c70a12a8a781130a8b536528a73eb4424bcf5810be39c1f71fa255a57f6f4012102a4efac2c002a3a39c1c347af7ea8742470941c325b3c33a497f5e92b39a8ebfd";

        let tx = HandshakeTx::deserialize_hex(hex).unwrap();
        let args = SighashArgs {
            index: 0,
            prevout_script: hex::decode("1976c014c0113093a59a0eb6f4854d92ed3c8e0477d5bdea88ac")
                .unwrap(),
            sighash_flag: Sighash::SingleNoInput,
            prevout_value: 5004999,
        };

        let expected = "e759858e74d5e69fb1703348fa21eeb6be1531784990ffc0a3e905fadaed5134";
        let signature_hash = tx.signature_hash(&args).unwrap();
        assert_eq!(expected, hex::encode(signature_hash));
    }

    #[test]
    fn it_computes_signature_hash_sighash_singlereverse_noinput() {
        let hex = "00000000022721a2f5b5eaf032d7d4ec8fb08c0b833cec53e9ceacc26baac992356b42225600000000ffffffff7c4abfab62d86b15e588237d68ef19cc36e58f82770e78b74c8f9a877101e18201000000ffffffff02c75e4c00000000000014a646dd759b001e4f1d443d698892dfe33e8a59bf040320a272cb07f4343c2cae77dabe4b001af36bd315b0b890161bdf1768bf6d335fdf04546300002027372f228faf5957abca71d3a266f582ed0a9db78ce4ad1ad8a342bfd4d36648f21cc54600000000001485853b72ec46ee925b0dba36a5401b58881cf8de0000000000000241d072a730fdf5272ae08ca5087f3834497fc2a30e7696c18d02d286e147b690653f05935ba25b5328f56f448a5bf28912013b4657acefac8f9db7c6c2939fe71a0121024561d5a46f16b44fab5b1d7af15e5ac82d51af185d337467a9e8ab7be4e5362a02413fe9e964b61b62ef4ff639588583be63466dee87cbaa513a5e2aedd2c66770bb47cc1ef89f46e6bdf96aeddf8fa55d252f6ed7060ca3d30fe004cb12e11dee8c0121026a429e727da92513838d454a48859fa1ea0f33d9401d6a45c8363c16232d0fa0";

        let tx = HandshakeTx::deserialize_hex(hex).unwrap();
        let args = SighashArgs {
            index: 0,
            prevout_script: hex::decode("1976c014a646dd759b001e4f1d443d698892dfe33e8a59bf88ac")
                .unwrap(),
            sighash_flag: Sighash::SingleReverseNoInput,
            prevout_value: 5004999,
        };

        let expected = "a2722b88db66fae11494e1d4b113908736f68755c763e15e3bd51ededc16851a";
        let signature_hash = tx.signature_hash(&args).unwrap();
        assert_eq!(expected, hex::encode(signature_hash));
    }

    #[test]
    fn it_computes_signature_hash_sighash_all_acp() {
        let hex = "0000000004ea1b0111af309537e0d01b45784296aee7720d5a99136e3830c916cf9cd9b2e600000000ffffffffea1b0111af309537e0d01b45784296aee7720d5a99136e3830c916cf9cd9b2e601000000ffffffffea1b0111af309537e0d01b45784296aee7720d5a99136e3830c916cf9cd9b2e602000000ffffffffc56d43037ceca5ed0eed2d00fdfb13446cccad33b3dba3ceec55002a93b069f004000000ffffffff048096980000000000001431437ee12898865eeb61505a16516b78f821e19b05022090fb0644f0a2fc780de9e9597e2669fd2fbf041af1c4a153e94314df33fc9338044d5e00000040420f000000000014f450fd99203c59c19942e87d141e934c2dbb735105022090fb0644f0a2fc780de9e9597e2669fd2fbf041af1c4a153e94314df33fc9338044d5e0000c0b60600000000000014c798cd1a71151b71442452039b14fb35f57c8d7a05022090fb0644f0a2fc780de9e9597e2669fd2fbf041af1c4a153e94314df33fc9338044d5e00000c8624e700000000001481ae8d9daff682cb2b1c7833eccc6ead90010be5000000000000024101b73d5911101132a550c37a966aaa965a81d6c8d675ec6ffaa0716194604e9c2a75377f5928a7adb2f3da2bc777d5f48491471a9ecc160e0708037836044727012103745f0c21912db13a50646265efef3201d12128f717c01ce95d817469a2b3f28c02413ad6dacc6c452bcb7b481bc7a99dfec162ba6e5406c2413ffcecb1f25cc6ccb217424375dccb1b9c4504ef59d23625019d59fa2077793f168450932a62b4b449012102b86a5ad5e7d70cbdfcdb54d4dd0ade1728e33ce8bfb088416f3093b9ffce709d02410f40c33ea8ca3af67fcf7a35e5410aace840ced6f9a4332ed45428fae7b036b341fd765b64c54687c44c0b3b8d3eeec2b391c7e4c5b134789e779beea9488813012103f04991e6aa992645569d0662204c3bdb47b7e76ff04b5f7c0da42dd104a4e81f0241be8693cd69149e5cfd3fcf8a748ab69fc054c3a8a755e0ef8a8c3906dc095be01f14713620fa20feb90c234015ab1597d5bd669daadd5bbfe8440d525abf9c94012102490ac55deaef03921eb451e73812631a8564c21d8dcf37c3a836ff43ec829cc1";

        let tx = HandshakeTx::deserialize_hex(hex).unwrap();
        let args = SighashArgs {
            index: 0,
            prevout_script: hex::decode("1976c01431437ee12898865eeb61505a16516b78f821e19b88ac")
                .unwrap(),
            sighash_flag: Sighash::AllACP,
            prevout_value: 10000000,
        };

        let expected = "c650b5a5329f39d065845adb407dcca151dc7ceed1a1f2932f4c2f77704dc6b8";
        let signature_hash = tx.signature_hash(&args).unwrap();
        assert_eq!(expected, hex::encode(signature_hash));
    }

    #[test]
    fn it_computes_signature_hash_sighash_none_acp() {
        let hex = "00000000033a32d87a03eb3a064bf8d9103532b9346f8feb864a94990871a6f4c2ad82862d00000000ffffffffc301c347b678567b25fc3d2c627bc602453d59118b6dacd65ffde3be924ecb5f00000000ffffffff8aaf9369ede1dd489d9b6381b4883419a305c4179090c962738a5e2e96b3203a01000000ffffffff03a01a1404000000000014ca26dec0d3001bf16679c57af6c4fe0382b66dd1040320c698822e130fd77d42a6ecdcfc41dfd7ff8c6d48f07c0318574e0e4f735df157043b64000020cc128acc40967561f02eed185d74e147a23dad87614755b3cd05064f24747ad478135100000000000014798fdca59cb131e0f23efd376d10565cc766a12a040320c698822e130fd77d42a6ecdcfc41dfd7ff8c6d48f07c0318574e0e4f735df157043b64000020d82441d0ef6b69f8e5d81a45840f3d35e8975e5309ef47342b895dbce1305c3036dcda010000000000146397b7d691ca4f9f0e721e643782ddbe80cae0c300000000000002411eef47e957ae441bbd93166d36f11947d47c6edd550f8b3a0fc726ce98d3411171fae32a09e6f3b442071ff37057d2e47956a38605449727ebf8eefc2a37496a012103b5bc2fefdd584482dbd3b5eeba700cc35968ffebb4a22830303edc12a3366b060241e12a3023a61f84f2fe66711ed5e787eacac5a58c9fe9f21a82a80509406a36a35bc97eccbba6709f556bb40dc49a330db82423b08e6fb991cab01dce25f28fd3012102927552c928aed25c544ed6cdbf2fd6789fe5bbe02c1ec228da5ef886327c91b60241faa546f0821c8904c7d853e7cd6347db53880bf767369a9081852beac5b5fd583bb2e1d12b8aa66f9f90b97144a698b07bd9d166e43886a8b04c0c73bdcb19d3012102ac263f0d623396cc0b29ee5b45573188ddfa4e5bad9150ae64cbf12a6fcdf16c";

        let tx = HandshakeTx::deserialize_hex(hex).unwrap();
        let args = SighashArgs {
            index: 0,
            prevout_script: hex::decode("1976c014ca26dec0d3001bf16679c57af6c4fe0382b66dd188ac")
                .unwrap(),
            sighash_flag: Sighash::NoneACP,
            prevout_value: 68426400,
        };

        let expected = "7b188afac059d4e00652563b3404fcc17f6d50efddc13197b9b462afba809fb7";
        let signature_hash = tx.signature_hash(&args).unwrap();
        assert_eq!(expected, hex::encode(signature_hash));
    }

    #[test]
    fn it_computes_signature_hash_sighash_single_acp() {
        let hex = "0000000002d460e4eadc6791e812b077b7a699329e1e2e3eac6843bd70ff3207a86941d1f800000000ffffffff558912bc59f9d78226ee790d6e8891ab840262d8212f7b09da588d9532ea088001000000ffffffff02b07e58000000000000148c1b0a949896e1521d01e2386629047bd898dd850403204acaca26264823f0c7a7f365e6e1a2fdd9e9ef4d1c07c58fa83fe163679e6373043b640000208b1f1301353ab7ba3cd4213431cb53bc8e8c5d9071deb3bead02e542928031ecfcff39010000000000141e004e16713bba3df318814999c5186e76fc2af50000000000000241a8e15a2e590916481eb5d88e056c97777899af323158ea5dab0962eea6908a6457fca1636ca130b91959e7f8ffd900491afe41fb5405f8267020893555cb6fbd0121038ac06c6258844de34d4fda1a76a56e5ed33f77b33521aba1cc29f6ca1cf709f00241e7854ba5de2b9343e8c4cdca6e849f41ac14ef9a444b572a25ff7ecf2edb24687b1403bbd771be01854f9642de7703893b1eff49683590ae26d725cef8c6f963012102fecd535227f0c8898d38b002fc58f0648088bfdc3c8673cad30ac712dc8274a7";

        let tx = HandshakeTx::deserialize_hex(hex).unwrap();
        let args = SighashArgs {
            index: 0,
            prevout_script: hex::decode("1976c0148c1b0a949896e1521d01e2386629047bd898dd8588ac")
                .unwrap(),
            sighash_flag: Sighash::SingleACP,
            prevout_value: 5799600,
        };

        let expected = "4cd708a5bbc4a9f27aaf18ec99e5efb7b80cb162a409ffb69f360165348a34d3";
        let signature_hash = tx.signature_hash(&args).unwrap();
        assert_eq!(expected, hex::encode(signature_hash));
    }

    #[test]
    fn it_computes_signature_hash_sighash_singlereverse_acp() {
        let hex = "000000000282a6664930c7472446bcfb2682d652f1b9402953558116282b4f0e83436dc0dc00000000ffffffff3199dedd034c8dbf85a57b8b2d854ab60bd328667e5437758ecb5a019658ce6f01000000ffffffff0208c45100000000000014282fa7c6a30266295f9d050284af57578dac4f33040320c62cc7b03dcf0f3c38637d996fba443db8b22922823ca25a39b2762ef613903c04396400002062157a465dd68acbf3862978365780e82a2e80bf14a3bf1452dca2bc6aec3643eceaa703000000000014b9520cae8b3a18a74adf39459904dc3e0b7318c700000000000002415839c62cf3419ec8edfb1f6c74b8b6441621fb9760602571a8e7117b6009c082540101225fcdc32932e4d3ccdd0cedce616b55d870fdd7cf1c4930996226527d012103e34e5e9c757a24b0ac972c64596b6f19ad9bfb8084ed55bf8ecc209d70f548f00241595206fc75983ac5b5ca5760a0167d89fc1e8856d4559275681c056a19c64f491a0ea9e4e7aba1665a5673aff152b7188e9a99a840609ffff38925e5ee37deef012103d07dfdaaaba732664f7d85235e24fafe7e3a6d9e9949bbbc193054bdf4c796f4";

        let tx = HandshakeTx::deserialize_hex(hex).unwrap();
        let args = SighashArgs {
            index: 0,
            prevout_script: hex::decode("1976c014282fa7c6a30266295f9d050284af57578dac4f3388ac")
                .unwrap(),
            sighash_flag: Sighash::SingleReverseACP,
            prevout_value: 5358600,
        };

        let expected = "6db11c454b3185143739a1110cbbbdaacd689290cc84fc4ff53ab1cf7754bec2";
        let signature_hash = tx.signature_hash(&args).unwrap();
        assert_eq!(expected, hex::encode(signature_hash));
    }

    #[test]
    fn it_computes_signature_hash_sighash_all_noinput_acp() {
        let hex = "000000000355bd0fccccb9ddf883c552bde19d17b8185d4cd39e910fa1c01085dfbde7139f00000000ffffffffcb9c674805d94a797f3ee41b61f6d2ec18666a3f47f5f1da523a5fb63e85db4a00000000ffffffffd673b312152807ca4d6eb9f5ff9bcd4bb56514d81f12a6fbd20782c7926c948800000000ffffffff0490410600000000000014aabc402d54f4b5455614ee56e0eb6c6b4e4374cd0403206a7acd3414e78d07f7201421c19515df98c7147c19e2da9b327760fe2d9974010424640000203eaaa69e3651448d2ec7a54c225dbf1dc7fbf420744fbcbdabf4f4a2aa615df4b749c600000000000014475da12722432489aa7c4d8bf526312c54e129800403206a7acd3414e78d07f7201421c19515df98c7147c19e2da9b327760fe2d9974010424640000208817c85b7a334096005b18a8cd7bee5c6b75a4424ecb31864391af4ddcae4a51000000000000000000142ea5bdea40da76a8019895804413dd5ba7436c480403206a7acd3414e78d07f7201421c19515df98c7147c19e2da9b327760fe2d997401042464000020e6f72c93116d29350c2fb2f688704f97260ec7a6f936ec4176d946641d96694323271801000000000014c716f3602b246808169615b971c74c1ffb1d525f00000000000002411605e331efbf5bd092aeec5956064728399d9e2d5c196aa8ec15fd842f66a3f573dd6adc1ef366359f44d5d7656a34da49c4115061756a5a635bd5b50004205a012103a390c961d7377d643eb80587b0f24bffd92bc6adeabff7106a8dbb78c139b4ab0241e2cc97e7c5a8c1dcf100c6c9c2affe277a526b6f40c1d71cfb9f8a13645980cc3c756b3e65c87ddeb55aeebd2ed2fe5edeae5301fcfd44e0bbaf388e7d39d84d012103bc397c2e526a46aad82956a9b4b4178874e7447aaef658fc5db79c25060853b10241cc9eaa36842f688d43adaf51c91476e3cfa645c5d9cf1dceab83d875db040dc5348707d65e7d200bea412375ef6cf630c736c816b9b2a100b05048e6884358d801210206e8045756d909895abeedce3be9f66079f295549fd8c87cc8035523792417a8";

        let tx = HandshakeTx::deserialize_hex(hex).unwrap();
        let args = SighashArgs {
            index: 0,
            prevout_script: hex::decode("1976c014aabc402d54f4b5455614ee56e0eb6c6b4e4374cd88ac")
                .unwrap(),
            sighash_flag: Sighash::AllNoInputACP,
            prevout_value: 410000,
        };

        let expected = "c84c24aca3c207d5021bff5d81e98c61b5d1810f2a4ea2f077dcaa5af98a3979";
        let signature_hash = tx.signature_hash(&args).unwrap();
        assert_eq!(expected, hex::encode(signature_hash));
    }

    #[test]
    fn it_computes_signature_hash_sighash_none_noinput_acp() {
        let hex = "00000000034f68be3fd13063184fa6839e092d3c129d60de66e6cc13aef7b05dcb9b1eceec00000000ffffffff55a3e584373e6e1077c27abebdb1583253bbcfc7c9165ac7dfbc9aa04ab4f97900000000ffffffff563b90ab8c53ce34f3f10ca22110b9a1f0850ae19c3ba3920e02a92d55f0d7de00000000ffffffff04f7795b000000000000144f9747117b3992c7dc0a09ae427c7b78efc731dc040320af90c469d01b6d649930b867c8925146c0a909ad232f6c580d8985f8830ec39c0425640000204e389cc47c119e895bf84c48187dfed9db911676678952bbd5df26a6211f250e801a06000000000000148ef64ffd162adcdec80d5070b0c47cd42b620f5f040320af90c469d01b6d649930b867c8925146c0a909ad232f6c580d8985f8830ec39c042564000020a2ef9a1930f6d76179ce8ab669a2a9b9ef4692f1c45595a9b9fd9cd16a966672406f4001000000000014a1e7aa3f7cfc1fd27311c494aec90a148c8a243c040320af90c469d01b6d649930b867c8925146c0a909ad232f6c580d8985f8830ec39c042564000020193cffa630303c607637709c128239e217b26972baef624c541480dc699848721cd1ca060000000000146de55c16b98e9f7678f5ac557e88cbf7120951460000000000000241afc9248c0abf0ab623ee8900dbb1d9ae7ea28737015c98fb2abf88b6dc31f50444b9a56e148ec0878525795bb51be139b8b6b54c0cbbc53b4fb4799c359c8d77012103b145bdf47724a242a40587047c52b3695b5c74a610c39a635d9743adb5172eb90241308ad7210195bf085c7cbb2df9d0177f8bd641986dd4f130123a43e62269002427fec64f6c16ef78957b31ee7709cc4b8429616787e447ace89b46af78976682012103585f141f518f4a617a9fe4777f6ca86a5b0dce9fa2001b460187e83439d9741502410ef9ef755b2799bcb458d8260be81138e18614b3a0de6ba62f4d9bc25c5cf97d11cc59cdf39fb13aa0012078287fdffe9335e986e8a9202462cf262407cb9e51012102923bb5a409208e5641dd256e24b6e0a144ee2f3a12d840bfae648e3ae9223f89";

        let tx = HandshakeTx::deserialize_hex(hex).unwrap();
        let args = SighashArgs {
            index: 0,
            prevout_script: hex::decode("1976c0144f9747117b3992c7dc0a09ae427c7b78efc731dc88ac")
                .unwrap(),
            sighash_flag: Sighash::NoneNoInputACP,
            prevout_value: 20004999,
        };

        let expected = "23cb231e1bd7206b4a33cb4cb1f6871637d3423daac07731d1f7bfe4e8b5bc7d";
        let signature_hash = tx.signature_hash(&args).unwrap();
        assert_eq!(expected, hex::encode(signature_hash));
    }

    #[test]
    fn it_computes_signature_hash_sighash_single_noinput_acp() {
        let hex = "00000000032eb69d73697b7e836e827d7688ed139477390d7d89f43ab773471b17bf1a7e2500000000ffffffff43647786be16cd616230d3414963fa3812d72bbd5cb6d292521462179c97abf900000000ffffffff7af1678cc75352d82fbe77b699c1e0ebb7e8e6be0e93a3bcbec6b60f005025ae00000000ffffffff0420a107000000000000143dd4ac1cb78168168c95bed0f615e00b24bd0790040320c4baebdd06f2039f77c2eb333928366811df412c54ad59021d16e1a591578f6d042664000020578631de928bef45eb5759e21fc4f2c8a2e7db7fe539cf38e7dcf04112fe7bf540420f00000000000014cd2cd152ab589223e0c55734c25b119b6795f9a7040320c4baebdd06f2039f77c2eb333928366811df412c54ad59021d16e1a591578f6d04266400002028c61298eca8e5339ad4da02f02f9c68c141ff72105a62bc15b378cc5abf566920a10700000000000014ed564f51be0ef4d9d92da4393f8fccf7a0413de7040320c4baebdd06f2039f77c2eb333928366811df412c54ad59021d16e1a591578f6d0426640000204b0aef4bc7435886f9bf1f155417f2acbe240a735e66aa5ec1987a3095bba0e94cc8e505000000000014d02771d4d09d3f1e91c2069f849a170006b415670000000000000241f3b9c180cf14d33030e8c9cf80f1fdee3fc2aaa3324400015624b15824c11f4e3df4070e97e4195dfa11241d7f04f18be6536e2a1edbaeaa2bc0615843d6a9ac012102910abdf1f1c36819b60e9cc74701c8f8db61d2e51e14d9dfe26efc90ff379f84024122eb155d7056612d4710839bd2c9e12557993be841f51c4c3ec1ad7a6186cbe15f28269530826e086c23e1122324c287ee5dbb3a4b485772e5b1d6e56c03acf5012103a84aef0973e5e4e3af33ba34454fad1b3cfb4b18d5f92818bf04d51c3c121c690241987d2aa2db0ec522e7e2755a720ea0ff995974b74f1e897068d30c7351af9aee44e0613b4fa97c6f2e693cfaa5960c675f75850c2ea280dbd6745b4444ffeea2012103442f431406f47373b68a01e8a25d4a3148b75c03ecbc036b29a3c687b682dd9b";

        let tx = HandshakeTx::deserialize_hex(hex).unwrap();
        let args = SighashArgs {
            index: 0,
            prevout_script: hex::decode("1976c0143dd4ac1cb78168168c95bed0f615e00b24bd079088ac")
                .unwrap(),
            sighash_flag: Sighash::SingleNoInputACP,
            prevout_value: 500000,
        };

        let expected = "4e496c67237a7caf3678326b20e3dbb982418c44bf83cbdcc5efe8e53414831f";
        let signature_hash = tx.signature_hash(&args).unwrap();
        assert_eq!(expected, hex::encode(signature_hash));
    }

    #[test]
    fn it_computes_signature_hash_sighash_singlereverse_noinput_acp() {
        let hex = "000000000604d78865f1b636d762dba98e4291cbf84dfdf695e879b0435995218d2e2e1da400000000ffffffff17a146d7cbd053931d4672bf7d3be06182ae09af40e606119e6e956bdbbaf60300000000ffffffff1ee121cfbe146755590d98c44cf6ef782b33fdbe465efe20a6cca9b02881cc6000000000ffffffff54fe06d944142caf93ae0078e1a3676a66f53162ac7ed9f66d7ff634dd3d574500000000ffffffffd93091b2453a726383f2ae2400439072c7177f8a46fb14e95f87f1d720b6468700000000ffffffffefe5557fcc167e0820befca88de11a4c8cc5bea23d5e87885bc0f62ea50618df00000000ffffffff070046c323000000000014cb884746bae24846a6139160b2abc34d256c5e9704032044c18293656c247597137316319018ecacfb01f89df7fa5f98fc2149602bfff20426640000204ed9f299d1fd7bc3ee2a07b28aa06aca866c2caa9878c799fdb20a68caee3c8480eca7090000000000146253b792216f4910c54d60dfbb159e8b90b7bc2904032044c18293656c247597137316319018ecacfb01f89df7fa5f98fc2149602bfff2042664000020212e750b3dcd7ba15dde50740bc63151f9a8c19e7a76b749615adeecda62f83940420f00000000000014c575a10930cc1bbde77f7ff5e6afaa2273f43f8504032044c18293656c247597137316319018ecacfb01f89df7fa5f98fc2149602bfff2042664000020f27567f2b9b717792bc0e540251c91ef011dd783782c3abb5b20acf662fe08d600e1f5050000000000142b3c630d3c5ac1faf119becefc3501c77c22a7f304032044c18293656c247597137316319018ecacfb01f89df7fa5f98fc2149602bfff2042664000020fbebddab6bd45e1e2e7e1dad130c39d5e3971ae05e96b7d218df1132c5c5d63f801a060000000000001430c950b6882b33cdd00ed803e5d9b060319f4d8804032044c18293656c247597137316319018ecacfb01f89df7fa5f98fc2149602bfff20426640000201dd4c1eb44892b966c3fe8c64bd81d1badd7efe00c65251bac44d0a474bb461d80733b0d000000000014b5be4473cf3e210bc4d2673dab6231659d202a9004032044c18293656c247597137316319018ecacfb01f89df7fa5f98fc2149602bfff2042664000020cfa67c3a3382f1849a561ada00a60cfa4db71d31b9ad633bb3a2e7579e414bff60df622b000000000014e69e55c6f62997625b960b2871535840c8e4c7bc0000000000000241fe7337483561ba9222cbd19e52ca379db8ae01ef792b41abfadeea702b3f15267a359b1dfc2a10965adc6be48d36e84e5c770de01553c28c68da0642ebb19340012102aa325289d2ab059baed6dd6d1dd515238fae586fa775c51c3567b66b1e360fcd024147489055bebdae01811de39e7ccdaa806093de4b2e5ac82817f10f5ad85678263aa37615b583806c6739de6bf54e2bf9eed91551524672e9b4b5cd5d24653931012103dfdfee945e0de2e43648b1e1ae41c9508ffdd29efbb2a83de1cb5275510e1e670241a0ecc2471ff8d67bb6b07c8acd67e28aa918ad5bb4090ffeaf92564c9e169f8874574f24becba6ac6e65d13a90160cf5d6756aa8d39e5e6a83abe209b5da56480121025cbc34caaf3c38ee902ca390f778f15b0b8a48dcd22e9fd53f1caf146beeee6a02417f103ddf07d1cdeb7fe555ac1969fc6e63315efd3b03f0061c8190232b77f00368f89dd1d3d5100e11188061ffd47a061ed5327a641862fbe5b15864d5dd4e300121038a9af3c257ed50a1997a7e7949b6dc89c9fc515eb4434a3ebb00873b518a8b9b02412e3616a2213a553b653acfb3a48b10b80a672076e0cedaa6bc9a1911558b7591798dc2b1f9b07cf66617e048458504f3394bd254b147a4dd413ea474ba92f3340121027c7abb332482af8c497a86238ba29d730beee5f194e8e183e46e184f11879b0902410772dbb6218a2f378e24cf5372ec5b3e663363e19e11b3778554c6c4bd5759d4064153322ba8bf1ec35d7a089748c520c070adb601fc6c09fb5483c020ec56bb012102a834017829b8cc0c8e34686580fe7583c89f8b3f40261bb68bed3c2ea49c9e07";

        let tx = HandshakeTx::deserialize_hex(hex).unwrap();
        let args = SighashArgs {
            index: 0,
            prevout_script: hex::decode("1976c014cb884746bae24846a6139160b2abc34d256c5e9788ac")
                .unwrap(),
            sighash_flag: Sighash::SingleReverseNoInputACP,
            prevout_value: 1250000000,
        };

        let expected = "943a86b8657a2dd9d533a69baeebb6ee2cbed40116b57e8157914d8b8d9ebff2";
        let signature_hash = tx.signature_hash(&args).unwrap();
        assert_eq!(expected, hex::encode(signature_hash));
    }
}
