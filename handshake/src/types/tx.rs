//! Handshake transaction types and associated sighash arguments.
use std::io::{Error as IOError, Read, Write};
use thiserror::Error;

// TODO: move this to coins_core
use bitcoins::{
    hashes::{TXID, WTXID},
    types::WitnessTransaction
};

use coins_core::{
    hashes::{
        blake2b256::{Blake2b256Digest, Blake2b256Writer},
        marked::{MarkedDigest, MarkedDigestWriter}
    },
    ser::{ByteFormat, SerError},
    types::tx::Transaction,
};

use crate::{
    types::{
        Witness,
        LockingScript,
        txin::{HandshakeOutpoint, HandshakeTxIn, Vin},
        txout::{TxOut, Vout},
        //witness::*,
    },
};

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
    fn signature_hash(
        &self,
        args: &Self::SighashArgs,
    ) -> Result<Self::Digest, Self::TxError> {
        let mut w = Self::HashWriter::default();
        self.write_sighash_preimage(&mut w, args)?;
        Ok(w.finish())
    }
}

/// Wrapper enum for returning values that may be EITHER a Witness OR a Legacy tx and the type is
/// not known in advance. While a few transaction methods have been implemented for convenience,
/// This wrapper must be explicitly unwrapped before the tx object can be signed.
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
    ///
    pub(crate) witnesses: Vec<Witness>,

}

impl Default for HandshakeTx {
    fn default() -> Self {
        Self{
            version: 0,
            vin: vec![],
            vout: vec![],
            locktime: 0,
            witnesses: vec![]
        }
    }
}

impl ByteFormat for HandshakeTx {
    type Error = TxError; // Ser associated error

    fn serialized_length(&self) -> usize {
        let mut len = 4; // version
        len += 2; // Segwit Flag
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
            witnesses
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
        // TODO: implement
        Self {
            version,
            vin: vin.into(),
            vout: vout.into(),
            locktime,
            witnesses: vec![]
        }
    }

    // TODO: double check this
    fn wtxid(&self) -> WTXID {
        let mut w = Self::HashWriter::default();
        self.write_to(&mut w)
            .expect("No IOError from hash functions");
        w.finish_marked()
    }
}

impl HandshakeTx {
    /// Calculates `hash_prevouts` according to BIP143 semantics.`
    ///
    /// For BIP143 (Witness and Compatibility sighash) documentation, see here:
    ///
    /// - https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    ///
    /// TODO: memoize
    fn hash_prevouts(&self, sighash_flag: Sighash) -> TxResult<Blake2b256Digest> {
        if sighash_flag as u8 & 0x80 == 0x80 {
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
        if sighash_flag == Sighash::Single || sighash_flag as u8 & 0x80 == 0x80 {
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
            Sighash::All | Sighash::AllACP => {
                let mut w = Blake2b256Writer::default();
                for output in self.vout.iter() {
                    output.write_to(&mut w)?;
                }
                Ok(w.finish())
            }
            Sighash::Single | Sighash::SingleACP => {
                let mut w = Blake2b256Writer::default();
                self.vout[index].write_to(&mut w)?;
                Ok(w.finish())
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
        // TODO: implement
        Self {
            version,
            vin: vin.into(),
            vout: vout.into(),
            locktime,
            witnesses: vec![]
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
        self.write_to(&mut w)
            .expect("No IOError from hash functions");
        w.finish_marked()
    }

    /// Return the TXID of the transaction
    fn write_sighash_preimage<W: Write>(
        &self,
        writer: &mut W,
        args: &Self::SighashArgs,
    ) -> Result<(), Self::TxError> {
        if args.sighash_flag == Sighash::None || args.sighash_flag == Sighash::NoneACP {
            return Err(TxError::NoneUnsupported);
        }

        if (args.sighash_flag == Sighash::Single || args.sighash_flag == Sighash::SingleACP)
            && args.index >= self.outputs().len()
        {
            return Err(TxError::SighashSingleBug);
        }

        let input = &self.vin[args.index];

        /*
        let mut prevouts = vec![];
        self.hash_prevouts(args.sighash_flag)?.write_to(&mut prevouts)?;
        let mut sequence = vec![];
        self.hash_sequence(args.sighash_flag)?.write_to(&mut sequence)?;
        let mut outpoint = vec![];
        input.outpoint.write_to(&mut outpoint)?;
        let mut script = vec![];
        args.prevout_script.write_to(&mut script)?;
        let mut outputs = vec![];
        self.hash_outputs(args.index, args.sighash_flag)?
            .write_to(&mut outputs)?;

        println!("version: {}", self.version);
        println!("prevouts: {}", hex::encode(prevouts));
        println!("sequence: {}", hex::encode(sequence));
        println!("outpoint: {}", hex::encode(outpoint));
        println!("script : {}", hex::encode(script));
        println!("value: {}", args.prevout_value);
        println!("sequence: {}", input.sequence);
        println!("outputs: {}", hex::encode(outputs));
        println!("locktime: {}", self.locktime);
        println!("flag: {}", args.sighash_flag as u32);
        */


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

    /// Sighash NONE is unsupported
    #[error("SIGHASH_NONE is unsupported")]
    NoneUnsupported,

    /// Satoshi's sighash single bug. Throws an error here.
    #[error("SIGHASH_SINGLE bug is unsupported")]
    SighashSingleBug,

    /// Caller provided an unknown sighash type to `Sighash::from_u8`
    #[error("Unknown Sighash: {}", .0)]
    UnknownSighash(u8),

    /// Got an unknown flag where we expected a witness flag. May indicate a non-witness
    /// transaction.
    #[error("Witness flag not as expected. Got {:?}. Expected {:?}.", .0, [0u8, 1u8])]
    BadWitnessFlag([u8; 2]),

    /// Wrong sighash args passed in to wrapped tx
    #[error("Sighash args must match the wrapped tx type")]
    WrongSighashArgs,
    // /// No outputs in vout
    // #[error("Vout may not be empty")]
    // EmptyVout
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
/// All possible Sighash modes
pub enum Sighash {
    /// Sign ALL inputs and ALL outputs
    All = 0x01,
    /// Sign ALL inputs and NO outputs (unsupported)
    None = 0x02,
    /// Sign ALL inputs and ONE output
    Single = 0x3,
    /// Sign ONE inputs and ALL outputs
    AllACP = 0x81,
    /// Sign ONE inputs and NO outputs (unsupported)
    NoneACP = 0x82,
    /// Sign ONE inputs and ONE output
    SingleACP = 0x83,
}

impl Sighash {
    ///
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Convert a u8 into a Sighash flag or an error.
    pub fn from_u8(flag: u8) -> Result<Sighash, TxError> {
        match flag {
            0x01 => Ok(Sighash::All),
            0x02 => Ok(Sighash::None),
            0x3 => Ok(Sighash::Single),
            0x81 => Ok(Sighash::AllACP),
            0x82 => Ok(Sighash::NoneACP),
            0x83 => Ok(Sighash::SingleACP),
            _ => Err(TxError::UnknownSighash(flag)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    //use crate::prelude::*;

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
    fn it_computes_signature_hash() {
        let hex = "000000000359741074e7e43facc55c3ae1a644a22561a59f4aabf31dde696649e01a9a0ea801000000ffffffff66a4c373c7c8044a1c76e818c74e5afdcdc4c474be81117bb47bb9fa60c167f601000000fffffffff6d6018a06b684e9690878e1a08ed9f89d17576ed318188d5c7433de875ee7de01000000ffffffff02b3b58311000000000014269ad5908a45b718e1c758603d40a50ede49f3b200000000127a000000000014cf2958d6d7a2e5d1597e30bcc6930eeb7227c77203042004306304c779b5a60d02ff55a6fd337f00961daab78838a28a9a0f37d4b2b80e047e5f000008786e2d2d366f3868200ec0b3671a9915869ce08b809a2eed90072dea6644d4258301947d72e6c2e0f7000000000241f3f2c41bfca7aa1284b59032a1242bc2310b455a9d2ac32db34c5d78b249f155093172334263d400a191fa9b3fbe049ea60ae70c0c830162371c9266bfa62d55012102471bd11ad149e58256a23594f93050eae947913dc48895022fa339261b058c7102410b68bb338918623912e75c063a2e782853c472ac962e69a5f23b07c9b5ab718e32ffbc6d2bad91a60509b62cca233deae39e349aba4ee204cb5118e887c870c1012102cd7938c7817e757ca5844bcd15673ccdf2ce13e93b58e04262204d75fcc8a6c10241ebbc15a3a3ec74430bd94d8c8f4ea36bd28ba7c3125fcaef031a38788053e4da2e443a3087a093fdfc63631424645316e4f52c4b0fa700adea783f2cd1526ead012102b8619b8d174552ff061c4c83636f4d7f163546e61194b73e90b7f8d23c84bb91";

        let tx = HandshakeTx::deserialize_hex(hex).unwrap();
        let args = SighashArgs {
            index: 0,
            prevout_script: hex::decode("1976c0146d7428ea0c83eee3a74edc53a1f9a7f26ca5d5c988ac").unwrap(),
            sighash_flag: Sighash::All,
            prevout_value: 503306619
        };

        let mut preimage = vec![];
        tx.write_sighash_preimage(&mut preimage, &args).unwrap();

        let expected = "c4f226db5b21a0948f43c856f6441f1776c3c38d4530c25006fa0bdd48e5af7e";
        let signature_hash = tx.signature_hash(&args).unwrap();
        assert_eq!(expected, hex::encode(signature_hash));
    }
}
