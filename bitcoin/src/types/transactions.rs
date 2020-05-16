//! Bitcoin transaction types and associated sighash arguments.
use bitcoin_spv::types::Hash256Digest;
use std::io::{Error as IOError, Read, Write};
use thiserror::Error;

use riemann_core::{
    hashes::{
        hash256::Hash256Writer,
        marked::{MarkedDigest, MarkedDigestWriter},
    },
    ser::{ByteFormat, SerError},
    types::tx::Transaction,
};

use crate::{
    hashes::{TXID, WTXID},
    types::{
        script::{Script, ScriptSig, Witness},
        txin::{BitcoinTxIn, Vin},
        txout::{TxOut, Vout},
    },
};

/// Wrapper enum for returning values that may be EITHER a Witness OR a Legacy tx and the type is
/// not known in advance. This wrapper must be explicitly downcast before the tx object can be
/// used
pub enum BitcoinTx {
    /// Witness
    Witness(WitnessTx),
    /// Legacy
    Legacy(LegacyTx),
}

impl BitcoinTx {
    /// Deserialize a hex string. Determine type information from the segwit marker `0001`
    /// immediately following the version bytes. This produces a `BitcoinTx` enum that must be
    /// explicitly cast to the desired type via `into_witness` or `into_legacy`.
    ///
    /// # Note
    ///
    /// Casting directly to legacy may drop witness information if the tx is witness
    pub fn from_hex(hex: &str) -> Result<BitcoinTx, TxError> {
        if &hex[8..12] == "0001" {
            WitnessTx::deserialize_hex(hex).map(BitcoinTx::Witness)
        } else {
            LegacyTx::deserialize_hex(hex).map(BitcoinTx::Legacy)
        }
    }

    /// True if the wrapped tx is a witness transaction. False otherwise
    pub fn is_witness(&self) -> bool {
        match self {
            BitcoinTx::Witness(_) => true,
            _ => false
        }
    }

    /// True if the wrapped tx is a legacy transaction. False otherwise
    pub fn is_legacy(&self) -> bool {
        match self {
            BitcoinTx::Legacy(_) => true,
            _ => false
        }
    }

    /// Consume the wrapper and convert it to a legacy tx. but `into_witness` should be
    /// preferred, as it will never drop information.
    pub fn into_legacy(self) -> LegacyTx {
        match self {
            BitcoinTx::Witness(tx) => tx.into_legacy(),
            BitcoinTx::Legacy(tx) => tx,
        }
    }

    /// Consume the wrapper and convert it to a witness tx.
    pub fn into_witness(self) -> WitnessTx {
        match self {
            BitcoinTx::Witness(tx) => tx,
            BitcoinTx::Legacy(tx) => tx.into_witness(),
        }
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
    // /// No inputs in vin
    // #[error("Vin may not be empty")]
    // EmptyVin,
    //
    // /// No outputs in vout
    // #[error("Vout may not be empty")]
    // EmptyVout
}

/// Type alias for result with TxError
pub type TxResult<T> = Result<T, TxError>;

/// Functions common to Bitcoin transactions. This provides a small abstraction layer over the
/// Legacy/SegWit tx divide by implementing a small common interface between them.
pub trait BitcoinTransaction<'a>:
    Transaction<
    'a,
    Digest = bitcoin_spv::types::Hash256Digest,
    Error = TxError,  // Ser associated error
    TxError = TxError,
    TXID = TXID,
    TxOut = TxOut,
    TxIn = BitcoinTxIn,
    HashWriter = Hash256Writer,
>
{
    /// Returns a reference to the tx as a legacy tx.
    fn as_legacy(&self) -> &LegacyTx;

    /// Consume the tx and convert it to a legacy tx. Useful for when you have
    /// `dyn BitcoinTransaction` or `impl BitcoinTransaction` types, but `into_witness` should be
    /// preferred, as it will never drop information.
    fn into_legacy(self) -> LegacyTx;

    /// Consume the tx and convert it to a legacy tx. Useful for when you have
    /// `dyn BitcoinTransaction` or `impl BitcoinTransaction` types.
    fn into_witness(self) -> WitnessTx;

    /// Return a reference to a slice of witnesses. For legacy txins this will ALWAYS be length 0.
    /// For witness txns, this will ALWAYS be the same length as the input vector.
    fn witnesses(&self) -> &[Witness];
}

/// Basic functionality for a Witness Transacti'on
///
/// This trait has been generalized to support transactions from Non-Bitcoin networks. The
/// transaction specificies which types it considers to be inputs and outputs, and a struct that
/// contains its Sighash arguments. This allows others to define custom transaction types with
/// unique functionality.
pub trait WitnessTransaction<'a>: BitcoinTransaction<'a> {
    /// The MarkedDigest type for the Transaction's Witness TXID
    type WTXID: MarkedDigest<Digest = Self::Digest>;
    /// The BIP143 sighash args needed to sign an input
    type WitnessSighashArgs;
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

    /// Writes the Legacy sighash preimage to the provider writer.
    fn write_legacy_sighash_preimage<W: Write>(
        &self,
        writer: &mut W,
        args: &LegacySighashArgs,
    ) -> Result<(), Self::TxError>;

    /// Calculates the Legacy sighash preimage given the sighash args.
    fn legacy_sighash(&self, args: &LegacySighashArgs) -> Result<Self::Digest, Self::TxError> {
        let mut w = Self::HashWriter::default();
        self.write_legacy_sighash_preimage(&mut w, args)?;
        Ok(w.finish())
    }

    /// Writes the BIP143 sighash preimage to the provided `writer`. See the
    /// `WitnessSighashArgsSigh` documentation for more in-depth discussion of sighash.
    fn write_witness_sighash_preimage<W: Write>(
        &self,
        writer: &mut W,
        args: &Self::WitnessSighashArgs,
    ) -> Result<(), Self::TxError>;

    /// Calculates the BIP143 sighash given the sighash args. See the
    /// `WitnessSighashArgsSigh` documentation for more in-depth discussion of sighash.
    fn witness_sighash(
        &self,
        args: &Self::WitnessSighashArgs,
    ) -> Result<Self::Digest, Self::TxError> {
        let mut w = Self::HashWriter::default();
        self.write_witness_sighash_preimage(&mut w, args)?;
        Ok(w.finish())
    }
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

/// Arguments required to serialize the transaction to create the sighash digest.Used in
/// `legacy_sighash`to abstract the sighash serialization logic from the hasher used.
///
/// SIGHASH_ALL commits to ALL inputs, and ALL outputs. It indicates that no further modification
/// of the transaction is allowed without invalidating the signature.
///
/// SIGHASH_ALL + ANYONECANPAY commits to ONE input and ALL outputs. It indicates that anyone may
/// add additional value to the transaction, but that no one may modify the payments made. Any
/// extra value added above the sum of output values will be given to miners as part of the tx
/// fee.
///
/// SIGHASH_SINGLE commits to ALL inputs, and ONE output. It indicates that anyone may append
/// additional outputs to the transaction to reroute funds from the inputs. Additional inputs
/// cannot be added without invalidating the signature. It is logically difficult to use securely,
/// as it consents to funds being moved, without specifying their destination.
///
/// SIGHASH_SINGLE commits specifically the the output at the same index as the input being
/// signed. If there is no output at that index, (because, e.g. the input vector is longer than
/// the output vector) it behaves insecurely, and we do not implement that protocol bug.
///
/// SIGHASH_SINGLE + ANYONECANPAY commits to ONE input and ONE output. It indicates that anyone
/// may add additional value to the transaction, and route value to any other location. The
/// signed input and output must be included in the fully-formed transaction at the same index in
/// their respective vectors.
///
/// For Legacy sighash documentation, see here:
///
/// - https://en.bitcoin.it/wiki/OP_CHECKSIG#Hashtype_SIGHASH_ALL_.28default.29
///
/// # Note
///
/// After signing the digest, you MUST append the sighash indicator
/// byte to the resulting signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacySighashArgs<'a> {
    /// The index of the input we'd like to sign
    pub index: usize,
    /// The sighash mode to use.
    pub sighash_flag: Sighash,
    /// The script used in the prevout, which must be signed. In complex cases involving
    /// `OP_CODESEPARATOR` this must be the subset of the script containing the `OP_CHECKSIG`
    /// currently being executed.
    pub prevout_script: &'a Script,
}

/// A Legacy (non-witness) Transaction.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq, Default)]
pub struct LegacyTx {
    /// The version number. Usually 1 or 2.
    version: u32,
    /// The vector of inputs
    vin: Vin,
    /// The vector of outputs
    vout: Vout,
    /// The nLocktime field.
    locktime: u32,
}

impl LegacyTx {
    /// Performs steps 6, 7, and 8 of the sighash setup described here:
    /// https://en.bitcoin.it/wiki/OP_CHECKSIG#How_it_works
    /// https://bitcoin.stackexchange.com/questions/3374/how-to-redeem-a-basic-tx
    ///
    /// OP_CODESEPARATOR functionality is NOT provided here.
    ///
    /// TODO: memoize
    fn legacy_sighash_prep(&self, index: usize, prevout_script: &Script) -> Self {
        let mut copy_tx = self.clone();

        for i in 0..copy_tx.vin.len() {
            copy_tx.vin[i].script_sig = if i == index {
                ScriptSig::from(prevout_script.items())
            } else {
                ScriptSig::null()
            };
        }
        copy_tx
    }

    /// Modifies copy_tx according to legacy SIGHASH_SINGLE semantics.
    ///
    /// For Legacy sighash documentation, see here:
    ///
    /// - https://en.bitcoin.it/wiki/OP_CHECKSIG#Hashtype_SIGHASH_ALL_.28default.29
    fn legacy_sighash_single(copy_tx: &mut Self, index: usize) -> TxResult<()> {
        let mut tx_outs: Vec<TxOut> = (0..index).map(|_| TxOut::null()).collect();
        tx_outs.push(copy_tx.vout[index].clone());
        copy_tx.vout = tx_outs;

        let mut vin = vec![];

        // let mut vin = copy_tx.vin.clone();
        for i in 0..copy_tx.vin.len() {
            let mut txin = copy_tx.vin[i].clone();
            if i != index {
                txin.sequence = 0;
            }
            vin.push(txin);
        }
        copy_tx.vin = vin;
        Ok(())
    }

    /// Modifies copy_tx according to legacy SIGHASH_ANYONECANPAY semantics.
    ///
    /// For Legacy sighash documentation, see here:
    ///
    /// - https://en.bitcoin.it/wiki/OP_CHECKSIG#Hashtype_SIGHASH_ALL_.28default.29
    fn legacy_sighash_anyone_can_pay(copy_tx: &mut Self, index: usize) -> TxResult<()> {
        copy_tx.vin = vec![copy_tx.vin[index].clone()];
        Ok(())
    }
}

impl<'a> Transaction<'a> for LegacyTx {
    type TxError = TxError;
    type Digest = Hash256Digest;
    type TxIn = BitcoinTxIn;
    type TxOut = TxOut;
    type SighashArgs = LegacySighashArgs<'a>;
    type TXID = TXID;
    type HashWriter = Hash256Writer;

    fn new<I, O>(version: u32, vin: I, vout: O, locktime: u32) -> Self
    where
        I: Into<Vec<Self::TxIn>>,
        O: Into<Vec<Self::TxOut>>,
    {
        Self {
            version,
            vin: vin.into(),
            vout: vout.into(),
            locktime,
        }
    }

    fn inputs(&'a self) -> &'a [Self::TxIn] {
        &self.vin
    }

    fn outputs(&'a self) -> &'a [Self::TxOut] {
        &self.vout
    }

    fn version(&self) -> u32 {
        self.version
    }

    fn locktime(&self) -> u32 {
        self.locktime
    }

    fn write_sighash_preimage<W: Write>(
        &self,
        writer: &mut W,
        args: &LegacySighashArgs,
    ) -> TxResult<()> {
        if args.sighash_flag == Sighash::None || args.sighash_flag == Sighash::NoneACP {
            return Err(TxError::NoneUnsupported);
        }

        let mut copy_tx: Self = self.legacy_sighash_prep(args.index, args.prevout_script);
        if args.sighash_flag == Sighash::Single || args.sighash_flag == Sighash::SingleACP {
            if args.index >= self.outputs().len() {
                return Err(TxError::SighashSingleBug);
            }
            Self::legacy_sighash_single(&mut copy_tx, args.index)?;
        }

        if args.sighash_flag as u8 & 0x80 == 0x80 {
            Self::legacy_sighash_anyone_can_pay(&mut copy_tx, args.index)?;
        }

        copy_tx.write_to(writer)?;
        Self::write_u32_le(writer, args.sighash_flag as u32)?;

        Ok(())
    }
}

impl<'a> BitcoinTransaction<'a> for LegacyTx {
    fn as_legacy(&self) -> &LegacyTx {
        &self
    }

    fn into_witness(self) -> WitnessTx {
        WitnessTx::from_legacy(self)
    }

    fn into_legacy(self) -> LegacyTx {
        self
    }

    fn witnesses(&self) -> &[Witness] {
        &[]
    }
}

impl ByteFormat for LegacyTx {
    type Error = TxError;

    fn serialized_length(&self) -> usize {
        let mut len = 4; // version
        len += riemann_core::ser::prefix_byte_len(self.vin.len() as u64) as usize;
        len += self.vin.serialized_length();
        len += riemann_core::ser::prefix_byte_len(self.vout.len() as u64) as usize;
        len += self.vout.serialized_length();
        len += 4; // locktime
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
        let locktime = Self::read_u32_le(reader)?;
        Ok(Self {
            version,
            vin,
            vout,
            locktime,
        })
    }

    fn write_to<W>(&self, writer: &mut W) -> Result<usize, Self::Error>
    where
        W: Write,
    {
        let mut len = Self::write_u32_le(writer, self.version())?;
        Self::write_prefix_vec(writer, &self.vin)?;
        Self::write_prefix_vec(writer, &self.vout)?;
        len += Self::write_u32_le(writer, self.locktime())?;
        Ok(len)
    }
}

/// Arguments required to serialize the transaction to create the BIP143 (witness) sighash
/// digest. Used in `witness_sighash` to abstract the sighash serialization logic from the hash
/// used.
///
/// SIGHASH_ALL commits to ALL inputs, and ALL outputs. It indicates that no further modification
/// of the transaction is allowed without invalidating the signature.
///
/// SIGHASH_ALL + ANYONECANPAY commits to ONE input and ALL outputs. It indicates that anyone may
/// add additional value to the transaction, but that no one may modify the payments made. Any
/// extra value added above the sum of output values will be given to miners as part of the tx
/// fee.
///
/// SIGHASH_SINGLE commits to ALL inputs, and ONE output. It indicates that anyone may append
/// additional outputs to the transaction to reroute funds from the inputs. Additional inputs
/// cannot be added without invalidating the signature. It is logically difficult to use securely,
/// as it consents to funds being moved, without specifying their destination.
///
/// SIGHASH_SINGLE commits specifically the the output at the same index as the input being
/// signed. If there is no output at that index, (because, e.g. the input vector is longer than
/// the output vector) it behaves insecurely, and we do not implement that protocol bug.
///
/// SIGHASH_SINGLE + ANYONECANPAY commits to ONE input and ONE output. It indicates that anyone
/// may add additional value to the transaction, and route value to any other location. The
/// signed input and output must be included in the fully-formed transaction at the same index in
/// their respective vectors.
///
/// For BIP143 sighash documentation, see here:
///
/// - https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
///
/// # Note
///
/// After signing the digest, you MUST append the sighash indicator byte to the resulting
/// signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessSighashArgs<'a> {
    /// The index of the input we'd like to sign
    pub index: usize,
    /// The sighash mode to use.
    pub sighash_flag: Sighash,
    /// The script used in the prevout, which must be signed. In complex cases involving
    /// `OP_CODESEPARATOR` this must be the subset of the script containing the `OP_CHECKSIG`
    /// currently being executed.
    pub prevout_script: &'a Script,
    /// The value of the prevout.
    pub prevout_value: u64,
}

/// A witness transaction. Any transaction that contains 1 or more witnesses.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq, Default)]
pub struct WitnessTx {
    legacy_tx: LegacyTx,
    witnesses: Vec<Witness>,
}

impl WitnessTx {
    /// Calculates `hash_prevouts` according to BIP143 semantics.`
    ///
    /// For BIP143 (Witness and Compatibility sighash) documentation, see here:
    ///
    /// - https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    ///
    /// TODO: memoize
    fn hash_prevouts(&self, sighash_flag: Sighash) -> TxResult<Hash256Digest> {
        if sighash_flag as u8 & 0x80 == 0x80 {
            Ok(Hash256Digest::default())
        } else {
            let mut w = Hash256Writer::default();
            for input in self.legacy_tx.vin.iter() {
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
    fn hash_sequence(&self, sighash_flag: Sighash) -> TxResult<Hash256Digest> {
        if sighash_flag == Sighash::Single || sighash_flag as u8 & 0x80 == 0x80 {
            Ok(Hash256Digest::default())
        } else {
            let mut w = Hash256Writer::default();
            for input in self.legacy_tx.vin.iter() {
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
    fn hash_outputs(&self, index: usize, sighash_flag: Sighash) -> TxResult<Hash256Digest> {
        match sighash_flag {
            Sighash::All | Sighash::AllACP => {
                let mut w = Hash256Writer::default();
                for output in self.legacy_tx.vout.iter() {
                    output.write_to(&mut w)?;
                }
                Ok(w.finish())
            }
            Sighash::Single | Sighash::SingleACP => {
                let mut w = Hash256Writer::default();
                self.legacy_tx.vout[index].write_to(&mut w)?;
                Ok(w.finish())
            }
            _ => Ok(Hash256Digest::default()),
        }
    }
}

impl WitnessTx {
    /// Consumes a `LegacyTx` and instantiates a new `WitnessTx` with empty witnesses
    pub fn from_legacy(legacy_tx: LegacyTx) -> Self {
        let witnesses = (0..legacy_tx.inputs().len())
            .map(|_| Witness::default())
            .collect();
        Self {
            legacy_tx,
            witnesses,
        }
    }
}

impl<'a> Transaction<'a> for WitnessTx {
    type TxError = TxError;
    type Digest = Hash256Digest;
    type TxIn = BitcoinTxIn;
    type TxOut = TxOut;
    type SighashArgs = WitnessSighashArgs<'a>;
    type TXID = TXID;
    type HashWriter = Hash256Writer;

    fn new<I, O>(version: u32, vin: I, vout: O, locktime: u32) -> Self
    where
        I: Into<Vec<Self::TxIn>>,
        O: Into<Vec<Self::TxOut>>,
    {
        let input_vector: Vec<BitcoinTxIn> = vin.into();
        let witnesses = input_vector.iter().map(|_| Witness::default()).collect();

        let legacy_tx = LegacyTx::new(version, input_vector, vout, locktime);
        Self {
            legacy_tx,
            witnesses,
        }
    }

    fn inputs(&'a self) -> &'a [Self::TxIn] {
        &self.legacy_tx.vin
    }

    fn outputs(&'a self) -> &'a [Self::TxOut] {
        &self.legacy_tx.vout
    }

    fn version(&self) -> u32 {
        self.legacy_tx.version
    }

    fn locktime(&self) -> u32 {
        self.legacy_tx.locktime
    }

    // Override the txid method to exclude witnesses
    fn txid(&self) -> Self::TXID {
        self.legacy_tx.txid()
    }

    fn write_sighash_preimage<W: Write>(
        &self,
        writer: &mut W,
        args: &Self::SighashArgs,
    ) -> TxResult<()> {
        self.write_witness_sighash_preimage(writer, args)
    }
}

impl<'a> BitcoinTransaction<'a> for WitnessTx {
    fn as_legacy(&self) -> &LegacyTx {
        &self.legacy_tx
    }

    fn into_witness(self) -> WitnessTx {
        self
    }

    fn into_legacy(self) -> LegacyTx {
        self.legacy_tx
    }

    fn witnesses(&self) -> &[Witness] {
        &self.witnesses
    }
}

impl<'a> WitnessTransaction<'a> for WitnessTx {
    type WTXID = WTXID;
    type WitnessSighashArgs = WitnessSighashArgs<'a>;
    type Witness = Witness;

    fn new<I, O, W>(version: u32, vin: I, vout: O, witnesses: W, locktime: u32) -> Self
    where
        I: Into<Vec<Self::TxIn>>,
        O: Into<Vec<Self::TxOut>>,
        W: Into<Vec<Self::Witness>>,
    {
        let legacy_tx = LegacyTx::new(version, vin, vout, locktime);
        Self {
            legacy_tx,
            witnesses: witnesses.into(),
        }
    }

    fn wtxid(&self) -> Self::WTXID {
        let mut w = Self::HashWriter::default();
        self.write_to(&mut w).expect("No IOError from SHA2");
        w.finish_marked()
    }

    fn write_legacy_sighash_preimage<W: Write>(
        &self,
        writer: &mut W,
        args: &LegacySighashArgs,
    ) -> Result<(), Self::TxError> {
        self.legacy_tx.write_sighash_preimage(writer, args)
    }

    fn write_witness_sighash_preimage<W>(
        &self,
        writer: &mut W,
        args: &WitnessSighashArgs,
    ) -> TxResult<()>
    where
        W: Write,
    {
        if args.sighash_flag == Sighash::None || args.sighash_flag == Sighash::NoneACP {
            return Err(TxError::NoneUnsupported);
        }

        if (args.sighash_flag == Sighash::Single || args.sighash_flag == Sighash::SingleACP)
            && args.index >= self.outputs().len()
        {
            return Err(TxError::SighashSingleBug);
        }

        let input = &self.legacy_tx.vin[args.index];

        Self::write_u32_le(writer, self.legacy_tx.version)?;
        self.hash_prevouts(args.sighash_flag)?.write_to(writer)?;
        self.hash_sequence(args.sighash_flag)?.write_to(writer)?;
        input.outpoint.write_to(writer)?;
        args.prevout_script.write_to(writer)?;
        Self::write_u64_le(writer, args.prevout_value)?;
        Self::write_u32_le(writer, input.sequence)?;
        self.hash_outputs(args.index, args.sighash_flag)?
            .write_to(writer)?;
        Self::write_u32_le(writer, self.legacy_tx.locktime)?;
        Self::write_u32_le(writer, args.sighash_flag as u32)?;
        Ok(())
    }
}

impl ByteFormat for WitnessTx {
    type Error = TxError;

    fn serialized_length(&self) -> usize {
        let mut len = 4; // version
        len += 2; // Segwit Flag
        len += riemann_core::ser::prefix_byte_len(self.legacy_tx.vin.len() as u64) as usize;
        len += self.legacy_tx.vin.serialized_length();
        len += riemann_core::ser::prefix_byte_len(self.legacy_tx.vout.len() as u64) as usize;
        len += self.legacy_tx.vout.serialized_length();
        for witness in self.witnesses.iter() {
            len += riemann_core::ser::prefix_byte_len(self.witnesses.len() as u64) as usize;
            len += witness.serialized_length();
        }
        len += 4; // locktime
        len
    }

    fn read_from<R>(reader: &mut R, _limit: usize) -> Result<Self, Self::Error>
    where
        R: Read,
        Self: std::marker::Sized,
    {
        let version = Self::read_u32_le(reader)?;
        let mut flag = [0u8; 2];
        reader.read_exact(&mut flag)?;
        if flag != [0u8, 1u8] {
            return Err(TxError::BadWitnessFlag(flag));
        };
        let vin = Self::read_prefix_vec(reader)?;
        let vout = Self::read_prefix_vec(reader)?;
        let mut witnesses = vec![];
        for _ in vin.iter() {
            witnesses.push(Self::read_prefix_vec(reader)?);
        }
        let locktime = Self::read_u32_le(reader)?;

        let legacy_tx = LegacyTx {
            version,
            vin,
            vout,
            locktime,
        };

        Ok(Self {
            legacy_tx,
            witnesses,
        })
    }

    fn write_to<W>(&self, writer: &mut W) -> Result<usize, Self::Error>
    where
        W: Write,
    {
        let mut len = Self::write_u32_le(writer, self.version())?;
        len += writer.write(&[0u8, 1u8])?;

        len += Self::write_prefix_vec(writer, &self.legacy_tx.vin)?;
        len += Self::write_prefix_vec(writer, &self.legacy_tx.vout)?;
        for wit in self.witnesses.iter() {
            len += Self::write_prefix_vec(writer, &wit)?;
        }
        len += Self::write_u32_le(writer, self.locktime())?;
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_calculates_legacy_sighashes_and_txids() {
        // pulled from riemann helpers
        let tx_hex = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        let tx = LegacyTx::deserialize_hex(tx_hex).unwrap();
        assert_eq!(tx.serialized_length(), tx_hex.len() / 2);

        let prevout_script_hex = "17a91424d6008f143af0cca57344069c46661aa4fcea2387";
        let prevout_script = Script::deserialize_hex(prevout_script_hex).unwrap();

        let all = Hash256Digest::deserialize_hex(
            "b85c4f8d1377cc138225dd9b319d0a4ca547f7884270640f44c5fcdf269e0fe8",
        )
        .unwrap();
        let all_anyonecanpay = Hash256Digest::deserialize_hex(
            "3b67a5114cc9fc837ddd6f6ec11bde38db5f68c34ab6ece2a043d7b25f2cf8bb",
        )
        .unwrap();
        let single = Hash256Digest::deserialize_hex(
            "1dab67d768be0380fc800098005d1f61744ffe585b0852f8d7adc12121a86938",
        )
        .unwrap();
        let single_anyonecanpay = Hash256Digest::deserialize_hex(
            "d4687b93c0a9090dc0a3384cd3a594ce613834bb37abc56f6032e96c597547e3",
        )
        .unwrap();

        let txid = Hash256Digest::deserialize_hex(
            "03ee4f7a4e68f802303bc659f8f817964b4b74fe046facc3ae1be4679d622c45",
        )
        .unwrap();
        assert_eq!(tx.txid(), txid.into());

        let mut args = LegacySighashArgs {
            index: 0,
            sighash_flag: Sighash::All,
            prevout_script: &prevout_script,
        };

        assert_eq!(tx.sighash(&args).unwrap(), all);
        args.sighash_flag = Sighash::AllACP;
        assert_eq!(tx.sighash(&args).unwrap(), all_anyonecanpay);
        args.sighash_flag = Sighash::Single;
        assert_eq!(tx.sighash(&args).unwrap(), single);
        args.sighash_flag = Sighash::SingleACP;
        assert_eq!(tx.sighash(&args).unwrap(), single_anyonecanpay);
    }

    #[test]
    fn it_calculates_witness_sighashes_and_txids() {
        // pulled from riemann helpers
        let tx_hex = "02000000000101ee9242c89e79ab2aa537408839329895392b97505b3496d5543d6d2f531b94d20000000000fdffffff0173d301000000000017a914bba5acbec4e6e3374a0345bf3609fa7cfea825f18700cafd0700";
        let tx = WitnessTx::deserialize_hex(tx_hex).unwrap();
        assert_eq!(tx.serialized_length(), tx_hex.len() / 2);

        let prevout_script_hex = "160014758ce550380d964051086798d6546bebdca27a73";
        let prevout_script = Script::deserialize_hex(prevout_script_hex).unwrap();

        let all = Hash256Digest::deserialize_hex(
            "135754ab872e4943f7a9c30d6143c4c7187e33d0f63c75ec82a7f9a15e2f2d00",
        )
        .unwrap();
        let all_anyonecanpay = Hash256Digest::deserialize_hex(
            "cc7438d5b15e93ba612dcd227cf1937c35273675b3aa7d1b771573667376ddf6",
        )
        .unwrap();
        let single = Hash256Digest::deserialize_hex(
            "d04631d2742e6fd8e80e2e4309dece65becca41d37fd6bc0bcba041c52d824d5",
        )
        .unwrap();
        let single_anyonecanpay = Hash256Digest::deserialize_hex(
            "ffea9cdda07170af9bc9967cedf485e9fe15b78a622e0c196c0b6fc64f40c615",
        )
        .unwrap();

        let txid = Hash256Digest::deserialize_hex(
            "9e77087321b870859ebf08976d665c42d9f98cad18fff6a05a91c1d2da6d6c41",
        )
        .unwrap();
        assert_eq!(tx.txid(), txid.into());

        let mut args = WitnessSighashArgs {
            index: 0,
            sighash_flag: Sighash::All,
            prevout_script: &prevout_script,
            prevout_value: 120000,
        };

        assert_eq!(tx.sighash(&args).unwrap(), all);

        args.sighash_flag = Sighash::AllACP;
        assert_eq!(tx.sighash(&args).unwrap(), all_anyonecanpay);

        args.sighash_flag = Sighash::Single;
        assert_eq!(tx.sighash(&args).unwrap(), single);

        args.sighash_flag = Sighash::SingleACP;
        assert_eq!(tx.sighash(&args).unwrap(), single_anyonecanpay);
    }

    #[test]
    fn it_passes_more_witness_sighash_tests() {
        // from riemann
        let tx_hex = "02000000000102ee9242c89e79ab2aa537408839329895392b97505b3496d5543d6d2f531b94d20000000000fdffffffee9242c89e79ab2aa537408839329895392b97505b3496d5543d6d2f531b94d20000000000fdffffff0273d301000000000017a914bba5acbec4e6e3374a0345bf3609fa7cfea825f18773d301000000000017a914bba5acbec4e6e3374a0345bf3609fa7cfea825f1870000cafd0700";
        let tx = WitnessTx::deserialize_hex(tx_hex).unwrap();
        assert_eq!(tx.serialized_length(), tx_hex.len() / 2);

        let prevout_script_hex = "160014758ce550380d964051086798d6546bebdca27a73";
        let prevout_script = Script::deserialize_hex(prevout_script_hex).unwrap();

        let all = Hash256Digest::deserialize_hex(
            "75385c87ece4980b581cfd71bc5814f607801a87f6e0973c63dc9fda465c19c4",
        )
        .unwrap();
        let all_anyonecanpay = Hash256Digest::deserialize_hex(
            "bc55c4303c82cdcc8e290c597a00d662ab34414d79ec15d63912b8be7fe2ca3c",
        )
        .unwrap();
        let single = Hash256Digest::deserialize_hex(
            "9d57bf7af01a4e0baa57e749aa193d37a64e3bbc08eb88af93944f41af8dfc70",
        )
        .unwrap();
        let single_anyonecanpay = Hash256Digest::deserialize_hex(
            "ffea9cdda07170af9bc9967cedf485e9fe15b78a622e0c196c0b6fc64f40c615",
        )
        .unwrap();

        let txid = Hash256Digest::deserialize_hex(
            "184e7bce099679b27ed958213c97d2fb971e227c6517bca11f06ccbb97dcdc30",
        )
        .unwrap();
        assert_eq!(tx.txid(), txid.into());

        let mut args = WitnessSighashArgs {
            index: 1,
            sighash_flag: Sighash::All,
            prevout_script: &prevout_script,
            prevout_value: 120000,
        };

        assert_eq!(tx.sighash(&args).unwrap(), all);
        assert_eq!(tx.witness_sighash(&args).unwrap(), all);

        args.sighash_flag = Sighash::AllACP;
        assert_eq!(tx.sighash(&args).unwrap(), all_anyonecanpay);
        assert_eq!(tx.witness_sighash(&args).unwrap(), all_anyonecanpay);

        args.sighash_flag = Sighash::Single;
        assert_eq!(tx.sighash(&args).unwrap(), single);
        assert_eq!(tx.witness_sighash(&args).unwrap(), single);

        args.sighash_flag = Sighash::SingleACP;
        assert_eq!(tx.sighash(&args).unwrap(), single_anyonecanpay);
        assert_eq!(tx.witness_sighash(&args).unwrap(), single_anyonecanpay);
    }

    #[test]
    fn it_passes_more_legacy_sighash_tests() {
        // from riemann
        let tx_hex = "0200000002ee9242c89e79ab2aa537408839329895392b97505b3496d5543d6d2f531b94d20000000000fdffffffee9242c89e79ab2aa537408839329895392b97505b3496d5543d6d2f531b94d20000000000fdffffff0273d301000000000017a914bba5acbec4e6e3374a0345bf3609fa7cfea825f18773d301000000000017a914bba5acbec4e6e3374a0345bf3609fa7cfea825f18700000000";
        let tx = LegacyTx::deserialize_hex(tx_hex).unwrap();
        assert_eq!(tx.serialized_length(), tx_hex.len() / 2);

        let prevout_script_hex = "160014758ce550380d964051086798d6546bebdca27a73";
        let prevout_script = Script::deserialize_hex(prevout_script_hex).unwrap();

        let all = Hash256Digest::deserialize_hex(
            "3ab40bf1287b7be9a5c67ed0f97f80b38c5f68e53ec93bffd3893901eaaafdb2",
        )
        .unwrap();
        let all_anyonecanpay = Hash256Digest::deserialize_hex(
            "2d5802fed31e1ef6a857346cc0a9085ea452daeeb3a0b5afcb16a2203ce5689d",
        )
        .unwrap();
        let single = Hash256Digest::deserialize_hex(
            "ea52b62b26c1f0db838c952fa50806fb8e39ba4c92a9a88d1b4ba7e9c094517d",
        )
        .unwrap();
        let single_anyonecanpay = Hash256Digest::deserialize_hex(
            "9e2aca0a04afa6e1e5e00ff16b06a247a0da1e7bbaa7cd761c066a82bb3b07d0",
        )
        .unwrap();

        let txid = Hash256Digest::deserialize_hex(
            "40157948972c5c97a2bafff861ee2f8745151385c7f9fbd03991ddf59b76ac81",
        )
        .unwrap();
        assert_eq!(tx.txid(), txid.into());

        let mut args = LegacySighashArgs {
            index: 1,
            sighash_flag: Sighash::All,
            prevout_script: &prevout_script,
        };

        assert_eq!(tx.sighash(&args).unwrap(), all);

        args.sighash_flag = Sighash::AllACP;
        assert_eq!(tx.sighash(&args).unwrap(), all_anyonecanpay);

        args.sighash_flag = Sighash::Single;
        assert_eq!(tx.sighash(&args).unwrap(), single);

        args.sighash_flag = Sighash::SingleACP;
        assert_eq!(tx.sighash(&args).unwrap(), single_anyonecanpay);
    }

    #[test]
    fn it_calculates_witness_txid() {
        // from mainnet: 3c7fb4af9b7bd2ba6f155318e0bc8a50432d4732ab6e36293ef45b304567b46a
        let tx_hex = "01000000000101b77bebb3ac480e99c0d95a4c812137b116e65e2f3b3a66a36d0e252928d460180100000000ffffffff03982457000000000017a91417b8e0f150215cc70bf2fb58070041d655b162dd8740e133000000000017a9142535e444f7d55f0500c1f86609d6cfc289576b698747abfb0100000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d040047304402205c6a889efa26955bef7ce2b08792e63e25eac9859080f0d83912b0ea833d7eb402205f859f4640f1600db5012b467ec05bb4ae1779640c1b5fadc8908960740e52b30147304402201c239ea25cfeadfa9493a1b0d136d70f50f821385972b7188c4329c2bf2d23a302201ee790e4b6794af6567f85a226a387d5b0222c3dc90d2fc558d09e08062b8271016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000";
        let wtxid = Hash256Digest::deserialize_hex(
            "84d85ce82c728e072bb11f379a6ed0b9127aa43905b7bae14b254bfcdce63549",
        )
        .unwrap();

        let tx = WitnessTx::deserialize_hex(tx_hex).unwrap();

        assert_eq!(tx.wtxid(), wtxid.into());
    }

    #[test]
    fn it_rejects_sighash_none() {
        let tx_hex = "02000000000102ee9242c89e79ab2aa537408839329895392b97505b3496d5543d6d2f531b94d20000000000fdffffffee9242c89e79ab2aa537408839329895392b97505b3496d5543d6d2f531b94d20000000000fdffffff0273d301000000000017a914bba5acbec4e6e3374a0345bf3609fa7cfea825f18773d301000000000017a914bba5acbec4e6e3374a0345bf3609fa7cfea825f1870000cafd0700";
        let tx = WitnessTx::deserialize_hex(tx_hex).unwrap();

        let args = WitnessSighashArgs {
            index: 0,
            sighash_flag: Sighash::None,
            prevout_script: &vec![].into(),
            prevout_value: 120000,
        };

        match tx.sighash(&args) {
            Err(TxError::NoneUnsupported) => {}
            _ => assert!(false, "expected sighash none unsupported"),
        }
    }

    #[test]
    fn it_rejects_sighash_single_bug() {
        let tx_hex = "02000000000102ee9242c89e79ab2aa537408839329895392b97505b3496d5543d6d2f531b94d20000000000fdffffffee9242c89e79ab2aa537408839329895392b97505b3496d5543d6d2f531b94d20000000000fdffffff0173d301000000000017a914bba5acbec4e6e3374a0345bf3609fa7cfea825f1870000cafd0700";
        let tx = WitnessTx::deserialize_hex(tx_hex).unwrap();

        let args = WitnessSighashArgs {
            index: 1,
            sighash_flag: Sighash::Single,
            prevout_script: &vec![].into(),
            prevout_value: 120000,
        };

        match tx.sighash(&args) {
            Err(TxError::SighashSingleBug) => {}
            _ => assert!(false, "expected sighash single bug unsupported"),
        }
    }

    #[test]
    fn it_calculates_legacy_sighash_of_witness_txns() {
        // pulled from riemann helpers
        let tx_hex = "01000000000101813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac0019430600";
        let tx = WitnessTx::deserialize_hex(tx_hex).unwrap();
        assert_eq!(tx.as_legacy().clone().into_witness(), tx);
        assert_eq!(tx.serialized_length(), tx_hex.len() / 2);

        let prevout_script_hex = "17a91424d6008f143af0cca57344069c46661aa4fcea2387";
        let prevout_script = Script::deserialize_hex(prevout_script_hex).unwrap();

        let all = Hash256Digest::deserialize_hex(
            "b85c4f8d1377cc138225dd9b319d0a4ca547f7884270640f44c5fcdf269e0fe8",
        )
        .unwrap();
        let all_anyonecanpay = Hash256Digest::deserialize_hex(
            "3b67a5114cc9fc837ddd6f6ec11bde38db5f68c34ab6ece2a043d7b25f2cf8bb",
        )
        .unwrap();
        let single = Hash256Digest::deserialize_hex(
            "1dab67d768be0380fc800098005d1f61744ffe585b0852f8d7adc12121a86938",
        )
        .unwrap();
        let single_anyonecanpay = Hash256Digest::deserialize_hex(
            "d4687b93c0a9090dc0a3384cd3a594ce613834bb37abc56f6032e96c597547e3",
        )
        .unwrap();

        let txid = Hash256Digest::deserialize_hex(
            "03ee4f7a4e68f802303bc659f8f817964b4b74fe046facc3ae1be4679d622c45",
        )
        .unwrap();
        assert_eq!(tx.txid(), txid.into());

        let mut args = LegacySighashArgs {
            index: 0,
            sighash_flag: Sighash::All,
            prevout_script: &prevout_script,
        };

        assert_eq!(tx.legacy_sighash(&args).unwrap(), all);
        args.sighash_flag = Sighash::AllACP;
        assert_eq!(tx.legacy_sighash(&args).unwrap(), all_anyonecanpay);
        args.sighash_flag = Sighash::Single;
        assert_eq!(tx.legacy_sighash(&args).unwrap(), single);
        args.sighash_flag = Sighash::SingleACP;
        assert_eq!(tx.legacy_sighash(&args).unwrap(), single_anyonecanpay);
    }

    #[test]
    fn it_gets_sighash_flags_from_u8s() {
        let cases = [
            (0x01, Sighash::All),
            (0x02, Sighash::None),
            (0x3, Sighash::Single),
            (0x81, Sighash::AllACP),
            (0x82, Sighash::NoneACP),
            (0x83, Sighash::SingleACP),
        ];
        let errors = [
            (0x84, TxError::UnknownSighash(0x84)),
            (0x16, TxError::UnknownSighash(0x16)),
            (0x34, TxError::UnknownSighash(0x34)),
            (0xab, TxError::UnknownSighash(0xab)),
            (0x39, TxError::UnknownSighash(0x39)),
            (0x00, TxError::UnknownSighash(0x00)),
            (0x30, TxError::UnknownSighash(0x30)),
            (0x4, TxError::UnknownSighash(0x4)),
        ];
        for case in cases.iter() {
            assert_eq!(Sighash::from_u8(case.0).unwrap(), case.1)
        }
        for case in errors.iter() {
            match Sighash::from_u8(case.0) {
                Err(TxError::UnknownSighash(v)) => assert_eq!(case.0, v),
                _ => assert!(false, "expected err unknown sighash"),
            }
        }
    }
}
