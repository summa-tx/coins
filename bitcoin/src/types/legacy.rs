//! Legacy Transactions
use bitcoin_spv::types::Hash256Digest;
use std::io::{Read, Write};

use riemann_core::{
    hashes::hash256::Hash256Writer,
    ser::{ByteFormat},
    types::tx::Transaction,
};

use crate::{
    hashes::{TXID},
    types::{
        script::{Script, ScriptSig, Witness},
        transactions::*,
        txin::{BitcoinTxIn, Vin},
        txout::{TxOut, Vout},
        witness::*,
    },
};
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
pub struct LegacySighashArgs {
    /// The index of the input we'd like to sign
    pub index: usize,
    /// The sighash mode to use.
    pub sighash_flag: Sighash,
    /// The script used in the prevout, which must be signed. In complex cases involving
    /// `OP_CODESEPARATOR` this must be the subset of the script containing the `OP_CHECKSIG`
    /// currently being executed.
    pub prevout_script: Script,
}

/// A Legacy (non-witness) Transaction.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq, Default)]
pub struct LegacyTx {
    /// The version number. Usually 1 or 2.
    pub(crate) version: u32,
    /// The vector of inputs
    pub(crate) vin: Vin,
    /// The vector of outputs
    pub(crate) vout: Vout,
    /// The nLocktime field.
    pub(crate) locktime: u32,
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

impl Transaction for LegacyTx {
    type TxError = TxError;
    type Digest = Hash256Digest;
    type TxIn = BitcoinTxIn;
    type TxOut = TxOut;
    type SighashArgs = LegacySighashArgs;
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

    fn inputs(&self) -> &[Self::TxIn] {
        &self.vin
    }

    fn outputs(&self) -> &[Self::TxOut] {
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

        let mut copy_tx: Self = self.legacy_sighash_prep(args.index, &args.prevout_script);
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

impl BitcoinTransaction for LegacyTx {
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
