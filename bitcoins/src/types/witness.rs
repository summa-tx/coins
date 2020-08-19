//! Witness Transactions

use bitcoin_spv::types::Hash256Digest;
use std::io::{Read, Write};

use coins_core::{
    hashes::{
        hash256::Hash256Writer,
        marked::{MarkedDigest, MarkedDigestWriter},
    },
    ser::ByteFormat,
    types::tx::Transaction,
};

use crate::{
    hashes::{TXID, WTXID},
    types::{
        legacy::*,
        script::{Script, Witness},
        tx::*,
        txin::BitcoinTxIn,
        txout::TxOut,
    },
};

/// Basic functionality for a Witness Transaction
///
/// This trait has been generalized to support transactions from Non-Bitcoin networks. The
/// transaction specificies which types it considers to be inputs and outputs, and a struct that
/// contains its Sighash arguments. This allows others to define custom transaction types with
/// unique functionality.
pub trait WitnessTransaction: BitcoinTransaction {
    /// The MarkedDigest type for the Transaction's Witness TXID
    type WTXID: MarkedDigest<Digest = Self::Digest>;
    /// The BIP143 sighash args needed to sign an input
    type WitnessSighashArgs;
    /// A type that represents this transactions per-input `Witness`.
    type Witness;

    /// Instantiate a new WitnessTx from the arguments.
    fn new<I, O, W>(
        version: u32,
        vin: I,
        vout: O,
        witnesses: W,
        locktime: u32,
    ) -> Result<Self, Self::TxError>
    where
        I: Into<Vec<Self::TxIn>>,
        O: Into<Vec<Self::TxOut>>,
        W: Into<Vec<Self::Witness>>,
        Self: Sized;

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
pub struct WitnessSighashArgs {
    /// The index of the input we'd like to sign
    pub index: usize,
    /// The sighash mode to use.
    pub sighash_flag: Sighash,
    /// The script used in the prevout, which must be signed. In complex cases involving
    /// `OP_CODESEPARATOR` this must be the subset of the script containing the `OP_CHECKSIG`
    /// currently being executed.
    pub prevout_script: Script,
    /// The value of the prevout.
    pub prevout_value: u64,
}

/// A witness transaction. Any transaction that contains 1 or more witnesses.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq, Default)]
pub struct WitnessTx {
    pub(crate) legacy_tx: LegacyTx,
    pub(crate) witnesses: Vec<Witness>,
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

impl Transaction for WitnessTx {
    type TxError = TxError;
    type Digest = Hash256Digest;
    type TxIn = BitcoinTxIn;
    type TxOut = TxOut;
    type SighashArgs = WitnessSighashArgs;
    type TXID = TXID;
    type HashWriter = Hash256Writer;

    fn new<I, O>(version: u32, vin: I, vout: O, locktime: u32) -> Result<Self, Self::TxError>
    where
        I: Into<Vec<Self::TxIn>>,
        O: Into<Vec<Self::TxOut>>,
        Self: Sized,
    {
        let input_vector: Vec<BitcoinTxIn> = vin.into();
        let witnesses = input_vector.iter().map(|_| Witness::default()).collect();

        let legacy_tx = LegacyTx::new(version, input_vector, vout, locktime)?;
        Ok(Self {
            legacy_tx,
            witnesses,
        })
    }

    fn inputs(&self) -> &[Self::TxIn] {
        &self.legacy_tx.vin
    }

    fn outputs(&self) -> &[Self::TxOut] {
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

impl BitcoinTransaction for WitnessTx {
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

impl WitnessTransaction for WitnessTx {
    type WTXID = WTXID;
    type WitnessSighashArgs = WitnessSighashArgs;
    type Witness = Witness;

    /// Create a new WitnessTx. Since witnesses correspond to inputs,
    /// ensure that there are the same number of witnesses as inputs.
    /// The number of witnesses will be trimmed if there are too many
    /// and will be filled with empty witnesses if too few.
    fn new<I, O, W>(
        version: u32,
        vin: I,
        vout: O,
        witnesses: W,
        locktime: u32,
    ) -> Result<Self, Self::TxError>
    where
        I: Into<Vec<Self::TxIn>>,
        O: Into<Vec<Self::TxOut>>,
        W: Into<Vec<Self::Witness>>,
        Self: Sized,
    {
        let vins = vin.into();
        let mut wits = witnesses.into();
        if wits.len() != vins.len() {
            wits.resize(vins.len(), Witness::default());
        }

        let legacy_tx = LegacyTx::new(version, vins, vout, locktime)?;

        Ok(Self {
            legacy_tx,
            witnesses: wits,
        })
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
        len += coins_core::ser::prefix_byte_len(self.legacy_tx.vin.len() as u64) as usize;
        len += self.legacy_tx.vin.serialized_length();
        len += coins_core::ser::prefix_byte_len(self.legacy_tx.vout.len() as u64) as usize;
        len += self.legacy_tx.vout.serialized_length();
        for witness in self.witnesses.iter() {
            len += coins_core::ser::prefix_byte_len(self.witnesses.len() as u64) as usize;
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
mod test {
    use super::*;
    use crate::types::{BitcoinTxIn, TxOut, Witness, WitnessStackItem};

    #[test]
    fn it_should_ensure_correct_amount_of_witnesses_addition() {
        let vin = vec![BitcoinTxIn::default(), BitcoinTxIn::default()];
        let vout = vec![TxOut::default()];
        let witnesses = vec![];

        let expect = vin.len();
        let tx = <WitnessTx as WitnessTransaction>::new(2, vin, vout, witnesses, 0).unwrap();
        assert_eq!(tx.witnesses.len(), expect);
    }

    #[test]
    fn it_should_ensure_correct_amount_of_witnesses_subtraction() {
        let vin = vec![BitcoinTxIn::default()];
        let vout = vec![TxOut::default()];

        let expected_witness = vec![WitnessStackItem::new(vec![1, 2, 3, 4])];
        let witnesses = vec![expected_witness.clone(), Witness::default()];

        let expected_size = vin.len();
        let tx = <WitnessTx as WitnessTransaction>::new(2, vin, vout, witnesses, 0).unwrap();
        assert_eq!(tx.witnesses.len(), expected_size);
        assert_eq!(expected_witness, tx.witnesses[0]);
    }
}
