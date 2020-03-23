use std::io::Write;

use crate::{
    hashes::{
        marked::{DigestMarker, MarkedHash},
        writer::{HashWriter},
    },
    types::{
        primitives::{Ser, TxResult},
    },
};

/// Basic functionality for a Transaction
///
/// This trait has been generalized to support transactions from Non-Bitcoin networks. The
/// transaction specificies which types it considers to be inputs and outputs, and a struct that
/// contains its Sighash arguments. This allows others to define custom transaction types with
/// unique functionality.
pub trait Transaction<'a>: Ser {
    type Digest: DigestMarker;
    /// The Input type for the transaction
    type TxIn;
    /// The Output type for the transaction
    type TxOut;
    /// A type describing arguments for the sighash function for this transaction
    type SighashArgs;
    /// A marked hash (see crate::hashes::marked) to be used as teh transaction ID type.
    type TXID: MarkedHash<Self::Digest>;
    /// A type that implements `HashWriter`. Used to generate the Sighash
    type HashWriter: HashWriter<Self::Digest>;

    fn new<I, O>(
        version: u32,
        vin: I,
        vout: O,
        locktime: u32
    ) -> Self
    where
        I: Into<Vec<Self::TxIn>>,
        O: Into<Vec<Self::TxOut>>;

    /// Returns the transaction version number
    fn version(&self) -> u32;

    /// Returns a reference to the transaction input vector
    fn inputs(&'a self) -> &'a[Self::TxIn];

    /// Returns a reference the the transaction output vector
    fn outputs(&'a self) -> &'a[Self::TxOut];

    /// Returns the transaction's nLocktime field
    fn locktime(&self) -> u32;

    /// Calculates and returns the transaction's ID. The default TXID is simply the serialized
    /// transaction. However, Witness transactions will have to override this in order to avoid
    /// serializing witnesses.
    /// TODO: memoize
    fn txid(&self) -> Self::TXID {
        let mut w = Self::HashWriter::default();
        self.serialize(&mut w).expect("No IOError from hash functions");
        w.finish_marked()
    }

    /// Serializes the transaction in the sighash format, depending on the args provided. Writes
    /// the result to `writer`. Used in `legacy_sighash`. Abstracts of the sighash serialization
    /// logic from the hasher used.
    ///
    /// SIGHASH_ALL commits to ALL inputs, and ALL outputs. It indicates that
    /// no further modification of the transaction is allowed without
    /// invalidating the signature.
    ///
    /// SIGHASH_ALL + ANYONECANPAY commits to ONE input and ALL outputs. It
    /// indicates that anyone may add additional value to the transaction, but
    /// that no one may modify the payments made. Any extra value added above
    /// the sum of output values will be given to miners as part of the tx fee.
    ///
    /// SIGHASH_SINGLE commits to ALL inputs, and ONE output. It indicates that/
    /// anyone may append additional outputs to the transaction to reroute
    /// funds from the inputs. Additional inputs cannot be added without
    /// invalidating the signature. It is logically difficult to use securely,
    /// as it consents to funds being moved, without specifying their
    /// destination.
    ///
    /// SIGHASH_SINGLE commits specifically the the output at the same index as
    /// the input being signed. If there is no output at that index, (because,
    /// e.g. the input vector is longer than the output vector) it behaves
    /// insecurely, and we do not implement that protocol bug.
    ///
    /// SIGHASH_SINGLE + ANYONECANPAY commits to ONE input and ONE output. It
    /// indicates that anyone may add additional value to the transaction, and
    /// route value to any other location. The signed input and output must be
    /// included in the fully-formed transaction at the same index in their
    /// respective vectors.
    ///
    /// For Legacy sighash documentation, see here:
    ///
    /// - https://en.bitcoin.it/wiki/OP_CHECKSIG#Hashtype_SIGHASH_ALL_.28default.29
    ///
    /// # Note
    ///     After signing the digest, you MUST append the sighash indicator
    ///     byte to the resulting signature. This will be 0x01 (SIGHASH_ALL),
    ///     0x81 (SIGHASH_ALL + SIGHASH_ANYONECANPAY), 0x81.
    fn write_legacy_sighash_preimage<W: Write>(
        &self,
        writer: &mut W,
        _args: &Self::SighashArgs
    ) -> TxResult<()>;

    /// Calls `write_legacy_sighash_preimage` with the provided arguments and a new HashWriter.
    /// Returns the sighash digest which should be signed.
    fn legacy_sighash(&self, args: &Self::SighashArgs) -> TxResult<Self::Digest> {
        let mut w = Self::HashWriter::default();
        self.write_legacy_sighash_preimage(&mut w, args)?;
        Ok(w.finish())
   }
}

/// Basic functionality for a Witness Transaction
///
/// This trait has been generalized to support transactions from Non-Bitcoin networks. The
/// transaction specificies which types it considers to be inputs and outputs, and a struct that
/// contains its Sighash arguments. This allows others to define custom transaction types with
/// unique functionality.
pub trait WitnessTransaction<'a>: Transaction<'a> {
    type WTXID: MarkedHash<Self::Digest>;
    type WitnessSighashArgs;
    type Witness;

    fn new<I, O, W>(
        version: u32,
        vin: I,
        vout: O,
        witnesses: W,
        locktime: u32
    ) -> Self
    where
        I: Into<Vec<Self::TxIn>>,
        O: Into<Vec<Self::TxOut>>,
        W: Into<Vec<Self::Witness>>;

    fn wtxid(&self) -> Self::WTXID;
    fn write_witness_sighash_preimage<W: Write>(&self, _writer: &mut W, args: &Self::WitnessSighashArgs) -> TxResult<()>;
    fn witness_sighash(&self, args: &Self::WitnessSighashArgs) -> TxResult<Self::Digest> {
        let mut w = Self::HashWriter::default();
        self.write_witness_sighash_preimage(&mut w, args)?;
        Ok(w.finish())
    }
}
