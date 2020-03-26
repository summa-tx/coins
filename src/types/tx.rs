use std::io::Write;

use crate::{
    hashes::{
        marked::{Digest, MarkedDigest, MarkedDigestWriter},
    },
    ser::{Ser}
};

/// A `TXOIdentifier` represents the network's unique identifier an output. In Bitcoin this is an
/// outpoint.
pub trait TXOIdentifier {}

/// An `Input` spends a specific TXO, and typically contains a `TXOIdentifier` for that TXO.
pub trait Input{
    /// An input must define what type contains the TXO ID it is spending.
    type TXOIdentifier: TXOIdentifier;
}

/// A RecipientIdentifier represents the network's identifier for a recipient. In Bitcoin this is
/// a script pubkey.
pub trait RecipientIdentifier {}

/// An Output represents a new TXO being created. It has an associated `RecipientIdentifier`.
pub trait Output {
    /// The associated `RecipientIdentifier` type that describes to whom the output is paid.
    type RecipientIdentifier: RecipientIdentifier;
}

/// Basic functionality for a Transaction
///
/// This trait has been generalized to support transactions from Non-Bitcoin networks. The
/// transaction specificies which types it considers to be inputs and outputs, and a struct that
/// contains its Sighash arguments. This allows others to define custom transaction types with
/// unique functionality.
pub trait Transaction<'a>: Ser {
    /// An associated error type, using in Results returned by the Transaction.
    type Error;
    /// A Digest type that underlies the associated marked hash, and is returned by `sighash()`.
    type Digest: Digest + Ser;
    /// The Input type for the transaction
    type TxIn: Input + Ser;
    /// The Output type for the transaction
    type TxOut: Output + Ser;
    /// A type describing arguments for the sighash function for this transaction.
    type SighashArgs;
    /// A marked hash (see crate::hashes::marked) to be used as the transaction ID type.
    type TXID: MarkedDigest<Digest = Self::Digest>;
    /// A type that implements `HashWriter`. Used to generate the `TXID` and `Sighash`.
    type HashWriter: MarkedDigestWriter<Self::Digest>;

    /// Instantiate a new Transaction by specifying inputs and outputs.
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

    /// Calculates and returns the transaction's ID. The default TXID is simply the digest of the
    /// serialized transaction.
    /// TODO: memoize
    fn txid(&self) -> Self::TXID {
        let mut w = Self::HashWriter::default();
        self.serialize(&mut w).expect("No IOError from hash functions");
        w.finish_marked()
    }

    /// Generate the digest that must be signed to authorize inputs. For Bitcoin transactions
    /// this is a function of the transaction, and the input's prevout.
    ///
    /// # Note:
    ///
    /// For Bitcoin, this will write the DEFAULT sighash for the current transaction type. For
    /// witness transactions, that is the BIP143 sighash. When signing Legacy inputs included in a
    /// witness transaction, use `write_legacy_sighash_preimage` instead.
    fn write_sighash_preimage<W: Write>(
        &self,
        writer: &mut W,
        _args: &Self::SighashArgs
    ) -> Result<(), Self::Error>;

    /// Calls `write_sighash_preimage` with the provided arguments and a new HashWriter.
    /// Returns the sighash digest which should be signed.
    fn sighash(&self, args: &Self::SighashArgs) -> Result<Self::Digest, Self::Error> {
        let mut w = Self::HashWriter::default();
        self.write_sighash_preimage(&mut w, args)?;
        Ok(w.finish())
   }
}
