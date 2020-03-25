
use crate::{
    enc::{
        encoder::{AddressEncoder},
    },
    types::{
        txin::{Outpoint},
        tx::{self, Transaction, WitnessTransaction},
    },
};

/// A builder-pattern interface for constructing transactions. Implementations should accumulate
/// inputs, outputs, witnesses, and other TX data, and then `build()` a Transaction object from
/// the accumulated data.
pub trait TxBuilder<'a> {
    /// The Transaction type returned by `build()`
    type Transaction: Transaction<'a>;

    /// An AddressEncoder that handles encoding and decoding network addresses. This is used in
    /// the `pay` function to decode addresses into Scripts.
    type Encoder: AddressEncoder;

    /// A WitnessTransaction type. This represents the Witness transaction associated with this
    /// builder. We add this associated type so that `extend_witnesses` can accept a vector of
    /// witnesses.
    ///
    /// If implementing TxBuilder for a network that doesn't support Witnesses, make a dummy type
    /// that implements WitnessTransaction, and use it here.
    type WitnessTransaction: WitnessTransaction<'a>;

    /// An associated WitnessBuilder. This is used as the return type for `extend_witnesses`.
    /// Calling `extend_witnesses` should return a new `WitnessBuilder` with all information
    /// carried over. This allows for a magic builder experience, where the user can be naive of
    /// the changed type.
    ///
    /// If implementing TxBuilder for a network that doesn't support Witnesses, use `Self` here.
    type WitnessBuilder: TxBuilder<'a>;

    /// Instantiate a new builder
    fn new() -> Self;

    /// Set or overwrite the transaction version.
    fn version(self, version: u32) -> Self;

    /// Spend an outpoint. Adds an unsigned TxIn spending the associated outpoint with the
    /// specified sequence number.
    fn spend<I: Into<Outpoint>>(self, prevout: I, sequence: u32) -> Self;

    /// Pay an Address. Adds a TxOut paying `value` to `address.`
    fn pay(self, value: u64, address: <Self::Encoder as AddressEncoder>::Address) -> Self;

    /// Add a set of TxIns to the transaction.
    fn extend_inputs<I>(self, inputs: I) -> Self
    where
        I: IntoIterator<Item = <Self::Transaction as tx::Transaction<'a>>::TxIn>;

    /// Add a set of TxOuts to the transaction.
    fn extend_outputs<I>(self, outputs: I) -> Self
    where
        I: IntoIterator<Item = <Self::Transaction as tx::Transaction<'a>>::TxOut>;

    /// Add a set of witnesses to the transaction, and return a witness builder.
    fn extend_witnesses<I>(self, outputs: I) -> Self::WitnessBuilder
    where
        I: IntoIterator<Item = <Self::WitnessTransaction as tx::WitnessTransaction<'a>>::Witness>;

    /// Set or overwrite the transaction locktime.
    fn locktime(self, locktime: u32) -> Self;

    /// Consume the builder and produce a transaction from the builder's current state.
    fn build(self) -> Self::Transaction;
}

/// A WitnessTxBuilder. This should provide all the same functionality as the TxBuilder, but build
/// Witness Txs.
///
/// If your network does not support witnesses, set `type LegacyBuilder = Self;`.
pub trait WitTxBuilder<'a>: TxBuilder<'a> {
    type LegacyBuilder: TxBuilder<'a>;
}
