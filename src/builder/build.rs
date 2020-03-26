use crate::{
    bitcoin::{Outpoint},  // TODO: REFACTOR OUT AND GENERALIZE
    enc::{
        encoder::{AddressEncoder},
    },
    types::{
        tx::{self, Transaction},
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

    /// Set or overwrite the transaction locktime.
    fn locktime(self, locktime: u32) -> Self;

    /// Consume the builder and produce a transaction from the builder's current state.
    fn build(self) -> Self::Transaction;
}
