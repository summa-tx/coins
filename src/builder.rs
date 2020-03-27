//! The `builder` module defines an abstract `TxBuilder` trait. A concrete implementation for
//! Bitcoin can be found in the `bitcoin` module

use crate::{
    enc::{AddressEncoder},
    types::{
        tx::{Transaction, Input},
    },
};

/// A builder-pattern interface for constructing transactions. Implementations should accumulate
/// inputs, outputs, witnesses, and other TX data, and then `build()` a Transaction object from
/// the accumulated data.
pub trait TxBuilder<'a>: std::marker::Sized {
    /// The Transaction type returned by `build()`
    type Transaction: Transaction<'a>;

    /// An AddressEncoder that handles encoding and decoding network addresses. This is used in
    /// the `pay` function to decode addresses into associated `RecipientIdentifier`s.
    type Encoder: AddressEncoder;

    /// Instantiate a new builder
    fn new() -> Self;

    /// Set or overwrite the transaction version.
    ///
    /// If implementing a network without a version field, feel free to leave this as a NOP
    fn version(self, version: u32) -> Self;

    /// Spend an outpoint. Adds an unsigned input spending the associated outpoint with the
    /// specified sequence number.
    fn spend<I>(self, prevout: I, sequence: u32) -> Self
    where
        I: Into<<<Self::Transaction as Transaction<'a>>::TxIn as Input>::TXOIdentifier>;

    /// Pay an Address. Adds an output paying `value` to `address.`
    fn pay(self, value: u64, address: <Self::Encoder as AddressEncoder>::Address) -> Result<Self, <Self::Encoder as AddressEncoder>::Error>;

    /// Add a set of inputs to the transaction.
    fn extend_inputs<I>(self, inputs: I) -> Self
    where
        I: IntoIterator<Item = <Self::Transaction as Transaction<'a>>::TxIn>;

    /// Add a set of outputs to the transaction.
    fn extend_outputs<I>(self, outputs: I) -> Self
    where
        I: IntoIterator<Item = <Self::Transaction as Transaction<'a>>::TxOut>;

    /// Set or overwrite the transaction locktime.
    ///
    /// If implementing a network without a locktime field, feel free to leave this as a NOP
    fn locktime(self, locktime: u32) -> Self;

    /// Consume the builder and produce a transaction from the builder's current state.
    fn build(self) -> Self::Transaction;
}
