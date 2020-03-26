//! Implementations of the `TxBuilder` for Bitcoin transactions. This module includes both a
//! `LegacyBuilder` for legacy transactions, and a `WitnessBuilder` for Witness transactions
//! The two types are very similar, but a witness builder will always build witness transactions.
//! As soon as the caller adds a witness to a legacy builder, it is substituted behind-the-scenes
//! with a witness builder. This means that the caller doesn't typically need to worry about the
//! implementation details. They can simply use the builder transparently.
//!
//! The builder can also be explicitly converted using the `as_witness` and `as_legacy` functions.
//!
//! The builder is best accessed via the preconstructed `BitcoinMainnet` objects in `nets.rs`.
//!
//! ```compile_fail
//! let legacy_builder = BitcoinMainnet::tx_builder();
//! let tx = legacy_builder
//!  .version(2)
//!  .spend(Outpoint::default(), 0xaabbccdd)
//!  .pay(0x8888_8888_8888_8888, Address::WPKH("bc1qvyyvsdcd0t9863stt7u9rf37wx443lzasg0usy".to_owned()))
//!  .pay(0x7777_7777_7777_7777, Address::SH("377mKFYsaJPsxYSB5aFfx8SW3RaN5BzZVh".to_owned()))
//!  .build();  // Legacy Transaction output
//!
//! let new_legacy_builder = BitcoinMainnet::tx_builder();
//! let tx = new_legacy_builder
//!  .version(2)
//!  .spend(Outpoint::default(), 0xaabbccdd)
//!  .pay(0x8888_8888_8888_8888, Address::WPKH("bc1qvyyvsdcd0t9863stt7u9rf37wx443lzasg0usy".to_owned()))
//!  .pay(0x7777_7777_7777_7777, Address::SH("377mKFYsaJPsxYSB5aFfx8SW3RaN5BzZVh".to_owned()))
//!  .locktime(300000)
//!  .extend_witnesses(vec![/*...*/])   // Automatically converts to a `WitnessBuilder` as soon as you add a witness
//!  .build();  // Witness Transaction output
//! ```

use std::marker::{PhantomData};

use crate::{
    bitcoin::{
        bases::{EncodingError},
        encoder::{Address},
        script::{Witness},
        transactions::{WitnessTransaction, LegacyTx, WitnessTx},
        txin::{TxIn},
        txout::{TxOut},
    },
    builder::{TxBuilder},
    enc::{AddressEncoder},
    types::{
        tx::{Transaction},
    },
};

/// A `TxBuilder` that builds Bitcoin transactions. This trait extends `TxBuilder` to provide
/// easy conversion between Legacy and Witness bitcoin builders.
pub trait BitcoinBuilder<'a>: TxBuilder<'a> {
    /// A WitnessTransaction type. This represents the Witness transaction associated with this
    /// builder. We add this associated type so that `extend_witnesses` can accept a vector of
    /// witnesses.
    type WitnessTransaction: WitnessTransaction<'a>;

    /// An associated WitnessBuilder. This is used as the return type for `extend_witnesses`.
    /// Calling `extend_witnesses` should return a new `WitnessBuilder` with all information
    /// carried over. This allows for a magic builder experience, where the user can be naive of
    /// the changed type.
    type WitnessBuilder: TxBuilder<'a>;

    /// Add a set of witnesses to the transaction, and return a witness builder.
    fn extend_witnesses<I>(self, outputs: I) -> Self::WitnessBuilder
    where
    I: IntoIterator<Item = <Self::WitnessTransaction as WitnessTransaction<'a>>::Witness>;

    /// Converts the builder into a witness builder.
    fn as_witness(self) -> Self::WitnessBuilder;
}

/// A WitnessTxBuilder. This should provide all the same functionality as the TxBuilder, but build
/// Witness Txs.
pub trait WitTxBuilder<'a>: BitcoinBuilder<'a> {
    /// The associated `LegacyBuilder` type..
    type LegacyBuilder: BitcoinBuilder<'a>;

    /// Convert the witness builder into a legacy builder. Discards any existing witnesses.
    fn as_legacy(self) -> Self::LegacyBuilder;
}

/// BitcoinBuilder provides a struct on which we implement `TxBuilder` for legacy Bitcoin
/// Transactions. Its associated types are the standard Bitcoin `LegacyTx`, and `WitnessTx`, and
/// the WitnessBuilder. It is parameterized with an address encoder, so that the same struct and
/// logic can be used on mainnet and testnet.
pub struct LegacyBuilder<T: AddressEncoder> {
    version: u32,
    vin: Vec<TxIn>,
    vout: Vec<TxOut>,
    locktime: u32,
    encoder: PhantomData<T>
}

/// WitnessBuilder implements `TxBuilder` and `WitTxBuilder`. The only difference between
/// `WitnessBuilder` and `LegacyBuilder` is that `WitnessBuilder` builds Witness transactions.
/// This is implemented by having `WitnessBuilder` contain an internal `LegacyBuilder` which all
/// non-witness updates are applied to.
pub struct WitnessBuilder<T: AddressEncoder> {
    builder: LegacyBuilder<T>,
    witnesses: Vec<Witness>,
    // encoder: PhantomData<T>
}

impl<T: AddressEncoder> From<LegacyBuilder<T>> for WitnessBuilder<T> {
    fn from(t: LegacyBuilder<T>) -> WitnessBuilder<T> {
        WitnessBuilder{
            builder: t,
            witnesses: vec![],
        }
    }
}

impl<T: AddressEncoder> From<WitnessBuilder<T>> for LegacyBuilder<T> {
    fn from(t: WitnessBuilder<T>) -> LegacyBuilder<T> {
        t.builder
    }
}

impl<'a, T> TxBuilder<'a> for LegacyBuilder<T>
where
    T: AddressEncoder<Address = Address, Error = EncodingError>
{
    type Encoder = T;

    type Transaction = LegacyTx;

    fn new() -> Self {
        Self {
            version: 0,
            vin: vec![],
            vout: vec![],
            locktime: 0,
            encoder: PhantomData,
        }
    }

    fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    // fn spend<I, M>(mut self, prevout: I, sequence: u32) -> Self
    // where
    //     I: Into<Outpoint<TXID>>,
    // {
    //     self.vin.push(TxIn::new(prevout.into(), Script::default(), sequence));
    //     self
    // }

    fn pay(mut self, value: u64, address: Address) -> Self {
        let output = TxOut::new(value, T::decode_address(address).expect("TODO: handle"));
        self.vout.push(output);
        self
    }

    fn extend_inputs<I>(mut self, inputs: I) -> Self
    where
        I: IntoIterator<Item = TxIn>
    {
        self.vin.extend(inputs);
        self
    }

    fn extend_outputs<I: IntoIterator<Item=TxOut>>(mut self, outputs: I) -> Self  {
        self.vout.extend(outputs);
        self
    }

    fn locktime(mut self, locktime: u32) -> Self {
        self.locktime = locktime;
        self
    }

    fn build(self) -> Self::Transaction {
        Self::Transaction::new(
            self.version, self.vin, self.vout, self.locktime
        )
    }
}

impl<'a, T> BitcoinBuilder<'a> for LegacyBuilder<T>
where
    T: AddressEncoder<Address = Address, Error = EncodingError> {
    type WitnessTransaction = WitnessTx;
    type WitnessBuilder = WitnessBuilder<T>;

    fn extend_witnesses<I: IntoIterator<Item=Witness>>(self, witnesses: I) -> WitnessBuilder<T>  {
        WitnessBuilder::from(self).extend_witnesses(witnesses)
    }

    fn as_witness(self) -> Self::WitnessBuilder {
        self.into()
    }
}

impl<'a, T> TxBuilder<'a> for WitnessBuilder<T>
where
    T: AddressEncoder<Address = Address, Error = EncodingError>
{
    type Encoder = T;

    type Transaction = WitnessTx;

    fn new() -> Self {
        Self{
            builder: LegacyBuilder::<T>::new(),
            witnesses: vec![],
        }
    }

    fn version(mut self, version: u32) -> Self {
        self.builder.version = version;
        self
    }

    // fn spend<I>(mut self, prevout: I, sequence: u32) -> Self
    // where
    //     I: Into<Outpoint<D>>
    // {
    //     self.builder.vin.push(TxIn::new(prevout.into(), Script::default(), sequence));
    //     self
    // }

    /// TODO: address as string
    fn pay(mut self, value: u64, address: Address) -> Self {
        let output = TxOut::new(value, T::decode_address(address).expect("TODO: handle"));
        self.builder.vout.push(output);
        self
    }

    fn extend_inputs<I>(mut self, inputs: I) -> Self
    where
        I: IntoIterator<Item = TxIn>
    {
        self.builder.vin.extend(inputs);
        self
    }

    fn extend_outputs<I: IntoIterator<Item=TxOut>>(mut self, outputs: I) -> Self  {
        self.builder.vout.extend(outputs);
        self
    }



    fn locktime(mut self, locktime: u32) -> Self {
        self.builder.locktime = locktime;
        self
    }

    fn build(self) -> Self::Transaction {
        WitnessTransaction::new(
            self.builder.version, self.builder.vin, self.builder.vout, self.witnesses, self.builder.locktime
        )
    }
}

impl<'a, T> BitcoinBuilder<'a> for WitnessBuilder<T>
where
    T: AddressEncoder<Address = Address, Error = EncodingError> {

    type WitnessTransaction = WitnessTx;
    type WitnessBuilder = Self;

    fn extend_witnesses<I: IntoIterator<Item=Witness>>(mut self, outputs: I) -> Self  {
        self.witnesses.extend(outputs);
        self
    }

    fn as_witness(self) -> Self::WitnessBuilder {
        self
    }
}

impl<'a, T> WitTxBuilder<'a> for WitnessBuilder<T>
where
    T: AddressEncoder<Address = Address, Error = EncodingError>
{
    type LegacyBuilder = LegacyBuilder<T>;

    fn as_legacy(self) -> Self::LegacyBuilder {
        self.builder
    }

}
