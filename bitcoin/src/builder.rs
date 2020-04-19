//! Implementations of the `TxBuilder` for Bitcoin transactions. This module includes both a
//! `LegacyBuilder` for legacy transactions, and a `WitnessBuilder` for Witness transactions
//! The two types are very similar, but a witness builder will always build witness transactions.
//! As soon as the caller adds a witness to a legacy builder, it is substituted behind-the-scenes
//! with a witness builder. This means that the caller doesn't typically need to worry about the
//! implementation details. They can simply use the builder transparently.
//!
//! The builder can also be explicitly converted using the `as_witness` and `as_legacy` functions.
//!
//! The builder is best accessed via the preconstructed network objects in `nets.rs`.

use std::marker::{PhantomData};

use riemann_core::{
    builder::{TxBuilder},
    enc::{AddressEncoder},
    types::{
        tx::{Transaction},
    },
};

use crate::{
    bases::{EncodingError, EncodingResult},
    encoder::{Address},
    script::{ScriptSig, ScriptPubkey, Witness},
    transactions::{WitnessTransaction, LegacyTx, WitnessTx},
    txin::{BitcoinOutpoint, BitcoinTxIn},
    txout::{TxOut},
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

/// LegacyBuilder provides a struct on which we implement `TxBuilder` for legacy Bitcoin
/// Transactions. Its associated types are the standard Bitcoin `LegacyTx`, and `WitnessTx`, and
/// the WitnessBuilder. It is parameterized with an address encoder, so that the same struct and
/// logic can be used on mainnet and testnet.
#[derive(Debug, Clone)]
pub struct LegacyBuilder<T: AddressEncoder> {
    version: u32,
    vin: Vec<BitcoinTxIn>,
    vout: Vec<TxOut>,
    locktime: u32,
    encoder: PhantomData<*const T>
}

/// WitnessBuilder implements `TxBuilder` and `WitTxBuilder`. The only difference between
/// `WitnessBuilder` and `LegacyBuilder` is that `WitnessBuilder` builds Witness transactions.
/// This is implemented by having `WitnessBuilder` contain an internal `LegacyBuilder` which all
/// non-witness updates are applied to.
#[derive(Debug, Clone)]
pub struct WitnessBuilder<T: AddressEncoder> {
    builder: LegacyBuilder<T>,
    witnesses: Vec<Witness>,
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
    T: AddressEncoder<Address = Address, Error = EncodingError, RecipientIdentifier = ScriptPubkey>
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

    fn from_tx(tx: &Self::Transaction) -> Self {
        Self {
            version: tx.version(),
            vin: tx.inputs().to_vec(),
            vout: tx.outputs().to_vec(),
            locktime: tx.locktime(),
            encoder: PhantomData,
        }
    }


    fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    fn spend<I>(mut self, prevout: I, sequence: u32) -> Self
    where
        I: Into<BitcoinOutpoint>,
    {
        self.vin.push(BitcoinTxIn::new(prevout.into(), ScriptSig::default(), sequence));
        self
    }

    fn pay(mut self, value: u64, address: &Address) -> EncodingResult<Self> {
        let output = TxOut::new(value, T::decode_address(&address)?);
        self.vout.push(output);
        Ok(self)
    }

    fn insert_input(mut self, index: usize, input: <Self::Transaction as Transaction<'a>>::TxIn) -> Self {
        self.vin.insert(index, input);
        self
    }

    fn extend_inputs<I>(mut self, inputs: I) -> Self
    where
        I: IntoIterator<Item = BitcoinTxIn>
    {
        self.vin.extend(inputs);
        self
    }

    fn insert_output(mut self, index: usize, output: <Self::Transaction as Transaction<'a>>::TxOut) -> Self {
        self.vout.insert(index, output);
        self
    }

    fn extend_outputs<I>(mut self, outputs: I) -> Self
    where
        I: IntoIterator<Item=TxOut>
    {
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
    T: AddressEncoder<Address = Address, Error = EncodingError, RecipientIdentifier = ScriptPubkey>
{
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
    T: AddressEncoder<Address = Address, Error = EncodingError, RecipientIdentifier = ScriptPubkey>
{
    type Encoder = T;

    type Transaction = WitnessTx;

    fn new() -> Self {
        Self{
            builder: LegacyBuilder::<T>::new(),
            witnesses: vec![],
        }
    }

    fn from_tx(tx: &Self::Transaction) -> Self {
        Self {
            builder: LegacyBuilder {
                version: tx.version(),
                vin: tx.inputs().to_vec(),
                vout: tx.outputs().to_vec(),
                locktime: tx.locktime(),
                encoder: PhantomData,
            },
            witnesses: tx.witnesses().to_vec(),
        }
    }

    fn version(mut self, version: u32) -> Self {
        self.builder.version = version;
        self
    }

    fn spend<I>(mut self, prevout: I, sequence: u32) -> Self
    where
        I: Into<BitcoinOutpoint>
    {
        self.builder.vin.push(BitcoinTxIn::new(prevout.into(), ScriptSig::default(), sequence));
        self
    }

    fn pay(mut self, value: u64, address: &Address) -> EncodingResult<Self> {
        let output = TxOut::new(value, T::decode_address(&address)?);
        self.builder.vout.push(output);
        Ok(self)
    }

    fn insert_input(mut self, index: usize, input: <Self::Transaction as Transaction<'a>>::TxIn) -> Self {
        self.builder.vin.insert(index, input);
        self
    }

    fn extend_inputs<I>(mut self, inputs: I) -> Self
    where
        I: IntoIterator<Item = BitcoinTxIn>
    {
        self.builder.vin.extend(inputs);
        self
    }

    fn insert_output(mut self, index: usize, output: <Self::Transaction as Transaction<'a>>::TxOut) -> Self {
        self.builder.vout.insert(index, output);
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
    T: AddressEncoder<Address = Address, Error = EncodingError, RecipientIdentifier = ScriptPubkey> {

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
    T: AddressEncoder<Address = Address, Error = EncodingError, RecipientIdentifier = ScriptPubkey>
{
    type LegacyBuilder = LegacyBuilder<T>;

    fn as_legacy(self) -> Self::LegacyBuilder {
        self.builder
    }

}
