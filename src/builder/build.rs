use std::marker::{PhantomData};

use crate::{
    enc::{
        bases::{EncodingError},
        encoders::{Address, AddressEncoder},
    },
    types::{
        bitcoin::{LegacyTx, WitnessTx},
        script::{Script, Witness},
        tx::{self, Transaction, WitnessTransaction},
        txin::{Outpoint, TxIn},
        txout::{TxOut},
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
    fn pay(self, value: u64, address: Address) -> Self;

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

pub trait WitTxBuilder<'a>: TxBuilder<'a> {
    type LegacyBuilder: TxBuilder<'a>;
}

pub struct BitcoinBuilder<T: AddressEncoder> {
    version: u32,
    vin: Vec<TxIn>,
    vout: Vec<TxOut>,
    locktime: u32,
    encoder: PhantomData<T>
}

pub struct WitnessBuilder<T: AddressEncoder> {
    version: u32,
    vin: Vec<TxIn>,
    vout: Vec<TxOut>,
    witnesses: Vec<Witness>,
    locktime: u32,
    encoder: PhantomData<T>
}

impl<T: AddressEncoder> From<BitcoinBuilder<T>> for WitnessBuilder<T> {
    fn from(t: BitcoinBuilder<T>) -> WitnessBuilder<T> {
        WitnessBuilder{
            version: t.version,
            vin: t.vin,
            vout: t.vout,
            witnesses: vec![],
            locktime: t.locktime,
            encoder: t.encoder,
        }
    }
}

impl<T: AddressEncoder> From<WitnessBuilder<T>> for BitcoinBuilder<T> {
    fn from(t: WitnessBuilder<T>) -> BitcoinBuilder<T> {
        BitcoinBuilder {
            version: t.version,
            vin: t.vin,
            vout: t.vout,
            locktime: t.locktime,
            encoder: t.encoder,
        }
    }
}

impl<'a, T> TxBuilder<'a> for BitcoinBuilder<T>
where
    T: AddressEncoder<Address = Address, Error = EncodingError>
{
    type Encoder = T;

    type Transaction = LegacyTx;
    type WitnessTransaction = WitnessTx;
    type WitnessBuilder = WitnessBuilder<T>;

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

    fn spend<I: Into<Outpoint>>(mut self, prevout: I, sequence: u32) -> Self {
        self.vin.push(TxIn::new(prevout.into(), Script::default(), sequence));
        self
    }

    fn pay(mut self, value: u64, address: Address) -> Self {
        let output = TxOut::new(value, T::decode_address(address).expect("TODO: handle"));
        self.vout.push(output);
        self
    }

    fn extend_inputs<I: IntoIterator<Item=TxIn>>(mut self, inputs: I) -> Self  {
        self.vin.extend(inputs);
        self
    }

    fn extend_outputs<I: IntoIterator<Item=TxOut>>(mut self, outputs: I) -> Self  {
        self.vout.extend(outputs);
        self
    }

    fn extend_witnesses<I: IntoIterator<Item=Witness>>(self, witnesses: I) -> WitnessBuilder<T>  {
        WitnessBuilder::from(self).extend_witnesses(witnesses)
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

impl<'a, T> TxBuilder<'a> for WitnessBuilder<T>
where
    T: AddressEncoder<Address = Address, Error = EncodingError>
{
    type Encoder = T;

    type Transaction = WitnessTx;
    type WitnessTransaction = WitnessTx;
    type WitnessBuilder = Self;

    fn new() -> Self {
        Self{
            version: 0,
            vin: vec![],
            vout: vec![],
            witnesses: vec![],
            locktime: 0,
            encoder: PhantomData,
        }
    }

    fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    fn spend<I: Into<Outpoint>>(mut self, prevout: I, sequence: u32) -> Self {
        self.vin.push(TxIn::new(prevout.into(), Script::default(), sequence));
        self
    }

    /// TODO: address as string
    fn pay(mut self, value: u64, address: Address) -> Self {
        let output = TxOut::new(value, T::decode_address(address).expect("TODO: handle"));
        self.vout.push(output);
        self
    }

    fn extend_inputs<I: IntoIterator<Item=TxIn>>(mut self, inputs: I) -> Self  {
        self.vin.extend(inputs);
        self
    }

    fn extend_outputs<I: IntoIterator<Item=TxOut>>(mut self, outputs: I) -> Self  {
        self.vout.extend(outputs);
        self
    }

    fn extend_witnesses<I: IntoIterator<Item=Witness>>(mut self, outputs: I) -> Self  {
        self.witnesses.extend(outputs);
        self
    }

    fn locktime(mut self, locktime: u32) -> Self {
        self.locktime = locktime;
        self
    }

    fn build(self) -> Self::Transaction {
        WitnessTransaction::new(
            self.version, self.vin, self.vout, self.witnesses, self.locktime
        )
    }
}

impl<'a, T> WitTxBuilder<'a> for WitnessBuilder<T>
where
    T: AddressEncoder<Address = Address, Error = EncodingError>
{
    type LegacyBuilder = BitcoinBuilder<T>;
}
