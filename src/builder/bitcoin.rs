use std::marker::{PhantomData};

use crate::{
    builder::{TxBuilder},
    enc::{
        bases::{EncodingError},
        encoder::{AddressEncoder},
        bitcoin::{Address},
    },
    types::{
        bitcoin::{WitnessTransaction, LegacyTx, WitnessTx},
        script::{Script, Witness},
        tx::{Transaction},
        txin::{Outpoint, TxIn},
        txout::{TxOut},
    },
};

pub trait BitcoinBuilder<'a>: TxBuilder<'a> {
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

    /// Add a set of witnesses to the transaction, and return a witness builder.
    fn extend_witnesses<I>(self, outputs: I) -> Self::WitnessBuilder
    where
    I: IntoIterator<Item = <Self::WitnessTransaction as WitnessTransaction<'a>>::Witness>;
}


/// A WitnessTxBuilder. This should provide all the same functionality as the TxBuilder, but build
/// Witness Txs.
///
/// If your network does not support witnesses, set `type LegacyBuilder = Self;`.
pub trait WitTxBuilder<'a>: BitcoinBuilder<'a> {
    type LegacyBuilder: BitcoinBuilder<'a>;
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
        // LegacyBuilder {
        //     version: t.version,
        //     vin: t.vin,
        //     vout: t.vout,
        //     locktime: t.locktime,
        //     encoder: t.encoder,
        // }
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

    fn spend<I: Into<Outpoint>>(mut self, prevout: I, sequence: u32) -> Self {
        self.builder.vin.push(TxIn::new(prevout.into(), Script::default(), sequence));
        self
    }

    /// TODO: address as string
    fn pay(mut self, value: u64, address: Address) -> Self {
        let output = TxOut::new(value, T::decode_address(address).expect("TODO: handle"));
        self.builder.vout.push(output);
        self
    }

    fn extend_inputs<I: IntoIterator<Item=TxIn>>(mut self, inputs: I) -> Self  {
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
}

impl<'a, T> WitTxBuilder<'a> for WitnessBuilder<T>
where
    T: AddressEncoder<Address = Address, Error = EncodingError>
{
    type LegacyBuilder = LegacyBuilder<T>;
}
