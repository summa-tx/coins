use std::marker::{PhantomData};

use crate::{
    enc::{
        bases::{Address},
        encoders::{NetworkEncoder},
    },
    types::{
        bitcoin::{LegacyTx, WitnessTx},
        script::{Script, Witness},
        tx::{self, Transaction, WitnessTransaction},
        txin::{Outpoint, TxIn},
        txout::{TxOut},
    },
};

pub trait TxBuilder<'a> {
    type Transaction: Transaction<'a>;
    type WitnessTransaction: WitnessTransaction<'a>;
    type Encoder: NetworkEncoder;
    type WitnessBuilder: TxBuilder<'a>;

    fn new() -> Self;
    fn version(self, version: u32) -> Self;
    fn spend<I: Into<Outpoint>>(self, prevout: I, sequence: u32) -> Self;
    fn pay(self, value: u64, address: Address) -> Self;
    fn extend_inputs<I: IntoIterator<Item=<Self::Transaction as tx::Transaction<'a>>::TxIn>>(self, inputs: I) -> Self;
    fn extend_outputs<I: IntoIterator<Item=<Self::Transaction as tx::Transaction<'a>>::TxOut>>(self, outputs: I) -> Self;
    fn extend_witnesses<I: IntoIterator<Item=<Self::WitnessTransaction as tx::WitnessTransaction<'a>>::Witness>>(self, outputs: I) -> Self::WitnessBuilder;
    fn locktime(self, locktime: u32) -> Self;
    fn build(self) -> Self::Transaction;
}

pub trait WitTxBuilder<'a>: TxBuilder<'a> {
    type Transaction: WitnessTransaction<'a>;
    type LegacyBuilder: TxBuilder<'a>;
}

pub struct BitcoinBuilder<T: NetworkEncoder> {
    version: u32,
    vin: Vec<TxIn>,
    vout: Vec<TxOut>,
    locktime: u32,
    encoder: PhantomData<T>
}

#[derive(Default)]
pub struct WitnessBuilder<T: NetworkEncoder> {
    version: u32,
    vin: Vec<TxIn>,
    vout: Vec<TxOut>,
    witnesses: Vec<Witness>,
    locktime: u32,
    encoder: PhantomData<T>
}

impl<T: NetworkEncoder> From<BitcoinBuilder<T>> for WitnessBuilder<T> {
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

impl<T: NetworkEncoder> From<WitnessBuilder<T>> for BitcoinBuilder<T> {
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

impl<'a, T: NetworkEncoder> TxBuilder<'a> for BitcoinBuilder<T> {
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

impl<'a, T: NetworkEncoder> TxBuilder<'a> for WitnessBuilder<T> {
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

impl<'a, T: NetworkEncoder> WitTxBuilder<'a> for WitnessBuilder<T> {
    type Transaction = WitnessTx;
    type LegacyBuilder = BitcoinBuilder<T>;
}
