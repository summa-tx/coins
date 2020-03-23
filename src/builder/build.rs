use crate::types::{
    bitcoin::{LegacyTx, WitnessTx},
    script::{Script, Witness},
    tx::{self, Transaction, WitnessTransaction},
    txin::{Outpoint, TxIn},
    txout::{TxOut},
};

pub trait TxBuilder<'a> {
    type Transaction: Transaction<'a>;
    type WitnessTransaction: WitnessTransaction<'a>;

    fn version(self, version: u32) -> Self;
    fn spend<T: Into<Outpoint>>(self, prevout: T, sequence: u32) -> Self;
    fn extend_inputs<T: IntoIterator<Item=<Self::Transaction as tx::Transaction<'a>>::TxIn>>(self, inputs: T) -> Self;
    fn extend_outputs<T: IntoIterator<Item=<Self::Transaction as tx::Transaction<'a>>::TxOut>>(self, outputs: T) -> Self;
    fn extend_witnesses<T: IntoIterator<Item=<Self::WitnessTransaction as tx::WitnessTransaction<'a>>::Witness>>(self, outputs: T) -> Self;
    fn locktime(self, locktime: u32) -> Self;
    fn build_witness(self) -> Self::WitnessTransaction;
    fn build_legacy(self) -> Self::Transaction;
}

pub struct Builder {
    version: u32,
    vin: Vec<TxIn>,
    vout: Vec<TxOut>,
    witnesses: Vec<Witness>,
    locktime: u32,
}

impl<'a> TxBuilder<'a> for Builder {
    type Transaction = LegacyTx;
    type WitnessTransaction = WitnessTx;

    fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    fn spend<T: Into<Outpoint>>(mut self, prevout: T, sequence: u32) -> Self {
        self.vin.push(TxIn::new(prevout.into(), Script::default(), sequence));
        self
    }

    fn extend_inputs<T: IntoIterator<Item=TxIn>>(mut self, inputs: T) -> Self  {
        self.vin.extend(inputs);
        self
    }

    fn extend_outputs<T: IntoIterator<Item=TxOut>>(mut self, outputs: T) -> Self  {
        self.vout.extend(outputs);
        self
    }

    fn extend_witnesses<T: IntoIterator<Item=Witness>>(mut self, outputs: T) -> Self  {
        self.witnesses.extend(outputs);
        self
    }

    fn locktime(mut self, locktime: u32) -> Self {
        self.locktime = locktime;
        self
    }

    fn build_witness(self) -> Self::WitnessTransaction {
        <Self::WitnessTransaction as tx::WitnessTransaction>::new(
            self.version, self.vin, self.vout, self.witnesses, self.locktime
        )
    }

    fn build_legacy(self) -> Self::Transaction {
        Self::Transaction::new(
            self.version, self.vin, self.vout, self.locktime
        )
    }
}

impl Builder
{
}
