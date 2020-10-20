//! Implementations of the `TxBuilder` for Bitcoin transactions. This builder automatically
//! selects between Legacy and Witness transactions based on its inputs. The user may also specify
//! the desired type using `build_legacy` or `build_witness`.
//!
//! This means that the caller doesn't typically need to worry about the implementation details.
//! They can simply use the builder transparently to produce the desired tx type.
//!
//! The builder is best accessed via the preconstructed network objects in `nets.rs`.

use std::marker::PhantomData;

use coins_core::{builder::TxBuilder, enc::AddressEncoder, types::tx::Transaction};

use crate::{
    enc::encoder::{Address, BitcoinEncoderMarker},
    types::{
        legacy::LegacyTx,
        script::{ScriptPubkey, ScriptSig, Witness},
        tx::{BitcoinTransaction, BitcoinTx},
        txin::{BitcoinOutpoint, BitcoinTxIn},
        txout::TxOut,
        witness::{WitnessTransaction, WitnessTx},
    },
};

/// This is a generic builder for Bitcoin transactions. It allows you to easily build legacy and
/// witness transactions.
///
/// Note: due to Bitcoin consensus rules, the order of inputs and outputs may be semantically
/// meaningful. E.g. when signing a transaction with the `SINGLE` sighash mode.
///
/// It is parameterized with an address encoder, so that the same struct and logic can be used on
/// mainnet and testnet.
#[derive(Debug, Clone, PartialEq)]
pub struct BitcoinTxBuilder<T: AddressEncoder> {
    version: u32,
    vin: Vec<BitcoinTxIn>,
    vout: Vec<TxOut>,
    locktime: u32,
    witnesses: Vec<Witness>,
    produce_witness: bool,
    encoder: PhantomData<fn(T) -> T>,
}

impl<T> BitcoinTxBuilder<T>
where
    T: BitcoinEncoderMarker,
{
    /// Add a set of witnesses to the transaction, and return a witness builder.
    pub fn extend_witnesses<I>(mut self, witnesses: I) -> Self
    where
        I: IntoIterator<Item = Witness>,
    {
        self.witnesses.extend(witnesses);
        self
    }

    /// Add an op_return output. Using this twice may render the transaction non-standard.
    pub fn op_return(mut self, message: &[u8]) -> Self {
        self.vout.push(TxOut::op_return(message));
        self
    }

    /// Set the script sig at a specific input. Do nothing if the vin is not that long.
    pub fn set_script_sig(mut self, input_idx: usize, script_sig: ScriptSig) -> Self {
        if input_idx >= self.vin.len() {
            self
        } else {
            self.vin[input_idx].script_sig = script_sig;
            self
        }
    }

    /// Consume self, produce a legacy tx. Discard any witness information in the builder
    pub fn build_legacy(self) -> Result<LegacyTx, <LegacyTx as Transaction>::TxError> {
        LegacyTx::new(self.version, self.vin, self.vout, self.locktime)
    }

    /// Consume self, produce a witness tx
    pub fn build_witness(self) -> Result<WitnessTx, <WitnessTx as Transaction>::TxError> {
        <WitnessTx as WitnessTransaction>::new(
            self.version,
            self.vin,
            self.vout,
            self.witnesses,
            self.locktime,
        )
    }

    /// Add an output paying `value` to `script_pubkey`
    pub fn pay_script_pubkey(mut self, value: u64, script_pubkey: ScriptPubkey) -> Self {
        let output = TxOut::new(value, script_pubkey);
        self.vout.push(output);
        self
    }
}

impl<T> TxBuilder for BitcoinTxBuilder<T>
where
    T: BitcoinEncoderMarker,
{
    type Encoder = T;
    type Transaction = BitcoinTx;

    fn new() -> Self {
        Self {
            version: 0,
            vin: vec![],
            vout: vec![],
            locktime: 0,
            witnesses: vec![],
            produce_witness: false,
            encoder: PhantomData,
        }
    }

    fn from_tx(tx: Self::Transaction) -> Self {
        Self {
            version: tx.version(),
            vin: tx.inputs().to_vec(),
            vout: tx.outputs().to_vec(),
            locktime: tx.locktime(),
            witnesses: tx.witnesses().to_vec(),
            produce_witness: tx.is_witness(),
            encoder: PhantomData,
        }
    }

    fn from_tx_ref(tx: &Self::Transaction) -> Self {
        Self {
            version: tx.version(),
            vin: tx.inputs().to_vec(),
            vout: tx.outputs().to_vec(),
            locktime: tx.locktime(),
            witnesses: tx.witnesses().to_vec(),
            produce_witness: tx.is_witness(),
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
        self.vin.push(BitcoinTxIn::new(
            prevout.into(),
            ScriptSig::default(),
            sequence,
        ));
        self
    }

    fn pay(self, value: u64, address: &Address) -> Self {
        let script_pubkey = T::decode_address(&address);
        self.pay_script_pubkey(value, script_pubkey)
    }

    fn insert_input(
        mut self,
        index: usize,
        input: <Self::Transaction as Transaction>::TxIn,
    ) -> Self {
        let index = std::cmp::min(index, self.vin.len());
        self.vin.insert(index, input);
        self
    }

    fn extend_inputs<I>(mut self, inputs: I) -> Self
    where
        I: IntoIterator<Item = BitcoinTxIn>,
    {
        self.vin.extend(inputs);
        self
    }

    fn insert_output(
        mut self,
        index: usize,
        output: <Self::Transaction as Transaction>::TxOut,
    ) -> Self {
        let index = std::cmp::min(index, self.vout.len());
        self.vout.insert(index, output);
        self
    }

    fn extend_outputs<I>(mut self, outputs: I) -> Self
    where
        I: IntoIterator<Item = TxOut>,
    {
        self.vout.extend(outputs);
        self
    }

    fn locktime(mut self, locktime: u32) -> Self {
        self.locktime = locktime;
        self
    }

    fn build(self) -> Result<Self::Transaction, <Self::Transaction as Transaction>::TxError> {
        if self.produce_witness || !self.witnesses.is_empty() {
            Ok(<WitnessTx as WitnessTransaction>::new(
                self.version,
                self.vin,
                self.vout,
                self.witnesses,
                self.locktime,
            )?
            .into())
        } else {
            Ok(LegacyTx::new(self.version, self.vin, self.vout, self.locktime)?.into())
        }
    }
}
