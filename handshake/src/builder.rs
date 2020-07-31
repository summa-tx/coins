//! Implementations of the `TxBuilder` for Handshake transactions.
//!
//! The builder is best accessed via the preconstructed network objects in `nets.rs`.

use std::marker::PhantomData;

use coins_core::{
    builder::TxBuilder,
    enc::{AddressEncoder, EncodingResult},
    types::tx::Transaction,
};

use crate::{
    enc::encoder::{Address, HandshakeEncoderMarker},
    types::{
        covenant::Covenant,
        tx::{HandshakeTransaction, HandshakeTx},
        txin::{HandshakeOutpoint, HandshakeTxIn},
        txout::TxOut,
        lockingscript::{Witness, LockingScript},
    },
};

/// This is a generic builder for Handshake transactions.
///
/// Note: due to Handshake consensus rules, the order of inputs and outputs may be semantically
/// meaningful. E.g. when signing a transaction with the `SINGLE` sighash mode.
///
/// It is parameterized with an address encoder, so that the same struct and logic can be used on
/// mainnet and testnet.
#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeTxBuilder<T: AddressEncoder> {
    version: u32,
    vin: Vec<HandshakeTxIn>,
    vout: Vec<TxOut>,
    locktime: u32,
    witnesses: Vec<Witness>,
    encoder: PhantomData<fn(T) -> T>,
}

impl<T> HandshakeTxBuilder<T>
where
    T: HandshakeEncoderMarker,
{
    /// Add a set of witnesses to the transaction, and return a witness builder.
    pub fn extend_witnesses<I>(mut self, outputs: I) -> Self
    where
        I: IntoIterator<Item = Witness>,
    {
        self.witnesses.extend(outputs);
        self
    }

    /// Set the script sig at a specific input. Do nothing if the vin is not that long.
    pub fn set_witness(mut self, input_idx: usize, witness: Witness) -> Self {
        if input_idx >= self.vin.len() {
            self
        } else {
            self.witnesses[input_idx] = witness;
            self
        }
    }

    /// Consume self, produce a tx
    pub fn build(self) -> HandshakeTx {
        <HandshakeTx as HandshakeTransaction>::new(
            self.version,
            self.vin,
            self.vout,
            self.witnesses,
            self.locktime,
        )
    }

    /// Add an output paying `value` to `script_pubkey`
    pub fn pay_locking_script(mut self, value: u64, locking_script: LockingScript) -> Self {
        let output = TxOut::new(value, locking_script, Covenant::null());
        self.vout.push(output);
        self
    }
}

impl<T> HandshakeTxBuilder<T>
where
T: HandshakeEncoderMarker,
{
    fn pay_covenant(mut self, value: u64, address: &Address, covenant: Covenant) -> EncodingResult<Self> {
        let locking_script = T::decode_address(&address)?;
        let output = TxOut::new(value, locking_script, covenant);
        self.vout.push(output);
        Ok(self)
    }
}

impl<T> TxBuilder for HandshakeTxBuilder<T>
where
    T: HandshakeEncoderMarker,
{
    type Encoder = T;
    type Transaction = HandshakeTx;

    fn new() -> Self {
        Self {
            version: 0,
            vin: vec![],
            vout: vec![],
            locktime: 0,
            witnesses: vec![],
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
            encoder: PhantomData,
        }
    }

    fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    fn spend<I>(mut self, prevout: I, sequence: u32) -> Self
    where
        I: Into<HandshakeOutpoint>,
    {
        self.vin.push(HandshakeTxIn::new(
            prevout.into(),
            sequence,
        ));
        self
    }

    fn pay(self, value: u64, address: &Address) -> EncodingResult<Self> {
        let locking_script = T::decode_address(&address)?;
        Ok(self.pay_locking_script(value, locking_script))
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
        I: IntoIterator<Item = HandshakeTxIn>,
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

    fn build(self) -> Self::Transaction {
        <HandshakeTx as HandshakeTransaction>::new(
            self.version,
            self.vin,
            self.vout,
            self.witnesses,
            self.locktime,
        ).into()
    }
}
