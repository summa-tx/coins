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

use std::marker::PhantomData;

use riemann_core::{builder::TxBuilder, enc::AddressEncoder, types::tx::Transaction};

use crate::{
    enc::{
        bases::{EncodingError, EncodingResult},
        encoder::Address,
    },
    types::{
        legacy::LegacyTx,
        script::{ScriptPubkey, ScriptSig, Witness},
        tx::BitcoinTransaction,
        txin::{BitcoinOutpoint, BitcoinTxIn},
        txout::TxOut,
        witness::{WitnessTransaction, WitnessTx},
    },
};

/// A `TxBuilder` that builds Bitcoin transactions. This trait extends `TxBuilder` to provide
/// easy conversion between Legacy and Witness bitcoin builders.
pub trait BitcoinBuilder: TxBuilder {
    /// A WitnessTransaction type. This represents the Witness transaction associated with this
    /// builder. We add this associated type so that `extend_witnesses` can accept a vector of
    /// witnesses.
    type WitnessTransaction: WitnessTransaction;

    /// An associated WitnessBuilder. This is used as the return type for `extend_witnesses`.
    /// Calling `extend_witnesses` should return a new `WitnessBuilder` with all information
    /// carried over. This allows for a magic builder experience, where the user can be naive of
    /// the changed type.
    type WitnessBuilder: TxBuilder;

    /// Add a set of witnesses to the transaction, and return a witness builder.
    fn extend_witnesses<I>(self, outputs: I) -> Self::WitnessBuilder
    where
        I: IntoIterator<Item = <Self::WitnessTransaction as WitnessTransaction>::Witness>;

    /// Converts the builder into a witness builder.
    fn as_witness(self) -> Self::WitnessBuilder;

    /// Set the script sig at a specific input. Do nothing if the vin is not that long.
    fn set_script_sig(self, input_idx: usize, script_sig: ScriptSig) -> Self;
}

/// A WitnessTxBuilder. This should provide all the same functionality as the TxBuilder, but build
/// Witness Txs.
pub trait WitTxBuilder: BitcoinBuilder {
    /// The associated `LegacyBuilder` type..
    type LegacyBuilder: BitcoinBuilder;

    /// Convert the witness builder into a legacy builder. Discards any existing witnesses.
    fn as_legacy(self) -> Self::LegacyBuilder;
}

/// LegacyBuilder provides a struct on which we implement `TxBuilder` for legacy Bitcoin
/// Transactions. Its associated types are the standard Bitcoin `LegacyTx`, and `WitnessTx`, and
/// the WitnessBuilder. It is parameterized with an address encoder, so that the same struct and
/// logic can be used on mainnet and testnet.
#[derive(Debug, Clone, PartialEq)]
pub struct LegacyBuilder<T: AddressEncoder> {
    version: u32,
    vin: Vec<BitcoinTxIn>,
    vout: Vec<TxOut>,
    locktime: u32,
    encoder: PhantomData<fn(T) -> T>,
}

/// WitnessBuilder implements `TxBuilder` and `WitTxBuilder`. The only difference between
/// `WitnessBuilder` and `LegacyBuilder` is that `WitnessBuilder` builds Witness transactions.
/// This is implemented by having `WitnessBuilder` contain an internal `LegacyBuilder` which all
/// non-witness updates are applied to.
#[derive(Debug, Clone, PartialEq)]
pub struct WitnessBuilder<T: AddressEncoder> {
    builder: LegacyBuilder<T>,
    witnesses: Vec<Witness>,
}

impl<T: AddressEncoder> From<LegacyBuilder<T>> for WitnessBuilder<T> {
    fn from(t: LegacyBuilder<T>) -> WitnessBuilder<T> {
        WitnessBuilder {
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

impl<T> TxBuilder for LegacyBuilder<T>
where
    T: AddressEncoder<Address = Address, Error = EncodingError, RecipientIdentifier = ScriptPubkey>,
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

    fn from_tx(tx: Self::Transaction) -> Self {
        Self {
            version: tx.version,
            vin: tx.vin,
            vout: tx.vout,
            locktime: tx.locktime,
            encoder: PhantomData,
        }
    }

    fn from_tx_ref(tx: &Self::Transaction) -> Self {
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
        self.vin.push(BitcoinTxIn::new(
            prevout.into(),
            ScriptSig::default(),
            sequence,
        ));
        self
    }

    fn pay(mut self, value: u64, address: &Address) -> EncodingResult<Self> {
        let output = TxOut::new(value, T::decode_address(&address)?);
        self.vout.push(output);
        Ok(self)
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

    fn build(self) -> Self::Transaction {
        Self::Transaction::new(self.version, self.vin, self.vout, self.locktime)
    }
}

impl<T> BitcoinBuilder for LegacyBuilder<T>
where
    T: AddressEncoder<Address = Address, Error = EncodingError, RecipientIdentifier = ScriptPubkey>,
{
    type WitnessTransaction = WitnessTx;
    type WitnessBuilder = WitnessBuilder<T>;

    fn extend_witnesses<I: IntoIterator<Item = Witness>>(self, witnesses: I) -> WitnessBuilder<T> {
        WitnessBuilder::from(self).extend_witnesses(witnesses)
    }

    fn as_witness(self) -> Self::WitnessBuilder {
        self.into()
    }

    fn set_script_sig(mut self, input_idx: usize, script_sig: ScriptSig) -> Self {
        if input_idx >= self.vin.len() {
            self
        } else {
            self.vin[input_idx].script_sig = script_sig;
            self
        }
    }
}

impl<T> TxBuilder for WitnessBuilder<T>
where
    T: AddressEncoder<Address = Address, Error = EncodingError, RecipientIdentifier = ScriptPubkey>,
{
    type Encoder = T;

    type Transaction = WitnessTx;

    fn new() -> Self {
        Self {
            builder: LegacyBuilder::<T>::new(),
            witnesses: vec![],
        }
    }

    fn from_tx(tx: Self::Transaction) -> Self {
        Self {
            builder: LegacyBuilder {
                version: tx.legacy_tx.version,
                vin: tx.legacy_tx.vin,
                vout: tx.legacy_tx.vout,
                locktime: tx.legacy_tx.locktime,
                encoder: PhantomData,
            },
            witnesses: tx.witnesses,
        }
    }

    fn from_tx_ref(tx: &Self::Transaction) -> Self {
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
        I: Into<BitcoinOutpoint>,
    {
        self.builder.vin.push(BitcoinTxIn::new(
            prevout.into(),
            ScriptSig::default(),
            sequence,
        ));
        self
    }

    fn pay(mut self, value: u64, address: &Address) -> EncodingResult<Self> {
        let output = TxOut::new(value, T::decode_address(&address)?);
        self.builder.vout.push(output);
        Ok(self)
    }

    fn insert_input(
        mut self,
        index: usize,
        input: <Self::Transaction as Transaction>::TxIn,
    ) -> Self {
        let index = std::cmp::min(index, self.builder.vin.len());
        self.builder.vin.insert(index, input);
        self
    }

    fn extend_inputs<I>(mut self, inputs: I) -> Self
    where
        I: IntoIterator<Item = BitcoinTxIn>,
    {
        self.builder.vin.extend(inputs);
        self
    }

    fn insert_output(
        mut self,
        index: usize,
        output: <Self::Transaction as Transaction>::TxOut,
    ) -> Self {
        let index = std::cmp::min(index, self.builder.vout.len());
        self.builder.vout.insert(index, output);
        self
    }

    fn extend_outputs<I: IntoIterator<Item = TxOut>>(mut self, outputs: I) -> Self {
        self.builder.vout.extend(outputs);
        self
    }

    fn locktime(mut self, locktime: u32) -> Self {
        self.builder.locktime = locktime;
        self
    }

    fn build(self) -> Self::Transaction {
        WitnessTransaction::new(
            self.builder.version,
            self.builder.vin,
            self.builder.vout,
            self.witnesses,
            self.builder.locktime,
        )
    }
}

impl<T> BitcoinBuilder for WitnessBuilder<T>
where
    T: AddressEncoder<Address = Address, Error = EncodingError, RecipientIdentifier = ScriptPubkey>,
{
    type WitnessTransaction = WitnessTx;
    type WitnessBuilder = Self;

    fn extend_witnesses<I: IntoIterator<Item = Witness>>(mut self, outputs: I) -> Self {
        self.witnesses.extend(outputs);
        self
    }

    fn as_witness(self) -> Self::WitnessBuilder {
        self
    }

    fn set_script_sig(mut self, input_idx: usize, script_sig: ScriptSig) -> Self {
        if input_idx >= self.builder.vin.len() {
            self
        } else {
            self.builder.vin[input_idx].script_sig = script_sig;
            self
        }
    }
}

impl<T> WitTxBuilder for WitnessBuilder<T>
where
    T: AddressEncoder<Address = Address, Error = EncodingError, RecipientIdentifier = ScriptPubkey>,
{
    type LegacyBuilder = LegacyBuilder<T>;

    fn as_legacy(self) -> Self::LegacyBuilder {
        self.builder
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::types::{BitcoinOutpoint, BitcoinTransaction};

    const TX_HEX: &'static str = "01000000000101f1e46af69e3ab97a3b195dbc34af1e2131ec31d53a6e331ab714504d27b6bd940400000000ffffffff03e0a57e000000000017a914e88869b88866281ab166541ad8aafba8f8aba47a8780841e00000000001976a9140e5c3c8d420c7f11e88d76f7b860d471e6517a4488aca31843a7380000002200201bf8a1831db5443b42a44f30a121d1b616d011ab15df62b588722a845864cc990400483045022100a74e04708f8032ce177c09642556945a5f5938de821edfa5df959c0ca61cb00d02207ea3b9353e0250a8a1440809a24a1d73c1c26d2c46e12dd96c7564ea4f8c6ee001473044022066611fd52c104f8be623cca6195ab0aa5dfc58408297744ff0d7b32da218c7d002200302be14cc76abaab271d848448d0b3cd3083d4dea76af495d1b1137d129d3120169522102489ec44d0358045c4be092978c40e574790820ebbc3bf069bffc12bda57af27d2102a4bf3a2bdbbcf2e68bbf04566052bbaf45dfe230a7a6de18d97c242fd85e9abc21038d4d2936c6e57f2093c2a43cb17fcf582afb1d312a1e129f900156075a490ae753ae00000000";

    #[test]
    fn basic_builder_routines() {
        let mut builder =
            WitnessBuilder::<crate::enc::MainnetEncoder>::from_hex_tx(TX_HEX).unwrap();
        let input = builder.builder.vin[0].clone();
        let output = builder.builder.vout[0].clone();
        let witness = builder.witnesses[0].clone();

        assert_eq!(builder.witnesses.len(), 1);
        assert_eq!(builder.builder.vin.len(), 1);
        assert_eq!(builder.builder.vout.len(), 3);

        builder = builder
            .insert_input(2, input.clone())
            .extend_inputs(vec![input.clone()])
            .spend(BitcoinOutpoint::null(), 100)
            .insert_output(0, output.clone())
            .extend_outputs(vec![output.clone()])
            .pay(
                0x8000_0000,
                &Address::PKH("12JvxPk4mT4PKMVHuHc1aQGBZpotQWQwF6".to_owned()),
            )
            .unwrap()
            .extend_witnesses(vec![witness.clone()])
            .as_witness()
            .version(2)
            .locktime(33);

        let tx = builder.clone().build();
        let without_witnesses = builder.clone().as_legacy().build();
        assert_eq!(tx.version(), 2);
        assert_eq!(tx.locktime(), 33);
        assert_eq!(tx.witnesses().len(), 2);
        assert_eq!(tx.inputs().len(), 4);
        assert_eq!(tx.outputs().len(), 6);
        assert_eq!(tx.as_legacy(), &without_witnesses);

        let mut legacy_builder = builder.clone().as_legacy();

        legacy_builder = legacy_builder
            .insert_input(2, input.clone())
            .extend_inputs(vec![input])
            .spend(BitcoinOutpoint::null(), 100)
            .insert_output(0, output.clone())
            .extend_outputs(vec![output])
            .pay(
                0x8000_0000,
                &Address::PKH("12JvxPk4mT4PKMVHuHc1aQGBZpotQWQwF6".to_owned()),
            )
            .unwrap()
            .locktime(1000)
            .version(1);
        let legacy_tx = legacy_builder.clone().build();
        let c = legacy_builder.clone().as_witness().as_legacy();
        assert_eq!(&legacy_tx, &c.build());
        assert_eq!(legacy_tx.version(), 1);
        assert_eq!(legacy_tx.locktime(), 1000);
        assert_eq!(legacy_tx.inputs().len(), 7);
        assert_eq!(legacy_tx.outputs().len(), 9);

        let legacy_tx = legacy_builder
            .clone()
            .extend_witnesses(vec![witness])
            .build();
        assert_eq!(legacy_tx.witnesses().len(), 1);
    }
}
