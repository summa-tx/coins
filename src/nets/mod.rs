use std::marker::{PhantomData};

use crate::{
    builder::{BitcoinBuilder, TxBuilder},
    types::{
        bitcoin::{LegacyTx, WitnessTx},
        tx::{Transaction, WitnessTransaction},
    },
    enc::encoders::{
        NetworkEncoder,
        MainnetEncoder,
        TestnetEncoder,
        SignetEncoder,
    },
};

// // TODO: Add tx types here
// pub struct Network<'a, Enc, Tx, WTx, B>
// where
//     Enc: NetworkEncoder,
//     Tx: Transaction<'a>,
//     WTx: WitnessTransaction<'a>,
//     B: TxBuilder<'a, Transaction = Tx, WitnessTransaction = WTx>,
// {
//     encoder: PhantomData<Enc>,
//     legacy_transaction: PhantomData<Tx>,
//     witness_transaction: PhantomData<WTx>,
//     builder: PhantomData<B>,
// }

pub trait Network<'a> {
    type Encoder: NetworkEncoder;
    type Tx: Transaction<'a>;
    type WTx: WitnessTransaction<'a>;
    type Builder: TxBuilder<'a, Self::Encoder>;
}

pub struct Bitcoin<T: NetworkEncoder>(PhantomData<T>);

impl<'a, T: NetworkEncoder> Network<'a> for Bitcoin<T> {
    type Encoder = T;
    type Tx = LegacyTx;
    type WTx = WitnessTx;
    type Builder = BitcoinBuilder;
}

pub type BitcoinMainnet<'a> = Bitcoin<MainnetEncoder>;
pub type BitcoinRegtest<'a> = Bitcoin<TestnetEncoder>;
pub type BitcoinSignet<'a> = Bitcoin<SignetEncoder>;
