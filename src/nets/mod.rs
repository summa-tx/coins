use std::marker::{PhantomData};

use crate::{
    builder::{BitcoinBuilder, TxBuilder},
    types::{
        bitcoin::{LegacyTx, WitnessTx},
        script::{Script},
        tx::{Transaction, WitnessTransaction},
    },
    enc::{
        bases::{
            Address,
            EncodingResult,
        },
        encoders::{
            NetworkEncoder,
            MainnetEncoder,
            TestnetEncoder,
            SignetEncoder,
        },
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
    type Builder: TxBuilder<'a, Encoder = Self::Encoder>;

    fn builder() -> Self::Builder {
        Self::Builder::new()
    }

    fn encode_address(a: Script) -> EncodingResult<Address> {
        Self::Encoder::encode_address(a)
    }

    fn decode_address(addr: Address) -> EncodingResult<Script> {
        Self::Encoder::decode_address(addr)
    }
}

pub struct Bitcoin<T: NetworkEncoder>(PhantomData<T>);

impl<'a, T: NetworkEncoder> Network<'a> for Bitcoin<T> {
    type Encoder = T;
    type Tx = LegacyTx;
    type WTx = WitnessTx;
    type Builder = BitcoinBuilder<T>;
}

pub type BitcoinMainnet<'a> = Bitcoin<MainnetEncoder>;
pub type BitcoinRegtest<'a> = Bitcoin<TestnetEncoder>;
pub type BitcoinSignet<'a> = Bitcoin<SignetEncoder>;

#[cfg(test)]
mod test {
    use super::*;
    use crate::types::{
        primitives::{Ser},
        txin::{Outpoint}
    };

    #[test]
    fn it_hash_sensible_syntax() {
        let mut b = BitcoinMainnet::builder()
            .version(2)
            .spend(Outpoint::default(), 32)
            // .pay(33, "bc1qvyyvsdcd0t9863stt7u9rf37wx443lzasg0usy")  // Errors b/c of encoder bug
            .build()
            .serialize_hex();
        println!("{:?}", b);
        let u = BitcoinMainnet::decode_address(Address::WPKH("bc1qvyyvsdcd0t9863stt7u9rf37wx443lzasg0usy".to_owned()));
        println!("({:?})", &u);
        assert_eq!(true, false, "u is an error");
    }
}
