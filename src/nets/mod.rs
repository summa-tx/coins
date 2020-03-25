use std::marker::{PhantomData};

use crate::{
    builder::{BitcoinBuilder, TxBuilder},
    types::{
        txin::{TxIn},
        txout::{TxOut},
        bitcoin::{LegacyTx, WitnessTx},
        script::{Script},
        tx::{Transaction, WitnessTransaction},
    },
    enc::{
        bases::{
            EncodingError,
        },
        encoders::{
            Address,
            AddressEncoder,
            MainnetEncoder,
            TestnetEncoder,
            SignetEncoder,
        },
    },
};

/// A Network describes a possible Bitcoin-like network. It is primarily a collection of types
/// with enforced relationships, but also provides convenient access the the transaction builder,
/// the address encoder, and other network-associated functionality.
///
/// Because we separate some commonly conflated functionality (e.g. output scripts and addresses)
/// we provide Networks to enforce relationships between them. This is why the `Network` trait's
/// associated types are complex. It exists to guarantee consistency of associated types across a
/// large number of disparate elements.
///
/// In particular, we want to guarantee that `Tx` and `WTx` use the same `TxIn` and `TxOut`
/// types, that the `Builder` uses that specific pair of `Tx` and `WTx` and that the `Builder`
/// uses the correct `Encoder`.
///
/// ```compile_fail
/// let b = BitcoinMainnet::tx_builder();
/// b.version(2)
///  .spend(Outpoint::default(), 0xaabbccdd)
///  .pay(0x8888_8888_8888_8888, Address::WPKH("bc1qvyyvsdcd0t9863stt7u9rf37wx443lzasg0usy".to_owned()))
///  .pay(0x7777_7777_7777_7777, Address::SH("377mKFYsaJPsxYSB5aFfx8SW3RaN5BzZVh".to_owned()))
///  .build()
///  .serialize_hex();
/// ```
pub trait Network<'a> {
    type Address;
    type Error;
    type Encoder: AddressEncoder<Address = Self::Address, Error = Self::Error>;

    type TxIn;
    type TxOut;

    type Tx: Transaction<'a, TxIn = Self::TxIn, TxOut = Self::TxOut>;
    type WTx: WitnessTransaction<'a, TxIn = Self::TxIn, TxOut = Self::TxOut>;
    type Builder: TxBuilder<'a, Encoder = Self::Encoder, Transaction = Self::Tx, WitnessTransaction = Self::WTx>;

    fn tx_builder() -> Self::Builder {
        Self::Builder::new()
    }

    fn encode_address(a: Script) -> Result<Self::Address, Self::Error> {
        Self::Encoder::encode_address(a)
    }

    fn decode_address(addr: Self::Address) -> Result<Script, Self::Error> {
        Self::Encoder::decode_address(addr)
    }
}

pub struct Bitcoin<T: AddressEncoder>(PhantomData<T>);

impl<'a, T> Network<'a> for Bitcoin<T>
where
    T: AddressEncoder<Address = Address, Error = EncodingError>
{
    type Address = Address;
    type Error = EncodingError;
    type Encoder = T;
    type TxIn = TxIn;
    type TxOut = TxOut;
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
    fn it_has_sensible_syntax() {
        let b = BitcoinMainnet::tx_builder()
            .version(2)
            .spend(Outpoint::default(), 0xaabbccdd)
            .pay(0x8888_8888_8888_8888, Address::WPKH("bc1qvyyvsdcd0t9863stt7u9rf37wx443lzasg0usy".to_owned()))
            .pay(0x7777_7777_7777_7777, Address::SH("377mKFYsaJPsxYSB5aFfx8SW3RaN5BzZVh".to_owned()))
            .build()
            .serialize_hex();
        println!("{:?}", b);
        // let u = BitcoinMainnet::decode_address(Address::WPKH("bc1qvyyvsdcd0t9863stt7u9rf37wx443lzasg0usy".to_owned().to_uppercase()));
        // println!("({:?})", &u);
        // assert_eq!(true, false, "u is an error");
    }
}
