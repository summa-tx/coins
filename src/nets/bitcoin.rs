
use std::marker::{PhantomData};

use crate::{
    builder::{BitcoinBuilder},
    nets::{Network},
    enc::{
        bases::{
            EncodingError,
        },
        bitcoin::{
            Address,
            MainnetEncoder,
            TestnetEncoder,
            SignetEncoder,
        },
        encoders::{
            AddressEncoder,
        },
    },
    types::{
        txin::{TxIn},
        txout::{TxOut},
        bitcoin::{LegacyTx, WitnessTx},
    },
};


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
    use crate::{
        build::{TxBuilder},
        types::{
            primitives::{Ser},
            txin::{Outpoint}
        }
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
