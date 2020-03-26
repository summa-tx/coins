use std::marker::{PhantomData};

use crate::{
    bitcoin::{
        bases::{
            EncodingError,
        },
        builder::{LegacyBuilder},
        encoder::{
            Address,
            MainnetEncoder,
            TestnetEncoder,
            SignetEncoder,
        },
        transactions::{
            LegacyTx,
            WitnessTx,
            WitnessTransaction,
        },
        txin::{TxIn},
        txout::{TxOut},
    },
    nets::{Network},
    enc::{AddressEncoder},
};

/// A trait for a Bitcoin network. Specifies that Witness Txns must use the same Input and Output
/// format as Legacy transactions.
pub trait BitcoinNetwork<'a>: Network<'a> {
    type WTx: WitnessTransaction<'a, TxIn = Self::TxIn, TxOut = Self::TxOut>;
}

/// A newtype for Bitcoin networks, parameterized by an encoder. We change the encoder to
/// differentiate between main, test, and signet.
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
    type Builder = LegacyBuilder<T>;
}

impl<'a, T> BitcoinNetwork<'a> for Bitcoin<T>
where
    T: AddressEncoder<Address = Address, Error = EncodingError>
{
    type WTx = WitnessTx;
}


/// A fully-parameterized BitcoinMainnet. This is the main interface for accessing the library.
pub type BitcoinMainnet<'a> = Bitcoin<MainnetEncoder>;

/// A fully-parameterized BitcoinTestnet. This is the main interface for accessing the library.
pub type BitcoinRegtest<'a> = Bitcoin<TestnetEncoder>;

/// A fully-parameterized BitcoinSignet. This is the main interface for accessing the library.
pub type BitcoinSignet<'a> = Bitcoin<SignetEncoder>;


#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        bitcoin::txin::{Outpoint},
        builder::{TxBuilder},
        types::primitives::{Ser},
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
