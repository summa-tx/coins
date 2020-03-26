//! The `bitcoin::nets` module cotains Bitcoin network definitions. These are the main interface
//! for accessing the library.
//!
//! Expected user flow is to import the network and access the transaction builder through it.
//! This gives the user immediate access to the full bitcoin toolchain via a single import.
//!
//! ```compile_fail
//! let b = BitcoinMainnet::tx_builder();
//! b.version(2)
//!  .spend(Outpoint::default(), 0xaabbccdd)
//!  .pay(0x8888_8888_8888_8888, Address::WPKH("bc1qvyyvsdcd0t9863stt7u9rf37wx443lzasg0usy".to_owned()))
//!  .pay(0x7777_7777_7777_7777, Address::SH("377mKFYsaJPsxYSB5aFfx8SW3RaN5BzZVh".to_owned()))
//!  .build()
//!  .serialize_hex();
//! ```
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
        script::{ScriptPubkey},
        transactions::{
            LegacyTx,
            WitnessTx,
            WitnessTransaction,
        },
        txin::{BitcoinTxIn},
        txout::{TxOut},
    },
    nets::{Network},
    enc::{AddressEncoder},
};

/// A trait for a Bitcoin network. Specifies that Witness Txns must use the same Input and Output
/// format as Legacy transactions.
pub trait BitcoinNetwork<'a>: Network<'a> {
    /// An associated witness transaction type.
    type WTx: WitnessTransaction<'a, TxIn = Self::TxIn, TxOut = Self::TxOut>;
}

/// A newtype for Bitcoin networks, parameterized by an encoder. We change the encoder to
/// differentiate between main, test, and signet.
pub struct Bitcoin<T: AddressEncoder>(PhantomData<T>);

impl<'a, T> Network<'a> for Bitcoin<T>
where
    T: AddressEncoder<Address = Address, Error = EncodingError, RecipientIdentifier = ScriptPubkey>
{
    type Address = Address;
    type Error = EncodingError;
    type RecipientIdentifier = ScriptPubkey;
    type Encoder = T;
    type TxIn = BitcoinTxIn;
    type TxOut = TxOut;
    type Tx = LegacyTx;
    type Builder = LegacyBuilder<T>;
}

impl<'a, T> BitcoinNetwork<'a> for Bitcoin<T>
where
    T: AddressEncoder<Address = Address, Error = EncodingError, RecipientIdentifier = ScriptPubkey>
{
    type WTx = WitnessTx;
}

/// A fully-parameterized BitcoinMainnet. This is the main interface for accessing the library.
pub type BitcoinMainnet<'a> = Bitcoin<MainnetEncoder>;

/// A fully-parameterized BitcoinTestnet. This is the main interface for accessing the library.
pub type BitcoinTestnet<'a> = Bitcoin<TestnetEncoder>;

/// A fully-parameterized BitcoinSignet. This is the main interface for accessing the library.
pub type BitcoinSignet<'a> = Bitcoin<SignetEncoder>;


#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        bitcoin::{BitcoinOutpoint},
        builder::{TxBuilder},
        ser::{Ser},
    };

    #[test]
    fn it_has_sensible_syntax() {
        let b = BitcoinMainnet::tx_builder()
            .version(2)
            .spend(BitcoinOutpoint::default(), 0xaabbccdd)
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
