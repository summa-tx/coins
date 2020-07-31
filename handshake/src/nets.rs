//! The `handshake::nets` module cotains Handshake network definitions. These are the main interface
//! for accessing the library.
//!
//! Expected user flow is to import the network and access the transaction builder through it.
//! This gives the user immediate access to the full bitcoin toolchain via a single import.
//!
//! ```
//! use handshakes::{HandshakeMainnet, enc::Address, types::txin::Outpoint};
//! use coins_core::{
//!     nets::Network,
//!     builder::TxBuilder,
//!     ser::ByteFormat,
//! };
//!
//! let address = HandshakeMainnet::string_to_address("hs1qqzlmrc6phwz2drwshstcr30vuhjacv5z0u2x9l").unwrap();
//!
//! let b = HandshakeMainnet::tx_builder();
//! b.version(2)
//!  .spend(Outpoint::default(), 0xaabbccdd)
//!  .pay(0x8888_8888_8888_8888, &address).unwrap()
//!  .pay(0x7777_7777_7777_7777, &Address::WSH("hs1qjhgt8dwvhwapf2a5v9865nmrrqhhqlz38w3zze".to_owned())).unwrap()
//!  .build()
//!  .serialize_hex();
//!
//! let script = HandshakeMainnet::decode_address(&address).unwrap();
//! let re_encoded = HandshakeMainnet::encode_address(&script).unwrap();
//! assert_eq!(address, re_encoded);
//! ```
use std::marker::PhantomData;

use coins_core::{
    enc::{AddressEncoder, EncodingError},
    nets::Network,
};

use crate::{
    builder::HandshakeTxBuilder,
    enc::encoder::{
        Address, HandshakeEncoderMarker, MainnetEncoder, RegtestEncoder, TestnetEncoder,
    },
    types::{HandshakeTransaction, HandshakeTx, HandshakeTxIn, LockingScript, TxOut},
};

/// A newtype for Bitcoin networks, parameterized by an encoder. We change the encoder to
/// differentiate between main, test, and signet.
#[derive(Debug)]
pub struct Handshake<T: AddressEncoder>(PhantomData<fn(T) -> T>);

impl<T> Network for Handshake<T>
where
    T: HandshakeEncoderMarker,
{
    type Address = Address;
    type Error = EncodingError;
    type RecipientIdentifier = LockingScript;
    type Encoder = T;
    type TxIn = HandshakeTxIn;
    type TxOut = TxOut;
    type Tx = HandshakeTx;
    type Builder = HandshakeTxBuilder<T>;
}

/// A fully-parameterized BitcoinMainnet. This is the main interface for accessing the library.
pub type HandshakeMainnet = Handshake<MainnetEncoder>;

/// A fully-parameterized BitcoinTestnet. This is the main interface for accessing the library.
pub type HandshakeTestnet = Handshake<TestnetEncoder>;

/// A fully-parameterized BitcoinSignet. This is the main interface for accessing the library.
pub type HandshakeRegtest = Handshake<RegtestEncoder>;

#[cfg(test)]
mod test {
    use super::*;
    use crate::types::txin::HandshakeOutpoint;
    use coins_core::{builder::TxBuilder, ser::ByteFormat};

    #[test]
    fn it_has_sensible_syntax() {
        let tx_hex = HandshakeMainnet::tx_builder()
            .version(2)
            .spend(HandshakeOutpoint::default(), 0xaabbccdd)
            .pay(
                0x8888_8888_8888_8888,
                &Address::WPKH("hs1qjhgt8dwvhwapf2a5v9865nmrrqhhqlz38w3zze".to_owned()),
            )
            .unwrap()
            .pay(
                0x7777_7777_7777_7777,
                &Address::WSH("hs1qjhgt8dwvhwapf2a5v9865nmrrqhhqlz38w3zze".to_owned()),
            )
            .unwrap()
            .build()
            .serialize_hex();

        //HandshakeMainnet::builder_from_hex(&tx_hex).unwrap();

        println!("{:?}", tx_hex);
    }

    #[test]
    fn it_exposes_encoder_interface() {
        let addr_string = "hs1qjhgt8dwvhwapf2a5v9865nmrrqhhqlz38w3zze".to_owned();
        let address = Address::WPKH(addr_string.clone());
        assert_eq!(
            &address,
            &HandshakeMainnet::string_to_address(&addr_string).unwrap()
        );
        let u = HandshakeMainnet::decode_address(&address).unwrap();
        assert_eq!(&address, &HandshakeMainnet::encode_address(&u).unwrap())
    }
}
