//! The `nets` module defines an abstract `Network.` The `Network` trait is a highly-abstracted
//! representation of the relationships between types in a UTXO network. Concrete implementations
//! for various Bitcoin networks are found in the `bitcoin` module.

use crate::{
    bitcoin::script::{Script},  // TODO: REFACTOR THIS OUT AND GENERALIZE
    builder::{TxBuilder},
    types::{
        tx::{Transaction},
    },
    enc::AddressEncoder,
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
    type Builder: TxBuilder<'a, Encoder = Self::Encoder, Transaction = Self::Tx>;

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
