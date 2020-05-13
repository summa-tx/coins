//! Partially Signed Bitcoin transactions (bip174)

#[macro_use]
pub(crate) mod prelude;

/// Common data structures
pub mod common;
/// Global KV store
pub mod global;
/// Per-Input KV store
pub mod input;
/// Per-Output KV store
pub mod output;
/// BIP174 schema valid,ation functions
pub mod schema;

/// Interfaces for BIP174 defined roles
pub mod roles;

pub use common::*;
pub use global::*;
pub use input::*;
pub use output::*;
pub use schema::*;

use std::{
    io::{Read, Write},
    marker::PhantomData,
};

use rmn_bip32::{
    self as bip32, enc::Encoder as Bip32Encoder, model::DerivedKey, DerivedXPub, KeyFingerprint,
    Secp256k1, XPub,
};

use riemann_core::{builder::TxBuilder, enc::AddressEncoder, ser::ByteFormat, tx::Transaction};

use rmn_btc::{
    builder::LegacyBuilder,
    enc::encoder::{BitcoinEncoderMarker, MainnetEncoder, TestnetEncoder},
    types::{transactions::LegacyTx, txin::BitcoinTxIn, txout::TxOut},
};

use crate::{common::PSBTError, global::PSBTGlobal, input::PSBTInput, output::PSBTOutput};

/// A generic Partially Signed Transaction.
pub trait PST<'a, T: AddressEncoder> {
    /// A 4-byte prefix used to identify partially signed transactions. May vary by network.
    const MAGIC_BYTES: [u8; 4];

    /// The `rmn_btc::Encoder` to be used for xpubs in this psbt
    type Bip32Encoder: Bip32Encoder;

    /// An associated Error type
    type Error: std::error::Error;

    /// An associated TxBuildertype, parameterized by the encoder
    type TxBuilder: TxBuilder<'a, Encoder = T, Transaction = LegacyTx>;

    /// An associated Global Map type
    type Global: PSTMap;

    /// An Associated Input type
    type Input: PSTMap;

    /// An associate Output type
    type Output: PSTMap;
    /// Run validation checks on the PST. This function SHOULD also run
    /// `self.consistency_checks()`. This function MUST be called on serialization AND
    /// deserialization.
    fn validate(&self) -> Result<(), Self::Error>;
    /// Run self-consistency validation on the PST
    fn consistency_checks(&self) -> Result<(), Self::Error>;
    /// Get a copy of the transaction associated with this PSBT
    fn tx(&self) -> Result<LegacyTx, Self::Error>;
    /// Return a reference to the global attributes
    fn global_map(&self) -> &Self::Global;
    /// Return a mutable reference to the global attributes
    fn global_map_mut(&mut self) -> &mut Self::Global;
    /// Return a reference to the vector of input maps
    fn input_maps(&self) -> &Vec<Self::Input>;
    /// Return a mutable reference to the vector of input maps
    fn input_maps_mut(&mut self) -> &mut Vec<Self::Input>;
    /// Return a reference to the vector of output maps
    fn output_maps(&self) -> &Vec<Self::Output>;
    /// Return a mutable reference to the vector of output maps
    fn output_maps_mut(&mut self) -> &mut Vec<Self::Output>;
}

/// A BIP174 Partially Signed Bitcoin Transaction
#[derive(Debug, Clone)]
pub struct PSBT<T: AddressEncoder, E: Bip32Encoder> {
    /// Global attributes
    global: PSBTGlobal,
    /// Per-input attribute maps
    inputs: Vec<PSBTInput>,
    /// Per-output attribute maps
    outputs: Vec<PSBTOutput>,
    /// Sppoooopppy
    encoder: PhantomData<*const T>,
    bip32_encoder: PhantomData<*const E>,
}

impl<T, E> PSBT<T, E>
where
    T: BitcoinEncoderMarker,
    E: Bip32Encoder,
{
    /// Insert an input into the PSBT. Updates the TX in the global, and inserts an `Input` map at
    /// the same index
    pub fn insert_input(&mut self, index: usize, tx_in: BitcoinTxIn) -> Result<(), PSBTError> {
        let b = <Self as PST<T>>::TxBuilder::from_tx(&self.tx()?);
        let tx = b.insert_input(index, tx_in).build();
        let mut buf = vec![];
        tx.write_to(&mut buf)?;
        self.global_map_mut()
            .insert(GlobalKey::UNSIGNED_TX.into(), buf.into());
        self.input_maps_mut().insert(index, Default::default());
        Ok(())
    }

    /// Insert an output into the PSBT. Updates the TX in the global, and inserts an `Output` map
    /// at the same index
    pub fn insert_output(&mut self, index: usize, tx_out: TxOut) -> Result<(), PSBTError> {
        let b = <Self as PST<T>>::TxBuilder::from_tx(&self.tx()?);
        let tx = b.insert_output(index, tx_out).build();
        let mut buf = vec![];
        tx.write_to(&mut buf)?;
        self.global_map_mut()
            .insert(GlobalKey::UNSIGNED_TX.into(), buf.into());
        self.output_maps_mut().insert(index, Default::default());
        Ok(())
    }

    /// Return a parsed vector of k/v pairs. Keys are parsed as XPubs with the provided backend.
    /// Values are parsed as `KeyDerivation` structs.
    pub fn parsed_xpubs<'a>(
        &self,
        backend: Option<&'a Secp256k1>,
    ) -> Result<Vec<DerivedXPub<'a>>, PSBTError> {
        self.global_map().parsed_xpubs::<E>(backend)
    }

    /// Find an xpub in the global map by its fingerprint. This will ignore any parsing errors
    pub fn find_xpub<'a>(
        &self,
        fingerprint: KeyFingerprint,
        backend: Option<&'a Secp256k1>,
    ) -> Option<XPub<'a>> {
        self.global_map()
            .xpubs()
            .find(|(k, _)| k.len() >= 9 && fingerprint.eq_slice(&k[5..9]))
            .map(|(k, _)| schema::try_key_as_xpub::<E>(k, backend).ok())
            .flatten()
    }

    /// Find all xpubs with a specified root fingerprint. This with silently fail if any
    pub fn find_xpubs_by_root<'a>(
        &self,
        root: KeyFingerprint,
        backend: Option<&'a Secp256k1>,
    ) -> Vec<DerivedXPub<'a>> {
        let mut results = vec![];
        let xpubs = self
            .global_map()
            .xpubs()
            .filter(|(_, v)| v.len() >= 4 && root.eq_slice(&v[0..4]));
        for (k, v) in xpubs {
            let xpub = schema::try_key_as_xpub::<E>(k, backend);
            let deriv = schema::try_val_as_key_derivation(v);
            if deriv.is_err() || xpub.is_err() {
                continue;
            }
            results.push(DerivedXPub::new(
                xpub.expect("checked"),
                deriv.expect("checked"),
            ));
        }
        results
        // self.parsed_xpubs(backend)
        //     .map_or_else(
        //         |_| vec![],
        //         |v| {
        //             v.into_iter()
        //             .filter(|k| root == k.derivation.root)
        //             .collect()
        //         }
        //     )
    }
}

impl<'a, T, E> PST<'a, T> for PSBT<T, E>
where
    T: BitcoinEncoderMarker,
    E: Bip32Encoder,
{
    const MAGIC_BYTES: [u8; 4] = *b"psbt";

    type Bip32Encoder = E;
    type Error = PSBTError;
    type TxBuilder = LegacyBuilder<T>;
    type Global = PSBTGlobal;
    type Input = PSBTInput;
    type Output = PSBTOutput;

    fn validate(&self) -> Result<(), PSBTError> {
        self.global.validate()?;
        for input in self.inputs.iter() {
            input.validate()?;
        }
        for output in self.outputs.iter() {
            output.validate()?;
        }
        self.consistency_checks()?;
        Ok(())
    }

    fn consistency_checks(&self) -> Result<(), PSBTError> {
        // - PSBT-level checks
        let tx = self
            .tx()
            .expect("already performed global consistency_checks");
        if tx.inputs().len() != self.inputs.len() {
            return Err(PSBTError::VinLengthMismatch {
                tx_ins: tx.inputs().len(),
                maps: self.inputs.len(),
            });
        }
        if tx.outputs().len() != self.outputs.len() {
            return Err(PSBTError::VoutLengthMismatch {
                tx_outs: tx.outputs().len(),
                maps: self.outputs.len(),
            });
        }

        // TODO:
        // - validate that all non-witness inputs match the tx
        Ok(())
    }

    fn tx(&self) -> Result<LegacyTx, PSBTError> {
        self.global.tx()
    }

    fn global_map(&self) -> &PSBTGlobal {
        &self.global
    }

    fn global_map_mut(&mut self) -> &mut PSBTGlobal {
        &mut self.global
    }

    fn input_maps(&self) -> &Vec<PSBTInput> {
        &self.inputs
    }

    fn input_maps_mut(&mut self) -> &mut Vec<PSBTInput> {
        &mut self.inputs
    }

    fn output_maps(&self) -> &Vec<PSBTOutput> {
        &self.outputs
    }

    fn output_maps_mut(&mut self) -> &mut Vec<PSBTOutput> {
        &mut self.outputs
    }
}

impl<'a, T, E> ByteFormat for PSBT<T, E>
where
    T: BitcoinEncoderMarker,
    E: Bip32Encoder,
{
    type Error = PSBTError;

    fn serialized_length(&self) -> usize {
        let mut length: usize = 5;
        length += self.global_map().serialized_length();
        length += self
            .input_maps()
            .iter()
            .map(|i| i.serialized_length())
            .sum::<usize>();
        length += self
            .output_maps()
            .iter()
            .map(|o| o.serialized_length())
            .sum::<usize>();
        length
    }

    fn read_from<R>(reader: &mut R, _limit: usize) -> Result<Self, PSBTError>
    where
        R: Read,
        Self: std::marker::Sized,
    {
        let mut prefix = [0u8; 5];
        reader.read_exact(&mut prefix)?;
        if prefix[..4] != <Self as PST<T>>::MAGIC_BYTES || prefix[4] != 0xff {
            return Err(PSBTError::BadPrefix);
        }

        let global = PSBTGlobal::read_from(reader, 0)?;

        let tx = global.tx()?;

        let inputs = Vec::<PSBTInput>::read_from(reader, tx.inputs().len())?;
        let outputs = Vec::<PSBTOutput>::read_from(reader, tx.outputs().len())?;

        let result = PSBT {
            global,
            inputs,
            outputs,
            encoder: PhantomData,
            bip32_encoder: PhantomData,
        };
        result.validate()?;
        Ok(result)
    }

    fn write_to<W>(&self, writer: &mut W) -> Result<usize, Self::Error>
    where
        W: Write,
    {
        self.validate()?;
        let mut len = writer.write(&<PSBT<T, E> as PST<T>>::MAGIC_BYTES)?;
        len += writer.write(&[0xff])?;
        len += self.global_map().write_to(writer)?;
        len += self.input_maps().write_to(writer)?;
        len += self.output_maps().write_to(writer)?;
        Ok(len)
    }
}

/// A PSBT Parameterized for mainnet
pub type MainnetPSBT = PSBT<MainnetEncoder, bip32::enc::MainnetEncoder>;

/// A PSBT Parameterized for testnet
pub type TestnetPSBT = PSBT<TestnetEncoder, bip32::enc::TestnetEncoder>;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_does_stuff() {
        let valid_cases = [
            "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab300000000000000",
            "70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000",
            "70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000",
            "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000001030401000000000000",
        ];
        for case in &valid_cases {
            let p = MainnetPSBT::deserialize_hex(case).unwrap();

            // Check for non-modification
            assert_eq!(p.serialize_hex().unwrap(), case.to_owned().to_string());
            println!("{:?}", p);
        }
    }
}
