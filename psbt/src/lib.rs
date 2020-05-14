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
    }

    /// Instantiate a PSBT from a transaction. This sets up empty input and output maps
    pub fn from_tx(tx: &LegacyTx) -> PSBT<T, E> {
        let mut global = PSBTGlobal::default();
        global.set_tx(tx);
        PSBT {
            global,
            inputs: (0..tx.inputs().len()).map(|_| Default::default()).collect(),
            outputs: (0..tx.outputs().len()).map(|_| Default::default()).collect(),
            encoder: PhantomData,
            bip32_encoder: PhantomData,
        }
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
        for input in tx.inputs().iter() {
            if !input.script_sig.is_empty() {
                return Err(PSBTError::ScriptSigInTx);
            }
        }

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

    macro_rules! assert_err {
        ($hex:literal, $err:pat) => {
            match MainnetPSBT::deserialize_hex($hex) {
                Err($err) => {},
                // Tests are non-deterministic because of how schema maps work. Sometimes a BIP32
                // error wil get propagated because of this.
                Err(PSBTError::Bip32Error(_)) => {},
                e => {println!("{:?}", e); assert!(false, "expected an error")},
            }
        }
    }

    #[test]
    fn it_deserializes_without_modifying() {
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
            // println!("{:?}", p);
        }
    }

    #[test]
    fn invalid_psbt_network_tx() {
        let psbt = "0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300";
        match MainnetPSBT::deserialize_hex(psbt) {
            Err(PSBTError::BadPrefix) => {},
            e => {println!("{:?}", e); assert!(false, "expected an error")},
        }
    }

    #[test]
    fn invalid_psbt_vout_mismatch() {
        let psbt = "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000000";

        // SerError(IOError(Custom { kind: UnexpectedEof, error: "failed to fill whole buffer" }))
        match MainnetPSBT::deserialize_hex(psbt) {
            Err(_) => {},
            Ok(e) => {println!("{:?}", e); assert!(false, "expected an error")},
        }
    }

    #[test]
    fn invalid_psbt_filled_script_sig() {
        let psbt =
        "70736274ff0100fd0a010200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be4000000006a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa88292feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000000001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000";

        // SerError(IOError(Custom { kind: UnexpectedEof, error: "failed to fill whole buffer" }))
        match MainnetPSBT::deserialize_hex(psbt) {
            Err(PSBTError::ScriptSigInTx) => {},
            e => {println!("{:?}", e); assert!(false, "expected an error")},
        }
    }

    #[test]
    fn invalid_psbt_no_unsigned_tx() {
        let psbt = "70736274ff000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000000";

        match MainnetPSBT::deserialize_hex(psbt) {
            Err(PSBTError::MissingKey(0)) => {},
            e => {println!("{:?}", e); assert!(false, "expected an error")},
        }
    }

    #[test]
    fn invalid_psbt_duplicate_key() {
        let psbt = "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000001003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000ffffffff010000000000000000036a010000000000000000";

        match MainnetPSBT::deserialize_hex(psbt) {
            Err(PSBTError::DuplicateKey(_)) => {},
            e => {println!("{:?}", e); assert!(false, "expected an error")},
        }
    }

    #[test]
    fn invalid_psbt_bad_tx() {
        assert_err!(
            "70736274ff020001550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000",
            PSBTError::MissingKey(0)
        );
    }

    #[test]
    fn invalid_psbt_bad_witness_utxo_key() {
        assert_err!(
            "70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac000000000002010020955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000",
            PSBTError::WrongKeyLength{expected: 1, got: 2}
        );
    }

    #[test]
    fn invalid_psbt_bad_pubkey_key() {
        assert_err!(
            "70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87210203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd46304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000",
            PSBTError::WrongKeyLength{expected: 66, got: 33}
        );
    }

    #[test]
    fn invalid_psbt_redeem_script_key() {
        assert_err!(
            "70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a01020400220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000",
            PSBTError::WrongKeyLength{expected: 1, got: 2}
        );
    }

    #[test]
    fn invalid_psbt_witness_script_key() {
        assert_err!(
            "70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d568102050047522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000",
            PSBTError::WrongKeyLength{expected: 1, got: 2}
        );
    }

    #[test]
    fn invalid_psbt_bip32_key() {
        assert_err!(
            "70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae210603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd10b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000",
            PSBTError::WrongKeyLength{expected: 34, got: 33}
        );
    }

    #[test]
    fn invalid_psbt_bad_non_witness_utxo_key() {
        assert_err!(
            "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f0000000000020000bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000000107da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae0001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8870107232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b20289030108da0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000",
            PSBTError::WrongKeyLength{expected: 1, got: 2}
        );
    }

    #[test]
    fn invalid_psbt_bad_script_sig_key() {
        assert_err!(
            "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000020700da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae0001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8870107232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b20289030108da0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000",
            PSBTError::WrongKeyLength{expected: 1, got: 2}
        );
    }

    #[test]
    fn invalid_psbt_bad_final_script_witness_key() {
        assert_err!(
            "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000000107da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae0001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8870107232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903020800da0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000",
            PSBTError::WrongKeyLength{expected: 1, got: 2}
        );
    }

    #[test]
    fn invalid_psbt_output_bip32_derivation_bad_pubkey() {
        assert_err!(
            "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000000107da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae0001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8870107232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b20289030108da0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00210203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca58710d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000",
            PSBTError::WrongKeyLength{expected: 34, got: 33}
        );
    }

    #[test]
    fn invalid_psbt_bad_input_sighash_key() {
        assert_err!(
            "70736274ff0100730200000001301ae986e516a1ec8ac5b4bc6573d32f83b465e23ad76167d68b38e730b4dbdb0000000000ffffffff02747b01000000000017a91403aa17ae882b5d0d54b25d63104e4ffece7b9ea2876043993b0000000017a914b921b1ba6f722e4bfa83b6557a3139986a42ec8387000000000001011f00ca9a3b00000000160014d2d94b64ae08587eefc8eeb187c601e939f9037c0203000100000000010016001462e9e982fff34dd8239610316b090cd2a3b747cb000100220020876bad832f1d168015ed41232a9ea65a1815d9ef13c0ef8759f64b5b2b278a65010125512103b7ce23a01c5b4bf00a642537cdfabb315b668332867478ef51309d2bd57f8a8751ae00",
            PSBTError::WrongKeyLength{expected: 1, got: 2}
        );
    }

    #[test]
    fn invalid_psbt_bad_output_redeem_script_key() {
        assert_err!(
            "70736274ff0100730200000001301ae986e516a1ec8ac5b4bc6573d32f83b465e23ad76167d68b38e730b4dbdb0000000000ffffffff02747b01000000000017a91403aa17ae882b5d0d54b25d63104e4ffece7b9ea2876043993b0000000017a914b921b1ba6f722e4bfa83b6557a3139986a42ec8387000000000001011f00ca9a3b00000000160014d2d94b64ae08587eefc8eeb187c601e939f9037c0002000016001462e9e982fff34dd8239610316b090cd2a3b747cb000100220020876bad832f1d168015ed41232a9ea65a1815d9ef13c0ef8759f64b5b2b278a65010125512103b7ce23a01c5b4bf00a642537cdfabb315b668332867478ef51309d2bd57f8a8751ae00",
            PSBTError::WrongKeyLength{expected: 1, got: 2}
        );
    }

    #[test]
    fn invalid_psbt_bad_output_witness_script_key() {
        assert_err!(
            "70736274ff0100730200000001301ae986e516a1ec8ac5b4bc6573d32f83b465e23ad76167d68b38e730b4dbdb0000000000ffffffff02747b01000000000017a91403aa17ae882b5d0d54b25d63104e4ffece7b9ea2876043993b0000000017a914b921b1ba6f722e4bfa83b6557a3139986a42ec8387000000000001011f00ca9a3b00000000160014d2d94b64ae08587eefc8eeb187c601e939f9037c00010016001462e9e982fff34dd8239610316b090cd2a3b747cb000100220020876bad832f1d168015ed41232a9ea65a1815d9ef13c0ef8759f64b5b2b278a6521010025512103b7ce23a01c5b4bf00a642537cdfabb315b668332867478ef51309d06d57f8a8751ae00",
            PSBTError::WrongKeyLength{expected: 1, got: 33}
        );
    }
}
