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
    self as bip32, enc::XKeyEncoder as Bip32Encoder, model::DerivedKey, DerivedXPub,
    KeyFingerprint, XPub,
};

use riemann_core::prelude::*;

use rmn_btc::{
    builder::LegacyBuilder,
    enc::encoder::{BitcoinEncoderMarker, MainnetEncoder, TestnetEncoder},
    types::{BitcoinTransaction, BitcoinTxIn, LegacyTx, TxOut},
};

/// A generic Partially Signed Transaction
pub trait PST<T: AddressEncoder> {
    /// A 4-byte prefix used to identify partially signed transactions. May vary by network.
    const MAGIC_BYTES: [u8; 4];

    /// The `rmn_btc::Encoder` to be used for xpubs in this psbt
    type Bip32Encoder: Bip32Encoder;

    /// An associated Error type
    type Error: std::error::Error;

    /// An associated TxBuildertype, parameterized by the encoder
    type TxBuilder: TxBuilder<Encoder = T, Transaction = LegacyTx>;

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

    /// Return a vector containing the serialized
    fn tx_bytes(&self) -> Result<&[u8], Self::Error>;

    /// Get a copy of the transaction associated with this PSBT
    fn tx(&self) -> Result<LegacyTx, Self::Error>;

    /// Get a builder from the underlying tx
    fn tx_builder(&self) -> Result<Self::TxBuilder, Self::Error> {
        Ok(Self::TxBuilder::from_tx(self.tx()?))
    }

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
    /// Instantiate a PST from a transaction. If script sigs or witnesses are present in the tx,
    /// this extracts them and stores them in the appropriate map under the finalized key.
    fn from_tx<Tx: BitcoinTransaction>(tx: &Tx) -> Self;
}

/// A BIP174 Partially Signed Bitcoin Transaction
#[derive(Debug, Clone, Default)]
pub struct PSBT<T: BitcoinEncoderMarker, E: Bip32Encoder> {
    /// Global attributes
    global: PSBTGlobal,
    /// Per-input attribute maps
    inputs: Vec<PSBTInput>,
    /// Per-output attribute maps
    outputs: Vec<PSBTOutput>,
    /// Sppoooopppy
    encoder: PhantomData<fn(T) -> T>,
    bip32_encoder: PhantomData<fn(E) -> E>,
}

impl<T: BitcoinEncoderMarker, E: Bip32Encoder> serde::Serialize for PSBT<T, E> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.serialize_base64())
    }
}

impl<'de, T: BitcoinEncoderMarker, E: Bip32Encoder> serde::Deserialize<'de> for PSBT<T, E> {
    fn deserialize<D>(deserializer: D) -> Result<PSBT<T, E>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: &str = serde::Deserialize::deserialize(deserializer)?;
        PSBT::<T, E>::deserialize_base64(s).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

impl<T, E> PSBT<T, E>
where
    T: BitcoinEncoderMarker,
    E: Bip32Encoder,
{
    /// Insert an input into the PSBT. Updates the TX in the global, and inserts an `Input` map at
    /// the same index. If the index is larger than the length of the vector, the Input will
    /// be appended to the end of the vector instead
    pub fn insert_input(&mut self, index: usize, tx_in: BitcoinTxIn) -> Result<(), PSBTError> {
        let index = std::cmp::min(index, self.inputs.len());
        let b = self.tx_builder()?;
        let tx = b.insert_input(index, tx_in).build();
        let mut buf = vec![];
        tx.write_to(&mut buf)?;
        self.global_map_mut()
            .insert(GlobalKey::UNSIGNED_TX.into(), buf.into());
        self.input_maps_mut().insert(index, Default::default());
        Ok(())
    }

    /// Insert an output into the PSBT. Updates the TX in the global, and inserts an `Output` map
    /// at the same index. If the index is larger than the length of the vector, the Output will
    /// be appended to the end of the vector instead
    pub fn insert_output(&mut self, index: usize, tx_out: TxOut) -> Result<(), PSBTError> {
        let index = std::cmp::min(index, self.outputs.len());
        let b = self.tx_builder()?;
        let tx = b.insert_output(index, tx_out).build();
        let mut buf = vec![];
        tx.write_to(&mut buf)?;
        self.global_map_mut()
            .insert(GlobalKey::UNSIGNED_TX.into(), buf.into());
        self.output_maps_mut().insert(index, Default::default());
        Ok(())
    }

    /// Push a tx_in to the end of the PSBT's vector. This crates a new empty map.
    pub fn push_input(&mut self, tx_in: BitcoinTxIn) -> Result<(), PSBTError> {
        self.insert_input(std::usize::MAX, tx_in)
    }

    /// Push a tx_out to the end of the PSBT's vector. This crates a new empty map.
    pub fn push_output(&mut self, tx_out: TxOut) -> Result<(), PSBTError> {
        self.insert_output(std::usize::MAX, tx_out)
    }

    /// Return a parsed vector of k/v pairs. Keys are parsed as XPubs with the provided backend.
    /// Values are parsed as `KeyDerivation` structs.
    pub fn parsed_xpubs(&self) -> Result<Vec<DerivedXPub>, PSBTError> {
        self.global_map().parsed_xpubs::<E>()
    }

    /// Find an xpub in the global map by its fingerprint. This will ignore any parsing errors
    pub fn find_xpub(&self, fingerprint: KeyFingerprint) -> Option<XPub> {
        self.global_map()
            .xpubs()
            .find(|(k, _)| k.len() >= 9 && fingerprint.eq_slice(&k[5..9]))
            .map(|(k, _)| schema::try_key_as_xpub::<E>(k).ok())
            .flatten()
    }

    /// Find all xpubs with a specified root fingerprint. This with silently fail if any
    pub fn find_xpubs_by_root(&self, root: KeyFingerprint) -> Vec<DerivedXPub> {
        let mut results = vec![];
        let xpubs = self
            .global_map()
            .xpubs()
            .filter(|(_, v)| v.len() >= 4 && root.eq_slice(&v[0..4]));
        for (k, v) in xpubs {
            let xpub = schema::try_key_as_xpub::<E>(k);
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
}

impl<T, E> PST<T> for PSBT<T, E>
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

    fn tx_bytes(&self) -> Result<&[u8], Self::Error> {
        self.global.tx_bytes()
    }

    fn tx(&self) -> Result<LegacyTx, Self::Error> {
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

    fn from_tx<Tx: BitcoinTransaction>(tx: &Tx) -> PSBT<T, E> {
        let mut global = PSBTGlobal::default();
        global.set_tx(&tx.as_legacy());

        let mut inputs = vec![];
        for input in tx.inputs() {
            let mut input_map: PSBTInput = Default::default();
            if !input.script_sig.is_empty() {
                input_map.insert_script_sig(&input.script_sig);
            }
            inputs.push(input_map);
        }

        for (i, witness) in tx.witnesses().iter().enumerate() {
            inputs[i].insert_witness(witness);
        }

        PSBT {
            global,
            inputs,
            outputs: (0..tx.outputs().len())
                .map(|_| Default::default())
                .collect(),
            encoder: PhantomData,
            bip32_encoder: PhantomData,
        }
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
    use rmn_btc::types::WitnessTx;

    macro_rules! assert_err {
        ($hex:literal, $err:pat) => {
            match MainnetPSBT::deserialize_hex($hex) {
                Err($err) => {}
                // Tests are non-deterministic because of how schema maps work. Sometimes a BIP32
                // error wil get propagated because of this.
                Err(PSBTError::Bip32Error(_)) => {}
                e => {
                    println!("{:?}", e);
                    assert!(false, "expected an error")
                }
            }
        };
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
            assert_eq!(p.serialize_hex(), case.to_owned().to_string());
            // println!("{:?}", p);
        }
    }

    #[test]
    fn invalid_psbt_network_tx() {
        let psbt = "0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300";
        match MainnetPSBT::deserialize_hex(psbt) {
            Err(PSBTError::BadPrefix) => {}
            e => {
                println!("{:?}", e);
                assert!(false, "expected an error")
            }
        }
    }

    #[test]
    fn invalid_psbt_vout_mismatch() {
        let psbt = "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000000";

        // SerError(IOError(Custom { kind: UnexpectedEof, error: "failed to fill whole buffer" }))
        match MainnetPSBT::deserialize_hex(psbt) {
            Err(_) => {}
            Ok(e) => {
                println!("{:?}", e);
                assert!(false, "expected an error")
            }
        }
    }

    #[test]
    fn invalid_psbt_filled_script_sig() {
        let psbt =
        "70736274ff0100fd0a010200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be4000000006a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa88292feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000000001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000";

        // SerError(IOError(Custom { kind: UnexpectedEof, error: "failed to fill whole buffer" }))
        match MainnetPSBT::deserialize_hex(psbt) {
            Err(PSBTError::ScriptSigInTx) => {}
            e => {
                println!("{:?}", e);
                assert!(false, "expected an error")
            }
        }
    }

    #[test]
    fn invalid_psbt_no_unsigned_tx() {
        let psbt = "70736274ff000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000000";

        match MainnetPSBT::deserialize_hex(psbt) {
            Err(PSBTError::MissingKey(0)) => {}
            e => {
                println!("{:?}", e);
                assert!(false, "expected an error")
            }
        }
    }

    #[test]
    fn invalid_psbt_duplicate_key() {
        let psbt = "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000001003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000ffffffff010000000000000000036a010000000000000000";

        match MainnetPSBT::deserialize_hex(psbt) {
            Err(PSBTError::DuplicateKey(_)) => {}
            e => {
                println!("{:?}", e);
                assert!(false, "expected an error")
            }
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

    #[test]
    fn it_instantiates_from_txns() {
        let large_tx = "02000000190067bcee941b9ead28616f460eb4ae9f4e24be7009d1f2cd71a9eb6339d0335f000000006b483045022100fcfacd312f567472ed75a418a4ccd0feb0106bd708b035071e89973050a29196022024d1bc3eac60ffb302a8ccb6bd5e178a35a95a8d373a4b9267c3ffb09794793f0121026bd73b80e05e8ae6d1f3f7e80c2eb73914a00a001f6f03b2c2ac482e8e4ff876feffffff018f7a1f34af38ac7c6a4a7aafbd52ddd0b4d358aaeb5e34d827b44bdf6d8da8170000006b483045022100b99902562b110b6bdfb40dda931f19b4e4a788e376b5bf4a4954c116cb47cc8f02203d1301b7566db8ba097e4eeff6f334b41d0b14bd9387980282dbca8022e4b8650121023e8fe11a589cf00c3fd5e48fdb32c70b9c2875e94ea1c65c8df3f80da0855533feffffff16813f6c08c2a465c612efde6f04a5ba0ca118a484f88b7c9a72004caa745a93000000006a4730440220318a4a89106952450de442d0f4b22e104abcd1131c8a17563bbad896db0539e6022025c5772c02d47a0562242dacccaf4c6ec6d7b1b1708d0a07035ade2cdad8fcb7012102940929eba90c4f84e43f707fa8e0f1df6f44002672e18c276d288171839edf70feffffff1f8322524eb40facfa30ae16a2bf8423d822bef854ae2a9aaf54c6a894f0b9cf010000006a47304402200bc9ee586f8f489ade18a8159b827f214640aa8716a6966852b7650951fa88f10220690ae8cd988f4b1bcb7426fceb00631e2e2279a0b7de4f79ec5866a5c17ba4c9012102fc5f07382a4b34342a44194fffeac33d7f3f4a29b3c0ff5cc44eb5802b755fe7feffffff29520d1c309848adb58bcc23860c9ea6647a4895bf86f6742dba2e3708ddd8c2000000006b483045022100dab6ceeee20a4b00fd79b48dbc169622d01943d13138602ec2b2492b9cfae17d02206ce99952a17e1d2c023b8f09d1c9a3d4e0d7395bc1ba186e8e5e5bdb7b3e1ab801210321320de95f03b9165239d1f0a56e93a7eff4afdd877f53e94139bf68728976e1feffffff2de3ae8b56e53d0d5e44355f9cae59183454091728b7f68dbc51ba94a908ca37000000006b483045022100ed71d6153ea96f0361f38d0badd31e69db55aed79d25f733d06ac709205ed1c702203f72fd860b037f511025f754ce255619018487d8bd7e6ac8670403ce065ef07e0121037b0512c03b7306f5acc25a06cd9e1625e40214ee080ac9c232a1fdb6b9973e55feffffff31decdd1ddbde39e952063088ccbcaa0f65a6fe861ffaa8d204988b696f01b31010000006b483045022100c475c969622d3fd27f216bf585af3abdb7786a1a7f4254adebb74274002b217b02202a49d8c943dfd19981784bb8fdaeafa4b7d09e1c3ee68cacf93289d1d620e54b012102fc5f07382a4b34342a44194fffeac33d7f3f4a29b3c0ff5cc44eb5802b755fe7feffffff324d466d667183cef61645e83a11a47eaa372a8d23ca2a1efba2aff337989317000000006b483045022100f05415ee89bba91d1d7a81f12ef1421255a8ee2112fd4b4b18007f57b5dea6dc02200d5a0ba64dc5da0d46a5d05651a2819b4dd1c77a1f355fff8d95c5c6cee0bd320121023e8fe11a589cf00c3fd5e48fdb32c70b9c2875e94ea1c65c8df3f80da0855533feffffff3281884e07ccdc497521f5ac7185a85eb00cf2fd069cd572a662d31edbeb3087010000006b4830450221008aee2eed61a1d678afbb3cafb16c66e436d26ecd8af39ce79cf17f1f0a3dd6450220617759454d2b0dd9cdfca2def48c78e56552baaab8735f56e6e5b0377603da74012103d61ed189dfdb1811aec888f9dbc4f1a522b3357df9eaf9ea8c0d7659fec5961bfeffffff336973d29a509685c73145fb58de9c55a9cf7a0d505e03c8afd99c7e05824a4d010000006b483045022100851df1c7bfab745d9920fb00e40f41a984c35af04af76d3761850943bf04df1202200e679f9f13209a1818ae25ebce677aa0d182920c07ffc8f3ff3ae83b1e67f6ff012103b222dacee77955c7c663e367606c4690ad3cb0f7438c6d73208a9918266a7d16feffffff35e1c055092f31128d706ff1da995083727931560a7fc85e1961dcd8a7715039010000006a47304402203669c622696f3e0de268a3841d416ad04f5b4c65ed0e09cf915497af976d3e0902201f29d1a959a4db1ef7b6c021fa7fcdb8530ba2177ff4143d63077e5700bf32400121024dcb1572c6fddd5f436327d1ea0f70a2cc4d9c6bdef4c1b2e0c620a4d598625ffeffffff3607dd0a4f07f9edd0b8210ead4e42872f3d3c1921ab2d0a1ebe5fa773b896c9010000006a473044022051695ffb7e640ecbb3acf930758911f0c771776f4091c0823380a4bddbe4795702200af03d48b136c82d865a1d3f46c435d48ae7a8d17f13369283ef691eaf9bab8d012103145ce92f50f413d8b0a4f848ae40080327d2ff1a0bb7f83e295a0e8f8a20ea54feffffff38dbd4430247b8050f7632e46f275bd874ee85e6a471f927e12692615a9cc310010000006b483045022100b94528fe52d95ae2bd4a25c54f275527c468294e005a2e692341fcad4fcdef9b02201d2ab19eaf2a436345420abd5fc30d56f24fd06db4eb0b45125c078b47154e5001210309270ca331ad524452e0070b5bc30129b49bc265a0e99888ec705bbd97b86528feffffff59fa66ddacc9388da2e15c0284efb3e128deabcca25e07cefb7a71c86fc38c20010000006a47304402204047f05ed0f53e74ed3bc0cf73f04cea6b9d816233ed0b8c9b27f8d7ed4cf5a802200d95d736b50e03c773b8c193236318c555ed9f729b47253db025cb2ad9b90b3c0121026bd73b80e05e8ae6d1f3f7e80c2eb73914a00a001f6f03b2c2ac482e8e4ff876feffffff6c89effceffdde175c0f8b5f8aab1c872682d7d1dbe3fdc8cd0ca0f51f160596010000006a4730440220163261c4bec5ff3b03e0bd66fc12bc4e39a78cea8ec618763470b2e18191d1c502201972b15c227293f41c2ba512dfd1d53ae0e606a52ed17df7331380fdbcdd7c07012102095c5f0110ba3a0c0a26c3d65cdcdb868ab618b39dfee05b67adc1aaaf391a4afeffffff6d1ad281e8cf6c5014e5d261c98928296a0db65c9534030bc36e0835064f2f49010000006b48304502210082bb38950f54a957b55769c60799ca3ea35cc2ecf00f69256c972a399f98ff5102206987cbe82209c170e12837b4a1ee5fead3410253a83020ee090560a3917b62d70121026f979f52ec0f5eddad28aa19e4d34984b7012f9f14aedf326a96fccad028b35efeffffff79b9479c7b1a9c08d5d9ac4835b2cfc33c811cdc04cd07a86a9c385b82bfbde0010000006a473044022032b7ee46c2462390ebfeb24b166c6b2efede0bb4e240f7cd258a71e2bc7db45702204e4a8499ce2c5afed3e29bcf00d041d6e532c1dbeffaf0df6f66149a4e7ef96901210321320de95f03b9165239d1f0a56e93a7eff4afdd877f53e94139bf68728976e1feffffff7d873fc09b41a66d9f8315d08d9bd2645a45021549ada840421e3b53765087bd000000006a473044022004f8ba0fde7c626482907d75e5989a7a743bb8e173704f6c289d69a171a18508022021e2ea7999e24f0123dfa0ce0e7b5e80e4ad8bd453575fad4fa48d11f3add7790121037b0512c03b7306f5acc25a06cd9e1625e40214ee080ac9c232a1fdb6b9973e55feffffff7f5d34d7fcee0eb3383a2ae1525b3556f0c7062918e4ceb0c33599d1e215980e010000006a473044022070b517e81f413018aa0f62f3d162b76deba241a1047b1e90b400c905ec4221fb0220261c385746b7dcc94b69899e87e1829807eba48e044a43e0a123a29179d91a0e012102095c5f0110ba3a0c0a26c3d65cdcdb868ab618b39dfee05b67adc1aaaf391a4afeffffff8f7ed9ebd3fd9fe6a5166d7f2c6813423dfbb934660a78cd1ca6188693d27d5c010000006b483045022100f4ff5c1e9611fca54f8dc2888e1abe8d2a30a221f734e83f1a20513bda9d5c640220649a799bafcab15b83a4bbde2cf5c7dd6b9b5450c8b2fa46610ea2539c578962012103bca3d56ce2dc497abbe906520466f571acedca4cddf54561ebf78916fe1ebb03feffffffbb1c7ed78969657467e57a6e14c64c22d407cb444edd19d086d27fe9f2f1d1bb010000006a47304402200eaabc38016aa4f3a19a17cd76110f9c64344dae4dcaf32dac2fe056986601620220603c0effbf507a6b25995b8d0e7419ed8fb0025316bbe0c0b22534355676245b0121026c6b3ae401fad3995614758a867db8de62cf0e8a10921f9e75698a3e75216f5bfeffffffcc6d5ef9cc6fa7436712f2bd2d1076819e9c97fe26146cfd5610beb645b4de34000000006a47304402206d629507f5c0692beea672623f1d48260c70008174cb8f1dae2ff57a604fde4b0220513af0d014422533a06eff6a5470223361364e4fa650c5d3c7ef365a8993a25d0121026bd73b80e05e8ae6d1f3f7e80c2eb73914a00a001f6f03b2c2ac482e8e4ff876feffffffd766a1e22667bdab32a3892943b2193376af9446eb3fc43292c294e81ceacc7b000000006a47304402200462679e3e87c676ea57bb170d2ca847691108a5acf893822acf86435f0f4b0502204e53320234017a9e2643cca05b19565f1427de7269d378c3171a79ccb1d70db20121027c9823fed06672bd3e8964bc7cd692ca16963463045ff173ccced7a2388b7282feffffffd7ccf4ccb1d32661af74a31d6c2c94112ad4059f486867400cf1de940616077c000000006b4830450221009d6e61345554abd05d87105d5d9558e7c786cf5e535eb841b669063b29df629402207aa515b8253b3a124fc33c98182d08f1d48ae7b1519c4fab5f422498cb91d30f0121026f979f52ec0f5eddad28aa19e4d34984b7012f9f14aedf326a96fccad028b35efeffffffed6e91690db0afbc395296606829ade5757003b519214b907a221d039f573be0010000006a473044022078aef7597f04eada1a47b6e1b0b837f7e446ec1e95a595af0c4ce4c907584e24022035dc2b05e39c08edd837e42e3160d354191c25cf6a686dac67249212ec508d0b0121037b0512c03b7306f5acc25a06cd9e1625e40214ee080ac9c232a1fdb6b9973e55feffffff02df3c0f00000000001976a914b0bde9b890a18362b2aac9c0e006e3ecab2e737288ac31f7ad070100000017a914c5041e89dbf1850f256e74f2cc5459afc3c7f05387f19d0900";

        let tx = LegacyTx::deserialize_hex(large_tx).unwrap();

        let psbt = MainnetPSBT::from_tx(&tx);
        assert_eq!(psbt.inputs.len(), 25);
        assert_eq!(psbt.outputs.len(), 2);

        // assert that the psbt tx has all tx inputs in its tx, and all script sigs in its maps
        for (i, input) in psbt.tx().unwrap().inputs().iter().enumerate() {
            assert_eq!(input, &tx.inputs()[i].unsigned());
            let script_sig = psbt.input_maps()[i].finalized_script_sig().unwrap();
            assert_eq!(script_sig, tx.inputs()[i].script_sig);
        }
        for (i, output) in psbt.tx().unwrap().outputs().iter().enumerate() {
            assert_eq!(output, &tx.outputs()[i]);
        }
    }

    #[test]
    fn it_instantiates_from_witness_txns() {
        let large_tx = "0100000000010672b45d6cfedc1d1eef6e9ad59a3588b58c138bd9c69c1c6663ffd83ae715c501da02000000ffffffffde87b4f1735cdd064afbcb808b3a6fe1d94bf83acf4716bce9091874ccc14af70100000000ffffffff60e70f7c23b8004413e7c2ac413e1e4d7bb392fefa2537035f9eb167c5d86eca3203000000ffffffff871910b8993509c26e4828d735547ca8f2d5727a5c9a651375544b22e40c55e8df02000000ffffffff444e259ce59625976ba5017dfb96293429b4690c8f61b5a7913d8fda32caa7251303000000ffffffff6a2e4327183e1ac697fa74f6d3ad1207082b02ee223ae25bef5158833f7e5dc1f202000000ffffffff025c9222000000000017a914709afc8e5b252a4e82b1084c251920b84dbc874a87f823060000000000160014fe6de21323c914bbfa502d200b98feab52ab6a2902483045022100c3f388701109cf0f59cef2f4582d8b6ff447795738aff35f24ddfab10b27946a022028d0decd4ce796333e8925b2d5deee6b960c66d9f95edebd1eef78023b25175101210376989e32539258a55ab252d1a91b81d30e9b5003cc95915faf9dda073f4d1b6502483045022100ccb431ca38d9a2c05cddd85c5351c7c5ee8bc7d73756df2ac5a05a24dece6f4602203e63687bbb3d8460e190ec62db1099751e57aa4a7d78f6d0d078f731049549e5012102432ac2035716878ce3202a4b745dbbe56990a474757454165ca9f2c3d989927a02473044022042ca31752904fe67ae6b4ca2faae33feb52ecefd44d031ea2afbd7604f800c4202205a79e0cff92282dd108fc9dad3864d3bb5255ac8f26e3d1b2b54d7e6f197186701210376989e32539258a55ab252d1a91b81d30e9b5003cc95915faf9dda073f4d1b6502483045022100f53030f7e533610e2707d4690e4375162fc17d1076723d987b092bd6d04ca08e02204c9445301cad690aa6b341d81589d0b21a6632dad852526de0d70a3968529d7601210376989e32539258a55ab252d1a91b81d30e9b5003cc95915faf9dda073f4d1b6502473044022033ac6853031c8219abcbbb01fa5b85fd207e4a1f842116eda153732c27d0a88a022079306e204940262c9926750dc2145c1030a9af24fe6bfc58a888cf0eeb6b754801210376989e32539258a55ab252d1a91b81d30e9b5003cc95915faf9dda073f4d1b65024730440220373f0bb56f8e1897d8ba4eecebdb4609d0f067f91cb408042be22e34fd7848b90220397639a4fe96c058fe54b8f45a40f7a0af4a555c69a3b492d58e545b7d8317c201210376989e32539258a55ab252d1a91b81d30e9b5003cc95915faf9dda073f4d1b6500000000";

        let tx = WitnessTx::deserialize_hex(large_tx).unwrap();

        let psbt = MainnetPSBT::from_tx(&tx);
        assert_eq!(psbt.inputs.len(), 6);
        assert_eq!(psbt.outputs.len(), 2);

        for (i, _input) in psbt.tx().unwrap().inputs().iter().enumerate() {
            // assert that ever witness is there
            let witness = psbt.input_maps()[i].finalized_script_witness().unwrap();
            assert_eq!(witness, tx.witnesses()[i]);
        }
        for (i, output) in psbt.tx().unwrap().outputs().iter().enumerate() {
            assert_eq!(output, &tx.outputs()[i]);
        }
    }
}
