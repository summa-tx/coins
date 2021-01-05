use thiserror::Error;

use bitcoins::prelude::*;
use coins_bip32::prelude::*;
use coins_core::types::Transaction;

use crate::{input::PSBTInput, roles::PSTSigner, PSBTError, PSBT, PST};

#[derive(Debug, Error)]
pub enum Bip32SignerError {
    /// Bubbled up from the BIP32 library
    #[error(transparent)]
    Bip32Error(#[from] Bip32Error),

    /// PSBTError bubbled up
    #[error(transparent)]
    PSBTError(#[from] crate::common::PSBTError),

    /// AlreadyFinalized
    #[error("Input at index {0} is already finalized")]
    AlreadyFinalized(usize),
}

/// A sample signer using a bip32 XPriv key with attached derivation information.
///
/// Implements naive change-checking by simply checking if it owns the pubkey of a PKH or WPKH
/// output.
pub struct Bip32Signer {
    xpriv: DerivedXPriv,
}

impl Bip32Signer {
    fn can_sign_non_witness(
        &self,
        tx: &LegacyTx,
        input_idx: usize,
        input_map: &PSBTInput,
    ) -> Result<(), PSBTError> {
        let prevout = input_map.as_utxo(&tx.inputs()[input_idx].outpoint)?;
        let prevout_type = prevout.standard_type();

        match prevout_type {
            ScriptType::WPKH(_) | ScriptType::WSH(_) | ScriptType::OP_RETURN(_) => {
                return Err(PSBTError::WrongPrevoutScriptType {
                    got: prevout.script_pubkey.standard_type(),
                    expected: vec![
                        ScriptType::SH(Hash160Digest::default()),
                        ScriptType::PKH(Hash160Digest::default()),
                        ScriptType::NonStandard,
                    ],
                });
            }
            _ => {}
        }

        match prevout.spend_script() {
            SpendScript::Missing => Err(PSBTError::MissingKey(
                crate::input::InputKey::REDEEM_SCRIPT as u8,
            )),
            _ => Ok(()),
        }
    }

    fn can_sign_witness(
        &self,
        outpoint: &BitcoinOutpoint,
        input_map: &PSBTInput,
    ) -> Result<(), PSBTError> {
        let prevout = input_map.as_utxo(&outpoint)?;

        let prevout_type = prevout.standard_type();

        match prevout_type {
            ScriptType::WPKH(_) | ScriptType::WSH(_) => {}
            _ => {
                return Err(PSBTError::WrongPrevoutScriptType {
                    got: prevout.script_pubkey.standard_type(),
                    expected: vec![
                        ScriptType::WSH(Hash256Digest::default()),
                        ScriptType::WPKH(Hash160Digest::default()),
                    ],
                })
            }
        }

        // TODO: Shortcut WPKH here

        match prevout.spend_script() {
            SpendScript::Missing => Err(PSBTError::MissingKey(
                crate::input::InputKey::WITNESS_SCRIPT as u8,
            )),
            _ => Ok(()),
        }
    }

    /// TODO: account for redeemscript
    fn sign_non_witness_input(
        &self,
        input_idx: usize,
        tx: &LegacyTx,
        input_map: &mut PSBTInput,
    ) -> Result<(), PSBTError> {
        let prevout_tx = input_map.non_witness_utxo()?;
        let paths: Vec<_> = input_map
            .parsed_pubkey_derivations()
            .iter()
            .map(|pk| self.xpriv.path_to_descendant(pk))
            .filter(Option::is_some)
            .map(Option::unwrap)
            .collect();

        let prevout_idx = tx.inputs()[input_idx].outpoint.idx as usize;
        let prevout = &prevout_tx.outputs()[prevout_idx];
        let sighash_args = LegacySighashArgs {
            index: input_idx,
            sighash_flag: input_map.sighash_or_default(),
            prevout_script: (&prevout.script_pubkey).into(),
        };

        for path in paths.iter() {
            let mut digest = coins_core::hashes::Hash256::default();
            tx.write_sighash_preimage(&mut digest, &sighash_args)?;
            let signature = self.xpriv.derive_path(path.clone())?.sign_digest(digest);
            input_map.insert_partial_sig(&self.xpriv.verify_key(), &signature);
        }

        Ok(())
    }

    /// TODO: account for witness script
    fn sign_witness_input(
        &self,
        input_idx: usize,
        tx: &WitnessTx,
        input_map: &mut PSBTInput,
    ) -> Result<(), PSBTError> {
        let paths: Vec<_> = input_map
            .parsed_pubkey_derivations()
            .iter()
            .map(|pk| self.xpriv.path_to_descendant(pk))
            .filter(Option::is_some)
            .map(Option::unwrap)
            .collect();

        // We immediately discard the outpoint, so it can be wrong.
        let tmp = BitcoinOutpoint::null();
        let prevout = input_map.as_utxo(&tmp)?;
        let sighash_args = prevout
            .witness_sighash_args(input_idx, input_map.sighash_or_default())
            .unwrap();

        for path in paths.iter() {
            let mut digest = coins_core::hashes::Hash256::default();
            tx.write_sighash_preimage(&mut digest, &sighash_args)?;
            let signature = self.xpriv.derive_path(path.clone())?.sign_digest(digest);
            input_map.insert_partial_sig(&self.xpriv.verify_key(), &signature);
        }
        Ok(())

        // WitnessSighashArgs {
        //     index: input_idx,
        //     sighash_flag: input_map.sighash_or_default(),
        //     prevout_script: (&prevout.script_pubkey).into(),
        //     prevout_value: prevout.value,
        // };
        //
        // // TODO: DRY
        // for path in paths.iter() {
        //     let sighash = tx.sighash(&sighash_args)?;
        //     let signature = self.xpriv.descendant_sign_digest(path.clone(), sighash)?;
        //     input_map.insert_partial_sig(&self.xpriv.verify_key(), &signature);
        // }
    }
}

impl From<DerivedXPriv> for Bip32Signer {
    fn from(xpriv: DerivedXPriv) -> Self {
        Self { xpriv }
    }
}

impl<A, E> PSTSigner<A, PSBT<A, E>> for Bip32Signer
where
    A: BitcoinEncoderMarker,
    E: XKeyEncoder,
{
    type Error = Bip32SignerError;

    fn is_change(&self, pst: &PSBT<A, E>, idx: usize) -> bool {
        let output_map = &pst.output_maps()[idx];

        let pubkeys = output_map.parsed_pubkey_derivations();
        if pubkeys.len() != 1 {
            return false;
        }
        let pubkey = &pubkeys[0];

        let tx_res = pst.tx();
        if tx_res.is_err() {
            return false;
        }
        let tx = tx_res.unwrap();
        let output = &tx.outputs()[idx];

        let script = &output.script_pubkey;
        let script_type = script.standard_type();

        match script_type {
            ScriptType::WPKH(v) => v == pubkey.pubkey_hash160(),
            ScriptType::PKH(v) => v == pubkey.pubkey_hash160(),
            _ => false,
        }
    }

    fn acceptable_sighash(&self, _sighash_type: Sighash) -> bool {
        true
    }

    fn can_sign_input(&self, psbt: &PSBT<A, E>, idx: usize) -> Result<(), Self::Error> {
        let input_map = &psbt.input_maps()[idx];

        let tx = psbt.tx()?;
        if input_map.has_non_witness_utxo() {
            Ok(self.can_sign_non_witness(&tx, idx, input_map)?)
        } else {
            Ok(self.can_sign_witness(&tx.inputs()[idx].outpoint, input_map)?)
        }
    }

    /// Sign the specified input in the PST.
    fn sign_input(&self, psbt: &mut PSBT<A, E>, idx: usize) -> Result<(), Self::Error> {
        let tx = psbt.tx()?;
        let input_map = &mut psbt.input_maps_mut()[idx];

        if input_map.is_finalized() {
            return Err(Bip32SignerError::AlreadyFinalized(idx));
        }

        if input_map.has_non_witness_utxo() {
            Ok(self.sign_non_witness_input(idx, &tx, input_map)?)
        } else {
            Ok(self.sign_witness_input(idx, &tx.into_witness(), input_map)?)
        }
    }
}
