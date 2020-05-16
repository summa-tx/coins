use rmn_bip32::{
    self as bip32,
    model::{DerivedKey, HasBackend, HasPubkey, SigningKey, XSigning},
};

use riemann_core::types::Transaction;
use rmn_btc::{
    enc::encoder::BitcoinEncoderMarker,
    types::{
        script::ScriptType,
        transactions::{BitcoinTransaction, LegacySighashArgs, LegacyTx, Sighash, WitnessSighashArgs, WitnessTx},
        txin::BitcoinOutpoint,
        utxo::SpendScript,
    },
};

use crate::{input::PSBTInput, roles::PSTSigner, PSBTError, PSBT, PST};

/// A sample signer using a bip32 XPriv key with attached derivation information.
///
/// Implements naive change-checking by simply checking if it owns the pubkey of a PKH or WPKH
/// output.
pub struct Bip32Signer<'a> {
    xpriv: &'a bip32::DerivedXPriv<'a>,
}

impl<'a> Bip32Signer<'a> {
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
                        ScriptType::SH([0u8; 20]),
                        ScriptType::PKH([0u8; 20]),
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
                    expected: vec![ScriptType::WSH([0u8; 32]), ScriptType::WPKH([0u8; 20])],
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
            .parsed_pubkey_derivations(self.xpriv.backend().ok())
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
            prevout_script: &(&prevout.script_pubkey).into(),
        };

        for path in paths.iter() {
            // TODO: DRY
            let sighash = tx.sighash(&sighash_args)?;
            let signature = self.xpriv.descendant_sign_digest(path, sighash)?;
            input_map.insert_partial_sig(&self.xpriv.derive_verifying_key()?, &signature);
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
        let prevout = input_map.witness_utxo()?;
        let paths: Vec<_> = input_map
            .parsed_pubkey_derivations(self.xpriv.backend().ok())
            .iter()
            .map(|pk| self.xpriv.path_to_descendant(pk))
            .filter(Option::is_some)
            .map(Option::unwrap)
            .collect();

        let sighash_args = WitnessSighashArgs {
            index: input_idx,
            sighash_flag: input_map.sighash_or_default(),
            prevout_script: &(&prevout.script_pubkey).into(),
            prevout_value: prevout.value,
        };

        // TODO: DRY
        for path in paths.iter() {
            let sighash = tx.sighash(&sighash_args)?;
            let signature = self.xpriv.descendant_sign_digest(path.clone(), sighash)?;
            input_map.insert_partial_sig(&self.xpriv.derive_verifying_key()?, &signature);
        }

        Ok(())
    }
}

impl<'a> From<&'a bip32::DerivedXPriv<'a>> for Bip32Signer<'a> {
    fn from(xpriv: &'a bip32::DerivedXPriv<'a>) -> Self {
        Self { xpriv }
    }
}

impl<'a, A, E> PSTSigner<'a, A, PSBT<A, E>> for Bip32Signer<'a>
where
    A: BitcoinEncoderMarker,
    E: bip32::enc::Encoder,
{
    type Error = PSBTError;

    fn is_change(&self, pst: &PSBT<A, E>, idx: usize) -> bool {
        let output_map = &pst.output_maps()[idx];

        let pubkeys = output_map.parsed_pubkey_derivations(self.xpriv.backend().ok());
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
        if input_map.has_non_witness_utxo() {
            self.sign_non_witness_input(idx, &tx, input_map)
        } else {
            self.sign_witness_input(idx, &tx.into_witness(), input_map)
        }
    }
}
