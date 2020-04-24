use bitcoin_spv::btcspv::{hash160, hash256};

use rmn_bip32::{self as bip32, model::XSigning};

use thiserror::Error;

use riemann_core::{enc::AddressEncoder, primitives::PrefixVec, types::Transaction};

use crate::{
    bases::EncodingError,
    encoder::Address,
    psbt::{input::PSBTInput, PSBTError, PSBT, PST},
    script::{ScriptPubkey, ScriptType},
    types::transactions::{LegacySighashArgs, LegacyTx, Sighash, WitnessSighashArgs, WitnessTx},
};

/// A PST Signer interface.
pub trait PSTSigner<'a, A, P>
where
    A: AddressEncoder,
    P: PST<'a, A>,
{
    /// An associated error type that can be instantiated from the PST's Error type.
    type Error: std::error::Error + From<P::Error>;

    /// Determine whether an output is change.
    fn is_change(&self, pst: &P, idx: usize) -> bool;

    /// Returns a vector of integers speciiying the indices out change ouputs.
    fn identify_change_outputs(&self, pst: &P) -> Vec<usize> {
        (0..pst.output_maps().len())
            .filter(|i| self.is_change(pst, *i))
            .collect()
    }

    /// Returns `true` if the sighash is acceptable, else `false`.
    fn acceptable_sighash(&self, sighash_type: Sighash) -> bool;

    /// Return `Ok(())` if the input at `idx` can be signed, else `Err()`.
    fn can_sign_input(&self, pst: &P, idx: usize) -> Result<(), Self::Error>;

    /// Sign the specified input in the PST.
    fn sign_input(&self, pst: &mut P, idx: usize) -> Result<(), Self::Error>;

    /// Return a vector with the indices of inputs that this signer can sign.
    fn signable_inputs(&self, pst: &P) -> Vec<usize> {
        (0..pst.input_maps().len())
            .map(|i| self.can_sign_input(pst, i).map(|_| i))
            .filter_map(Result::ok)
            .collect()
    }

    /// Append all producible signatures to a PSBT. Returns a vector containing the indices of
    /// the inputs that were succesfully signed signed.
    fn sign(&self, pst: &mut P) -> Vec<usize> {
        self.signable_inputs(pst)
            .iter()
            .map(|i| self.sign_input(pst, *i).map(|_| *i))
            .filter_map(Result::ok)
            .collect()
    }
}

/// Signing-related errors
#[derive(Debug, Error)]
pub enum SignerError {
    /// Returned when a signer is missing some signer info
    #[error("Missing info during signing attemts: {0}")]
    SignerMissingInfo(String),

    /// Returned when an unexpected script type is found. E.g. when a redeem script is found,
    /// but the prevout script pubkey is not P2SH.
    #[error("Wrong prevout script_pubkey type. Got: {got:?}. Expected {expected:?}")]
    WrongPrevoutScriptType {
        /// The actual script type
        got: ScriptType,
        /// The expected script type
        expected: Vec<ScriptType>,
    },

    /// Script in PSBT's hash is not at the appropriate location in the output's script
    /// pubkey.
    #[error("ScriptHash in PSBT does not match ScriptHash in prevout for input {0}")]
    ScriptHashMismatch(usize),
}

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
        input_idx: usize,
        tx: &LegacyTx,
        input_map: &PSBTInput,
    ) -> Result<(), SignerError> {
        let res = input_map.non_witness_utxo();
        let prevout_tx = match res {
            Ok(v) => v,
            Err(_) => {
                return Err(SignerError::SignerMissingInfo(
                    "Non-witness UTXO".to_owned(),
                ))
            }
        };

        let prevout_idx = tx.inputs()[input_idx].outpoint.idx as usize;
        let prevout = &prevout_tx.outputs()[prevout_idx];

        let prevout_script = &prevout.script_pubkey;
        let prevout_type = prevout_script.standard_type();

        if prevout_type == ScriptType::WPKH || prevout_type == ScriptType::WSH {
            return Err(SignerError::WrongPrevoutScriptType {
                got: prevout.script_pubkey.standard_type(),
                expected: vec![ScriptType::SH, ScriptType::PKH, ScriptType::NonStandard],
            });
        }

        // TODO: shortcut PKH here

        if let Ok(script) = input_map.redeem_script() {
            if prevout_type != ScriptType::SH {
                return Err(SignerError::WrongPrevoutScriptType {
                    got: prevout.script_pubkey.standard_type(),
                    expected: vec![ScriptType::SH],
                });
            }
            if hash160(&script.items()) != prevout_script.items()[2..15] {
                return Err(SignerError::ScriptHashMismatch(input_idx));
            }
        }

        Ok(())
    }

    fn can_sign_witness(&self, input_idx: usize, input_map: &PSBTInput) -> Result<(), SignerError> {
        let res = input_map.witness_utxo();
        let prevout = match res {
            Ok(v) => v,
            Err(_) => return Err(SignerError::SignerMissingInfo("Witness UTXO".to_owned())),
        };

        let prevout_script = &prevout.script_pubkey;
        let prevout_type = prevout_script.standard_type();

        if prevout_type != ScriptType::WPKH && prevout_type != ScriptType::WSH {
            return Err(SignerError::WrongPrevoutScriptType {
                got: prevout.script_pubkey.standard_type(),
                expected: vec![ScriptType::WSH, ScriptType::WPKH],
            });
        }

        // TODO: Shortcut WPKH here

        if let Ok(script) = input_map.witness_script() {
            if prevout_type != ScriptType::WSH {
                return Err(SignerError::WrongPrevoutScriptType {
                    got: prevout.script_pubkey.standard_type(),
                    expected: vec![ScriptType::WSH],
                });
            }
            if hash256(&[&script.items()]) != prevout_script.items()[2..] {
                return Err(SignerError::ScriptHashMismatch(input_idx));
            }
        }

        Ok(())
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
            .map(|pk| self.xpriv.path_to_descendant(&pk))
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
            input_map.insert_partial_sig(self.xpriv.pubkey()?, signature);
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
            .parsed_pubkey_derivations()
            .iter()
            .map(|pk| self.xpriv.path_to_descendant(&pk))
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
            let signature = self.xpriv.descendant_sign_digest(path, sighash)?;
            input_map.insert_partial_sig(self.xpriv.pubkey()?, signature);
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
    A: AddressEncoder<Address = Address, Error = EncodingError, RecipientIdentifier = ScriptPubkey>,
    E: bip32::Encoder,
{
    type Error = PSBTError;

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
        if script_type == ScriptType::WPKH || script_type == ScriptType::PKH {
            let res = self.xpriv.private_ancestor_of(pubkey);
            match res {
                Ok(v) => v,
                Err(_) => false,
            }
        } else {
            false
        }
    }

    fn acceptable_sighash(&self, _sighash_type: Sighash) -> bool {
        true
    }

    fn can_sign_input(&self, psbt: &PSBT<A, E>, idx: usize) -> Result<(), Self::Error> {
        let input_map = &psbt.input_maps()[idx];
        let tx = psbt.tx()?;
        if input_map.has_non_witness_utxo() {
            Ok(self.can_sign_non_witness(idx, &tx, input_map)?)
        } else {
            Ok(self.can_sign_witness(idx, input_map)?)
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
