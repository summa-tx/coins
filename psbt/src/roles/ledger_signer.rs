//! A PSBT signer for ledger hardware wallets.
//!
//! This signer does NOT currently support nested witness-via-P2SH.

use thiserror::Error;

use futures::executor::block_on;

use bitcoins::{
    enc::encoder::BitcoinEncoderMarker,
    types::{BitcoinTransaction, Sighash},
};
use bitcoins_ledger::{LedgerBTC, SigningInfo};
use coins_bip32 as bip32;
use coins_core::types::tx::Transaction;

use crate::{input::PSBTInput, roles::PSTSigner, PSBTError, PSBT, PST};

#[derive(Debug, Error)]
pub enum LedgerSignerError {
    /// LedgerBTCError bubbled up
    #[error(transparent)]
    LedgerBTCError(#[from] bitcoins_ledger::LedgerBTCError),

    /// PSBTError bubbled up
    #[error(transparent)]
    PSBTError(#[from] crate::common::PSBTError),

    /// No matching key
    #[error("No matching key in input")]
    NoMatchingKey,

    /// UnsupportedSingleInput
    #[error("Signing single inputs is not supported. Calling `sign` will automatically filter unsignable inputs.")]
    UnsupportedSingleInput,

    /// UnsupportedNestedSegwit
    #[error("Signing witness-via-p2sh is not supported")]
    UnsupportedNestedSegwit,

    /// AlreadyFinalized
    #[error("Input at index {0} is already finalized")]
    AlreadyFinalized(usize),
}

/// A PST Signer interface.
impl<A, E> PSTSigner<A, PSBT<A, E>> for LedgerBTC
where
    A: BitcoinEncoderMarker,
    E: bip32::enc::XKeyEncoder,
{
    type Error = LedgerSignerError;

    fn is_change(&self, pst: &PSBT<A, E>, idx: usize) -> bool {
        let pubkeys = pst.outputs[idx].parsed_pubkey_derivations();
        if pubkeys.len() == 1 {
            let key = &pubkeys[0];
            let xpub_res = block_on(self.get_xpub(&key.derivation.path));
            if let Ok(xpub) = xpub_res {
                return xpub.xpub.pubkey == key.pubkey && xpub.derivation == key.derivation;
            }
        }
        false
    }

    fn acceptable_sighash(&self, sighash_type: Sighash) -> bool {
        sighash_type == Sighash::All
    }

    fn can_sign_input(&self, pst: &PSBT<A, E>, idx: usize) -> Result<(), Self::Error> {
        let input_map = &pst.inputs[idx];
        if input_map.is_finalized() {
            return Err(LedgerSignerError::AlreadyFinalized(idx));
        }
        if input_map.has_witness_script() && input_map.has_redeem_script() {
            return Err(LedgerSignerError::UnsupportedNestedSegwit);
        }

        let pubkeys = input_map.parsed_pubkey_derivations();
        for key in pubkeys {
            let xpub = block_on(self.get_xpub(&key.derivation.path))?;
            if xpub.xpub.pubkey == key.pubkey && xpub.derivation == key.derivation {
                return Ok(());
            }
        }
        Err(LedgerSignerError::NoMatchingKey)
    }

    fn sign_input(&self, _pst: &mut PSBT<A, E>, _idx: usize) -> Result<(), Self::Error> {
        Err(LedgerSignerError::UnsupportedSingleInput)
    }

    /// Append all producible signatures to a PSBT. Returns a vector containing the indices of
    /// the inputs that were succesfully signed signed.
    fn sign(&self, pst: &mut PSBT<A, E>) -> Result<Vec<usize>, Self::Error> {
        let tx = pst.tx()?;

        let signing_info: Vec<SigningInfo> = pst
            .inputs
            .iter()
            .enumerate()
            .map(|(i, m)| extract_signing_info(&tx, i, m))
            .filter_map(Result::ok)
            .flatten()
            .collect();

        let sig_infos = block_on(self.get_tx_signatures(&tx.into_witness(), &signing_info))?;

        for sig_info in sig_infos.iter() {
            let key = block_on(self.get_xpub(&sig_info.deriv.path))?;
            pst.inputs[sig_info.input_idx].insert_partial_sig(&key, &sig_info.sig);
        }

        Ok(sig_infos.iter().map(|i| i.input_idx).collect())
    }
}

fn extract_signing_info(
    tx: &bitcoins::types::LegacyTx,
    idx: usize,
    input_map: &PSBTInput,
) -> Result<Vec<SigningInfo>, PSBTError> {
    let prevout = input_map.as_utxo(&tx.inputs()[idx].outpoint)?;
    Ok(input_map
        .parsed_pubkey_derivations()
        .iter()
        .map(|key| SigningInfo {
            input_idx: idx,
            prevout: prevout.clone(),
            deriv: Some(key.derivation.clone()),
        })
        .collect())
}
