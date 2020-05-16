/// bip32 signer
pub mod bip32_signer;

#[cfg(feature = "ledger")]
pub mod ledger_signer;

use crate::PST;
use riemann_core::enc::AddressEncoder;
use rmn_btc::types::transactions::Sighash;

use thiserror::Error;

/// Signing-related errors
#[derive(Debug, Error)]
pub enum SignerError {
    /// Returned when a signer is missing some signer info
    #[error("Missing info during signing attemts: {0}")]
    SignerMissingInfo(String),

    /// Script in PSBT's hash is not at the appropriate location in the output's script
    /// pubkey.
    #[error("ScriptHash in PSBT does not match ScriptHash in prevout for input {0}")]
    ScriptHashMismatch(usize),
}

pub trait PSTUpdater<'a, A, P>
where
    A: AddressEncoder,
    P: PST<'a, A>,
{
    /// An associated error type that can be instantiated from the PST's Error type.
    type Error: std::error::Error + From<P::Error>;

    fn update(&self, pst: &mut P) -> Result<(), Self::Error>;
}

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
    fn sign(&self, pst: &mut P) -> Result<Vec<usize>, Self::Error> {
        Ok(self
            .signable_inputs(pst)
            .iter()
            .map(|i| self.sign_input(pst, *i).map(|_| *i))
            .filter_map(Result::ok)
            .collect())
    }
}
