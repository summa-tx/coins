/// A Provided bip32 input signer.
pub mod bip32_signer;

#[cfg(feature = "ledger")]
pub mod ledger_signer;

/// Provided finalizers.
pub mod finalizer;

/// Provided tx extractors.
pub mod extractor;

use crate::PST;
use riemann_core::enc::AddressEncoder;
use rmn_btc::types::transactions::{BitcoinTx, Sighash};

pub trait PSTUpdater<A, P>
where
    A: AddressEncoder,
    P: PST<A>,
{
    /// An associated error type that can be instantiated from the PST's Error type. This may be
    /// the PST's Error type.
    type Error: std::error::Error + From<P::Error>;

    fn update(&mut self, pst: &mut P) -> Result<(), Self::Error>;
}

/// A PST Signer interface.
pub trait PSTSigner<A, P>
where
    A: AddressEncoder,
    P: PST<A>,
{
    /// An associated error type that can be instantiated from the PST's Error type. This may be
    /// the PST's Error type.
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
    /// the inputs that were succesfully signed signed. The default implementation will simply
    /// silently fail to sign any input that errors. This method returns a result to enable
    /// signer implementations to override it with more complex functionality. (e.g. the provided
    /// Ledger signing).
    fn sign(&self, pst: &mut P) -> Result<Vec<usize>, Self::Error> {
        Ok(self
            .signable_inputs(pst)
            .iter()
            .map(|i| self.sign_input(pst, *i).map(|_| *i))
            .filter_map(Result::ok)
            .collect())
    }
}

/// A PST Finalizer. These will typically be specialized for some purpose, and a PST may need
/// several rounds of finalization by different finalizers if it contains several types of input.
pub trait PSTFinalizer<A, P>
where
    A: AddressEncoder,
    P: PST<A>,
{
    /// An associated error type that can be instantiated from the PST's Error type. This may be
    /// the PST's Error type.
    type Error: std::error::Error + From<P::Error>;

    /// Finalize an input, creating a ScriptSig and/or Witness for it as appropriate
    fn finalize_input(&mut self, input_map: &mut P::Input) -> Result<(), Self::Error>;

    /// Call finalize_input on all inputs. The default implementation will simply silently not
    /// finalize any input that errors in `finalize_input`. This method returns a result to enable
    /// other finalizer implementations to override it with more complex functionality.
    #[allow(unused_must_use)]
    fn finalize(&mut self, pst: &mut P) -> Result<(), Self::Error> {
        pst.input_maps_mut()
            .iter_mut()
            .try_for_each(|input_map| self.finalize_input(input_map));
        Ok(())
    }
}

pub trait PSTExtractor<A, P>
where
    A: AddressEncoder,
    P: PST<A>,
{
    /// An associated error type that can be instantiated from the PST's Error type. This may be
    /// the PST's Error type.
    type Error: std::error::Error + From<P::Error>;

    fn extract(&mut self, pst: &P) -> Result<BitcoinTx, Self::Error>;
}
