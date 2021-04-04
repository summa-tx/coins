use crate::{roles::PstExtractor, Psbt, PsbtError, Pst};
use bitcoins::{enc::encoder::BitcoinEncoderMarker, types::BitcoinTx};
use coins_bip32 as bip32;
use coins_core::builder::TxBuilder;

/// An extractor
pub struct PsbtExtractor();

impl<A, E> PstExtractor<A, Psbt<A, E>> for PsbtExtractor
where
    A: BitcoinEncoderMarker,
    E: bip32::enc::XKeyEncoder,
{
    type Error = PsbtError;

    fn extract(&mut self, pst: &Psbt<A, E>) -> Result<BitcoinTx, Self::Error> {
        // For convenience, we use a WitnessBuilder. If we ever set a witness, we return a witness
        // transaction. Otherwise we return a legacy transaction.
        let mut builder = pst.tx_builder()?;

        for (i, input_map) in pst.input_maps().iter().enumerate() {
            if !input_map.is_finalized() {
                return Err(PsbtError::UnfinalizedInput(i));
            }

            // Insert a script sig if we have one.
            if let Ok(script_sig) = input_map.finalized_script_sig() {
                builder = builder.set_script_sig(i, script_sig);
            }

            // Insert a witness if we have one, or an empty witness otherwise
            if let Ok(witness) = input_map.finalized_script_witness() {
                builder = builder.extend_witnesses(vec![witness]);
            } else {
                builder = builder.extend_witnesses(vec![Default::default()]);
            }
        }

        Ok(builder.build()?)
    }
}
