use rmn_btc::{
    enc::encoder::BitcoinEncoderMarker,
    types::{ScriptType},
};
use rmn_bip32::{self as bip32, HasPubkey, curve::SigSerialize};
use crate::{PSBT, PSBTError, PSBTInput, input::InputKey, roles::PSTFinalizer};

/// A finalizer that creates WPKH witnesses
pub struct PSBTWPKHFinalizer();


impl<'a, A, E> PSTFinalizer<'a, A, PSBT<A, E>> for PSBTWPKHFinalizer
where
    A: BitcoinEncoderMarker,
    E: bip32::enc::Encoder,
{
    type Error = PSBTError;

    fn finalize_input(&mut self, input_map: &mut PSBTInput) -> Result<(), Self::Error> {
        let prevout = input_map.witness_utxo()?;

        let pkh = match prevout.standard_type() {
            ScriptType::WPKH(data) => {data},
            other => {
                return Err(PSBTError::WrongPrevoutScriptType{
                    got: other,
                    expected: vec![ScriptType::WPKH([0u8; 20])]
                })
            }
        };

        while let Some((pubkey, partial_sig, sighash)) = input_map.partial_sigs(None).iter().next() {
            let mut witness = rmn_btc::types::Witness::default();

            if pubkey.pubkey_hash160() == pkh {
                let mut sig_bytes = vec![];
                sig_bytes.extend(partial_sig.to_der());
                sig_bytes.extend(&[sighash.to_u8()]);

                witness.push(pubkey.pubkey_bytes().as_ref().into());
                witness.push(sig_bytes.into());

                input_map.insert_witness(&witness);
                break;
            }
        }
        Err(PSBTError::MissingKey(InputKey::PARTIAL_SIG as u8))
    }
}
