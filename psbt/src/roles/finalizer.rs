use crate::{input::InputKey, roles::PSTFinalizer, PSBTError, PSBTInput, PSTMap, PSBT};
use rmn_bip32::{self as bip32, curve::SigSerialize, HasPubkey};
use rmn_btc::{enc::encoder::BitcoinEncoderMarker, types::ScriptType};

/// A finalizer that creates WPKH witnesses
pub struct PSBTWPKHFinalizer();

fn clear_input_map(input_map: &mut PSBTInput) {
    // clears the following keys:
    // PARTIAL_SIG = 2
    // SIGHASH_TYPE = 3
    // REDEEM_SCRIPT = 4
    // WITNESS_SCRIPT = 5
    // BIP32_DERIVATION = 6
    for key_type in 2u8..7u8 {
        let keys: Vec<_> = input_map
            .range_by_key_type(key_type)
            .map(|(k, _)| k.clone())
            .collect();
        for key in keys.iter() {
            input_map.remove(&key);
        }
    }
}

impl<A, E> PSTFinalizer<A, PSBT<A, E>> for PSBTWPKHFinalizer
where
    A: BitcoinEncoderMarker,
    E: bip32::enc::Encoder,
{
    type Error = PSBTError;

    fn finalize_input(&mut self, input_map: &mut PSBTInput) -> Result<(), Self::Error> {
        let prevout = input_map.witness_utxo()?;

        let pkh = match prevout.standard_type() {
            ScriptType::WPKH(data) => data,
            other => {
                return Err(PSBTError::WrongPrevoutScriptType {
                    got: other,
                    expected: vec![ScriptType::WPKH([0u8; 20])],
                })
            }
        };

        // If any pubkeys match, build a witness and finalize
        if let Some((pubkey, partial_sig, sighash)) = input_map
            .partial_sigs(None)
            .iter()
            .find(|(pubkey, _, _)| pkh == pubkey.pubkey_hash160())
        {
            let mut witness = rmn_btc::types::Witness::default();
            let mut sig_bytes = vec![];
            sig_bytes.extend(partial_sig.to_der());
            sig_bytes.extend(&[sighash.to_u8()]);

            witness.push(pubkey.pubkey_bytes().as_ref().into());
            witness.push(sig_bytes.into());

            input_map.insert_witness(&witness);
            clear_input_map(input_map);
            Ok(())
        } else {
            Err(PSBTError::MissingKey(InputKey::PARTIAL_SIG as u8))
        }
    }
}
