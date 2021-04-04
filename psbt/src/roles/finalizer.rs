use crate::{input::InputKey, roles::PstFinalizer, Psbt, PsbtError, PsbtInput, Pst, PstMap};
use bitcoins::{
    enc::encoder::BitcoinEncoderMarker,
    prelude::Hash160Digest,
    types::{BitcoinOutpoint, BitcoinTransaction, ScriptType},
};
use coins_bip32::{self as bip32};
use coins_core::prelude::{Digest, MarkedDigestOutput, Transaction};

/// A finalizer that creates WPKH witnesses
pub struct PsbtWpkhFinalizer();

fn clear_input_map(input_map: &mut PsbtInput) {
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

/// Finalize an input, creating a ScriptSig and/or Witness for it as appropriate
fn finalize_input(outpoint: &BitcoinOutpoint, input_map: &mut PsbtInput) -> Result<(), PsbtError> {
    let non_witness_utxo = input_map.non_witness_utxo()?;
    let prevout = non_witness_utxo
        .txout_from_outpoint(outpoint)
        .ok_or_else(|| {
            PsbtError::MissingInfo(format!(
                "Input TXO does not match while finalizing. Outpoint is {:?}",
                outpoint
            ))
        })?;

    let pkh = match prevout.standard_type() {
        ScriptType::Wpkh(data) => data,
        other => {
            return Err(PsbtError::WrongPrevoutScriptType {
                got: other,
                expected: vec![ScriptType::Wpkh(Hash160Digest::default())],
            })
        }
    };

    // If any pubkeys match, build a witness and finalize
    if let Some((pubkey, partial_sig, sighash)) =
        input_map.partial_sigs().iter().find(|(pubkey, _, _)| {
            pkh.as_slice() == coins_core::hashes::Hash160::digest(&pubkey.to_bytes()).as_slice()
        })
    {
        let mut witness = bitcoins::types::Witness::default();
        let mut sig_bytes = vec![];
        sig_bytes.extend(partial_sig.to_asn1().as_bytes());
        sig_bytes.extend(&[sighash.to_u8()]);

        witness.push(pubkey.to_bytes().as_ref().into());
        witness.push(sig_bytes.into());

        input_map.insert_witness(witness);
        clear_input_map(input_map);
        Ok(())
    } else {
        Err(PsbtError::MissingKey(InputKey::PartialSig as u8))
    }
}

impl<A, E> PstFinalizer<A, Psbt<A, E>> for PsbtWpkhFinalizer
where
    A: BitcoinEncoderMarker,
    E: bip32::enc::XKeyEncoder,
{
    type Error = PsbtError;

    fn finalize(&mut self, pst: &mut Psbt<A, E>) -> Result<(), PsbtError> {
        let outpoints: Vec<BitcoinOutpoint> = pst
            .tx()?
            .inputs()
            .iter()
            .map(|txin| txin.outpoint)
            .collect();
        let input_maps = pst.input_maps_mut();
        for (o, i) in outpoints.iter().zip(input_maps.iter_mut()) {
            finalize_input(o, i)?;
        }
        Ok(())
    }
}
