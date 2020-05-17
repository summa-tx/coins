use std::collections::HashMap;

use riemann_core::ser::{self, ByteFormat};

use rmn_bip32::{
    self as bip32,
    curve::{PointDeserialize, Secp256k1Backend, SigSerialize, Signature},
    derived::DerivedPubkey,
    keys::Pubkey,
    model::DerivedKey,
    path::KeyDerivation,
    Bip32Error, Secp256k1, XPub,
};

use rmn_btc::types::{
    script::{ScriptType, Witness},
    transactions::{LegacyTx, Sighash, TxError},
    txout::TxOut,
};

use crate::common::{PSBTError, PSBTKey, PSBTValue};

/// A PSBT key/value validation function. Returns `Ok(())` if the KV pair is valid, otherwise an
/// error.
pub type KVPredicate = Box<dyn Fn(&PSBTKey, &PSBTValue) -> Result<(), PSBTError>>;

/// The map key is the PSBT key-type to be validated. The value is a boxed function that performs
/// validation.
#[derive(Default)]
pub struct KVTypeSchema(pub HashMap<u8, KVPredicate>);

impl KVTypeSchema {
    /// Insert a predicate into the map. This creates a composition with any predicate already in
    /// the map. Which is to say, multiple inserts at the same key additive. They are ALL
    /// enforced.
    ///
    /// Custom schemas can be built manually, or made by getting the standard schema for a type
    /// and then updating it.
    pub fn insert(&mut self, key_type: u8, new: KVPredicate) {
        let existing = self.0.remove(&key_type);
        let updated: KVPredicate = match existing {
            Some(predicate) => Box::new(move |k: &PSBTKey, v: &PSBTValue| {
                predicate(k, v)?;
                new(k, v)
            }),
            None => new,
        };
        self.0.insert(key_type, updated);
    }

    /// Remove the (potentially composed) predicate at any key
    pub fn remove(&mut self, key_type: u8) {
        self.0.remove(&key_type);
    }
}

/// Check that a value can be interpreted as a bip32 fingerprint + derivation
pub fn try_val_as_key_derivation(val: &PSBTValue) -> Result<KeyDerivation, PSBTError> {
    if val.is_empty() || val.len() % 4 != 0 {
        return Err(PSBTError::InvalidBip32Path);
    }
    let limit = val.len() / 4;
    let mut deriv_bytes = &val.items()[..];
    Ok(KeyDerivation::read_from(&mut deriv_bytes, limit)?)
}

/// Validate that a key is a fixed length
pub fn validate_fixed_key_length(key: &PSBTKey, length: usize) -> Result<(), PSBTError> {
    if key.len() != length {
        Err(PSBTError::WrongKeyLength {
            expected: length,
            got: key.len(),
        })
    } else {
        Ok(())
    }
}

/// Validate that a key is a fixed length
pub fn validate_fixed_val_length(val: &PSBTValue, length: usize) -> Result<(), PSBTError> {
    if val.len() != length {
        Err(PSBTError::WrongValueLength {
            expected: length,
            got: val.len(),
        })
    } else {
        Ok(())
    }
}

/// Ensure that a key is exactly 1 byte
pub fn validate_single_byte_key_type(key: &PSBTKey) -> Result<(), PSBTError> {
    validate_fixed_key_length(key, 1)
}

/// Ensure that a key has the expected key type
pub fn validate_expected_key_type(key: &PSBTKey, key_type: u8) -> Result<(), PSBTError> {
    if key.key_type() != key_type {
        Err(PSBTError::WrongKeyType {
            expected: key_type,
            got: key.key_type(),
        })
    } else {
        Ok(())
    }
}

/// Compares an xpub key to its derivation, and ensure the depth marker matches tne stated
/// derivation depth
pub fn validate_xpub_depth(key: &PSBTKey, val: &PSBTValue) -> Result<(), PSBTError> {
    let expected = (val.len() / 4) - 1;
    if let Some(depth) = key.items().get(4) {
        if expected == *depth as usize {
            Ok(())
        } else {
            Err(PSBTError::Bip32DepthMismatch)
        }
    } else {
        Err(PSBTError::Bip32DepthMismatch)
    }
}

/// Attempt to parse a keyas a Secp256k1 pybkey
pub fn try_key_as_pubkey<'a>(key: &PSBTKey, backend: Option<&'a Secp256k1<'a>>) -> Result<Pubkey<'a>, PSBTError> {
    if key.len() != 34 {
        return Err(PSBTError::WrongKeyLength {
            expected: 34,
            got: key.len(),
        });
    }
    let mut buf = [0u8; 33];
    buf.copy_from_slice(&key.items()[1..]);
    Ok(Pubkey {
        key: <Secp256k1 as Secp256k1Backend<'_>>::Pubkey::from_pubkey_array(buf)?,
        backend,
    })
}

/// Attempt to deserialize a value as a as transaction
pub fn try_val_as_tx(val: &PSBTValue) -> Result<LegacyTx, PSBTError> {
    let mut tx_bytes = &val.items()[..];
    Ok(LegacyTx::read_from(&mut tx_bytes, 0)?)
}

/// Attempt to deserialize a value as a Bitcoin Output
pub fn try_val_as_tx_out(val: &PSBTValue) -> Result<TxOut, PSBTError> {
    let mut out_bytes = &val.items()[..];
    Ok(TxOut::read_from(&mut out_bytes, 0)?)
}

/// Attempt to deserialize a value as a sighash flag
pub fn try_val_as_sighash(val: &PSBTValue) -> Result<Sighash, PSBTError> {
    validate_fixed_val_length(val, 4)?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&val.items()[..4]);
    let sighash = u32::from_le_bytes(buf);
    if sighash > 0xff {
        // bits higher than the first byte should be empty
        return Err(TxError::UnknownSighash(0xff).into());
    }
    Ok(Sighash::from_u8(sighash as u8)?)
}

/// Attempt to deserialize a value as a signature
pub fn try_val_as_signature(val: &PSBTValue) -> Result<(Signature, Sighash), PSBTError> {
    let (sighash_flag, sig_bytes) =
        val.items()
            .split_last()
            .ok_or(PSBTError::WrongValueLength {
                got: 0,
                expected: 75,
            })?;

    let sig = Signature::try_from_der(sig_bytes)?;
    Ok((sig, Sighash::from_u8(*sighash_flag)?))
}

/// Attempt to deserialize a value as a script Witness
pub fn try_val_as_witness(val: &PSBTValue) -> Result<Witness, PSBTError> {
    let mut wit_bytes = &val.items()[..];
    let number = ser::read_compact_int(&mut wit_bytes)? as usize;
    Ok(Witness::read_from(&mut wit_bytes, number)?)
}

/// Attempt to parse a key as a valid extended pubkey
pub fn try_key_as_xpub<'a, E>(
    key: &PSBTKey,
    backend: Option<&'a Secp256k1>,
) -> Result<XPub<'a>, PSBTError>
where
    E: bip32::enc::Encoder,
{
    if key.len() < 2 {
        return Err(Bip32Error::BadXPubVersionBytes([0u8; 4]).into());
    }
    // strip off first byte (the type)
    let mut xpub_bytes = &key.items()[1..];
    Ok(E::read_xpub(&mut xpub_bytes, backend)?)
}

/// Attempt to convert a KV pair into a derived pubkey struct
pub fn try_kv_pair_as_derived_pubkey<'a>(
    key: &PSBTKey,
    val: &PSBTValue,
    backend: Option<&'a Secp256k1<'a>>,
) -> Result<DerivedPubkey<'a>, PSBTError> {
    let pubkey = if key.len() == 34 {
        let mut pubkey = [0u8; 33];
        pubkey.copy_from_slice(&key[1..34]);
        bip32::curve::Pubkey::from_pubkey_array(pubkey)?
    } else if key.len() == 66 {
        let mut pubkey = [0u8; 65];
        pubkey.copy_from_slice(&key[1..66]);
        bip32::curve::Pubkey::from_pubkey_array_uncompressed(pubkey)?
    } else {
        return Err(PSBTError::WrongKeyLength {
            got: key.len(),
            expected: 34,
        });
    };

    let deriv = try_val_as_key_derivation(val)?;

    let pubkey = bip32::keys::Pubkey {
        key: pubkey,
        backend,
    };

    Ok(DerivedPubkey::new(pubkey, deriv))
}

pub fn try_kv_pair_as_pubkey_and_sig<'a>(
    key: &PSBTKey,
    val: &PSBTValue,
    backend: Option<&'a Secp256k1<'a>>,
) -> Result<(Pubkey<'a>, Signature, Sighash), PSBTError> {
    let pubkey = try_key_as_pubkey(key, backend)?;

    let (sig, sighash) = try_val_as_signature(val)?;
    Ok((pubkey, sig, sighash))
}

/// Validation functions for PSBT Global maps
pub mod global {
    use super::*;
    /// Validate a `PSBT_GLOBAL_UNSIGNED_TX` key-value pair in a global map
    pub fn validate_tx(key: &PSBTKey, val: &PSBTValue) -> Result<(), PSBTError> {
        validate_expected_key_type(key, 0)?;
        validate_single_byte_key_type(key)?;
        try_val_as_tx(val).map(|_| ())
    }

    /// Validate PSBT_GLOBAL_XPUB kv pairs. Checks that the xpub is 78 bytes long, and that the value
    /// can be interpreted as a 4-byte fingerprint with a list of 32-bit integers.
    pub fn validate_xpub(key: &PSBTKey, val: &PSBTValue) -> Result<(), PSBTError> {
        validate_expected_key_type(key, 1)?;
        validate_fixed_key_length(key, 79)?;
        validate_xpub_depth(key, val)
    }

    /// Validate version kv pair. Checks whether the version is exactly 32-bytes.
    pub fn validate_version(key: &PSBTKey, val: &PSBTValue) -> Result<(), PSBTError> {
        validate_expected_key_type(key, 0xfb)?;
        validate_single_byte_key_type(key)?;
        validate_fixed_val_length(val, 4)
    }
}

/// Validation functions for PSBT Output maps
pub mod output {
    use super::*;
    /// Validate PSBT_OUT_REDEEM_SCRIPT kv pair.
    pub fn validate_redeem_script(key: &PSBTKey, _val: &PSBTValue) -> Result<(), PSBTError> {
        validate_expected_key_type(key, 0)?;
        validate_single_byte_key_type(key)
        // TODO: Script isn't nonsense
    }

    /// Validate PSBT_OUT_WITNESS_SCRIPT kv pair.
    pub fn validate_witness_script(key: &PSBTKey, _val: &PSBTValue) -> Result<(), PSBTError> {
        validate_expected_key_type(key, 1)?;
        validate_single_byte_key_type(key)
        // TODO: Script isn't nonsense
    }

    /// Validate PSBT_OUT_BIP32_DERIVATION kv pairs. Checks that the
    /// pubkey is 33 bytes long, and that the value can be interpreted as a 4-byte fingerprint
    /// with a list of 0-or-more 32-bit integers.
    pub fn validate_bip32_derivations(key: &PSBTKey, val: &PSBTValue) -> Result<(), PSBTError> {
        // 34 = 33-byte pubkey + 1-byte type
        validate_expected_key_type(key, 2)?;
        if validate_fixed_key_length(key, 66).is_err() {
            validate_fixed_key_length(key, 34)?;
        }
        try_val_as_key_derivation(val)?;
        Ok(())
    }
}

/// Validation functions for PSBT Input maps
pub mod input {
    use super::*;

    /// Validate a PSBT_IN_NON_WITNESS_UTXO key-value pair in an input map
    pub fn validate_in_non_witness(key: &PSBTKey, val: &PSBTValue) -> Result<(), PSBTError> {
        validate_expected_key_type(key, 0)?;
        validate_single_byte_key_type(key)?;
        try_val_as_tx(val).map(|_| ())
    }

    /// Validate a PSBT_IN_WITNESS_UTXO key-value pair in an input map
    pub fn validate_in_witness(key: &PSBTKey, val: &PSBTValue) -> Result<(), PSBTError> {
        validate_expected_key_type(key, 1)?;
        validate_single_byte_key_type(key)?;
        let tx_out = try_val_as_tx_out(val)?;
        match tx_out.script_pubkey.standard_type() {
            ScriptType::WSH(_) | ScriptType::WPKH(_) | ScriptType::SH(_) => Ok(()),
            _ => Err(PSBTError::InvalidWitnessTXO),
        }
    }

    /// Validate a PSBT_IN_PARTIAL_SIG key-value pair in an input map
    pub fn validate_in_partial_sig(key: &PSBTKey, val: &PSBTValue) -> Result<(), PSBTError> {
        // 34 = 33-byte pubkey + 1-byte type
        validate_expected_key_type(key, 2)?;
        if validate_fixed_key_length(key, 34).is_err() {
            validate_fixed_key_length(key, 66)?;
        }
        try_val_as_signature(val).map(|_| ())
    }

    /// Validate a PSBT_IN_SIGHASH_TYPE key-value pair in an input map
    pub fn validate_sighash_type(key: &PSBTKey, val: &PSBTValue) -> Result<(), PSBTError> {
        validate_expected_key_type(key, 3)?;
        validate_single_byte_key_type(key)?;
        validate_fixed_val_length(val, 4)?;
        try_val_as_sighash(val).map(|_| ())
    }

    /// Validate PSBT_IN_REDEEM_SCRIPT kv pair.
    pub fn validate_redeem_script(key: &PSBTKey, _val: &PSBTValue) -> Result<(), PSBTError> {
        validate_expected_key_type(key, 4)?;
        validate_single_byte_key_type(key)
        // TODO: Script isn't nonsense
    }

    /// Validate PSBT_IN_WITNESS_SCRIPT kv pair.
    pub fn validate_witness_script(key: &PSBTKey, _val: &PSBTValue) -> Result<(), PSBTError> {
        validate_expected_key_type(key, 5)?;
        validate_single_byte_key_type(key)
        // TODO: Script isn't nonsense
    }

    /// Validate PSBT_IN_BIP32_DERIVATION kv pairs. Checks that the
    /// pubkey is 33 bytes long, and that the value can be interpreted as a 4-byte fingerprint
    /// with a list of 0-or-more 32-bit integers.
    pub fn validate_bip32_derivations(key: &PSBTKey, val: &PSBTValue) -> Result<(), PSBTError> {
        // 34 = 33-byte pubkey + 1-byte type
        validate_expected_key_type(key, 6)?;
        try_key_as_pubkey(key, None)?;
        try_val_as_key_derivation(val)?;
        Ok(())
    }

    /// Validate PSBT_IN_FINAL_SCRIPTSIG kv pair.
    pub fn validate_finalized_script_sig(key: &PSBTKey, _val: &PSBTValue) -> Result<(), PSBTError> {
        validate_expected_key_type(key, 7)?;
        validate_single_byte_key_type(key)
        // TODO: Script isn't nonsense
    }

    /// Validate PSBT_IN_FINAL_SCRIPTWITNESS kv pair.
    pub fn validate_finalized_script_witness(
        key: &PSBTKey,
        _val: &PSBTValue,
    ) -> Result<(), PSBTError> {
        validate_expected_key_type(key, 8)?;
        validate_single_byte_key_type(key)
        // TODO: Script isn't nonsense
    }

    /// Validate PSBT_IN_POR_COMMITMENT kv pair.
    pub fn validate_por_commitment(key: &PSBTKey, _val: &PSBTValue) -> Result<(), PSBTError> {
        validate_expected_key_type(key, 9)?;
        validate_single_byte_key_type(key)
        // TODO: Bip 127?
    }
}
