use std::collections::HashMap;

use riemann_core::{
    ser::{Ser},
    types::primitives::{PrefixVec}
};

use crate::{
    psbt::common::{PSBTError, PSBTKey, PSBTValue},
    types::{
        script::{Witness},
        transactions::{LegacyTx, sighash_from_u8, Sighash, TxError},
        txout::{TxOut},
    },
};

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
            Some(predicate) => {
                Box::new(move |k: &PSBTKey, v: &PSBTValue| {
                    predicate(k, v)?;
                    new(k, v)
                })
            }
            None => new
        };
        self.0.insert(key_type, updated);
    }

    /// Remove the (potentially composed) predicate at any key
    pub fn remove(&mut self, key_type: u8) {
        self.0.remove(&key_type);
    }
}

/// Check that a value can be interpreted as a bip32 fingerprint + derivation
pub fn validate_bip32_value(val: &PSBTValue) -> Result<(), PSBTError> {
    if !val.is_empty() && val.len() % 4 != 0  {
        Err(PSBTError::InvalidBIP32Path)
    } else {
        Ok(())
    }
}

/// Validate that a key is a fixed length
pub fn validate_fixed_key_length(key: &PSBTKey, length: usize) -> Result<(), PSBTError> {
    if key.len() != length {
        Err(PSBTError::WrongKeyLength{expected: length, got: key.len()})
    } else {
        Ok(())
    }
}

/// Validate that a key is a fixed length
pub fn validate_fixed_val_length(val: &PSBTValue, length: usize) -> Result<(), PSBTError> {
    if val.len() != length {
        Err(PSBTError::WrongValueLength{expected: length, got: val.len()})
    } else {
        Ok(())
    }
}

/// Ensure that a key is exactly 1 byte
pub fn validate_single_byte_key_type(key: &PSBTKey) -> Result<(), PSBTError> {
    validate_fixed_key_length(key, 1)
}

/// Ensure that a key has the expected key type
pub fn validate_expected_key_type(key: &PSBTKey, key_type: u8) ->  Result<(), PSBTError> {
    if key.key_type() != key_type {
        Err(PSBTError::WrongKeyType{expected: key_type, got: key.key_type()})
    } else {
        Ok(())
    }
}

/// Attempt to deserialize a value as a as transaction
pub fn try_val_as_tx(val: &PSBTValue) -> Result<LegacyTx, PSBTError> {
    let mut tx_bytes = val.items();
    Ok(LegacyTx::deserialize(&mut tx_bytes, 0)?)
}

/// Attempt to deserialize a value as a Bitcoin Output
pub fn try_val_as_tx_out(val: &PSBTValue) -> Result<TxOut, PSBTError> {
    let mut out_bytes = val.items();
    Ok(TxOut::deserialize(&mut out_bytes, 0)?)
}

/// Attempt to deserialize a value as a sighash flag
pub fn try_val_as_sighash(val: &PSBTValue) -> Result<Sighash, PSBTError> {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&val.items()[..4]);
    let sighash = u32::from_le_bytes(buf);
    if sighash > 0xff {  // bits higher than the first byte should be empty
        return Err(TxError::UnknownSighash(0xff).into())
    }
    Ok(sighash_from_u8(sighash as u8)?)
}

/// Attempt to deserialize a value as a script Witness
pub fn try_val_as_witness(val: &PSBTValue) -> Result<Witness, PSBTError> {
    let mut wit_bytes = val.items();
    Ok(Witness::deserialize(&mut wit_bytes, 0)?)
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
        validate_bip32_value(val)
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
        validate_fixed_key_length(key, 34)?;
        validate_bip32_value(val)
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
        try_val_as_tx_out(val).map(|_| ())
    }

    /// Validate a PSBT_IN_PARTIAL_SIG key-value pair in an input map
    pub fn validate_in_partial_sig(key: &PSBTKey, _val: &PSBTValue) -> Result<(), PSBTError> {
        // 34 = 33-byte pubkey + 1-byte type
        validate_expected_key_type(key, 2)?;
        validate_fixed_key_length(key, 34)
        // TODO: validate val is signature
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
        validate_fixed_key_length(key, 34)?;
        validate_bip32_value(val)
    }

    /// Validate PSBT_IN_FINAL_SCRIPTSIG kv pair.
    pub fn validate_finalized_script_sig(key: &PSBTKey, _val: &PSBTValue) -> Result<(), PSBTError> {
        validate_expected_key_type(key, 7)?;
        validate_single_byte_key_type(key)
        // TODO: Script isn't nonsense
    }

    /// Validate PSBT_IN_FINAL_SCRIPTWITNESS kv pair.
    pub fn validate_finalized_script_witness(key: &PSBTKey, _val: &PSBTValue) -> Result<(), PSBTError> {
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
