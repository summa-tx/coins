use riemann_core::{
    ser::{Ser},
    types::primitives::{PrefixVec}
};

use crate::{
    psbt::common::{PSBTError, PSBTKey, PSBTValue},
    types::transactions::{LegacyTx},
};

/// A PSBT key/value validation function. Returns `Ok(())` if the KV pair is valid, otherwise an
/// error.
pub type KVPredicate<'a> = &'a dyn Fn(&PSBTKey, &PSBTValue) -> Result<(), PSBTError>;

/// The first item is the key-type that it operates on. The second item is a KVPredicate
pub type KVTypeSchema<'a> = (u8, KVPredicate<'a>);

/// Check that a value can be interpreted as a bip32 fingerprint + derivation
fn validate_bip32_value(val: &PSBTValue) -> Result<(), PSBTError> {
    if !val.is_empty() && val.len() % 4 != 0  {
        Err(PSBTError::InvalidBIP32Path)
    } else {
        Ok(())
    }
}

/// Validate that a key is a fixed length
fn validate_fixed_key_length(key: &PSBTKey, length: usize) -> Result<(), PSBTError> {
    if key.len() != length {
        Err(PSBTError::WrongKeyLength{expected: length, got: key.len()})
    } else {
        Ok(())
    }
}

/// Validate that a key is a fixed length
fn validate_fixed_val_length(val: &PSBTValue, length: usize) -> Result<(), PSBTError> {
    if val.len() != length {
        Err(PSBTError::WrongValueLength{expected: length, got: val.len()})
    } else {
        Ok(())
    }
}


/// Ensure that a key is exactly 1 byte
fn validate_single_byte_key_type(key: &PSBTKey) -> Result<(), PSBTError> {
    validate_fixed_key_length(key, 1)
}

/// Ensure that a key has the expected key type
fn validate_expected_key_type(key: &PSBTKey, key_type: u8) ->  Result<(), PSBTError> {
    if key.key_type() != key_type {
        Err(PSBTError::WrongKeyType{expected: key_type, got: key.key_type()})
    } else {
        Ok(())
    }
}

/// Ensure that a value can be deserialzed as a transaction
fn validate_val_is_tx(val: &PSBTValue) -> Result<(), PSBTError> {
    let mut tx_bytes = val.items();
    Ok(LegacyTx::deserialize(&mut tx_bytes, 0).map(|_| ())?)
}


/// Validate PSBT_OUT_BIP32_DERIVATION kv pairs. Checks that the
/// pubkey is 33 bytes long, and that the value can be interpreted as a 4-byte fingerprint with a
/// list of 0-or-more 32-bit integers.
pub fn validate_out_bip32_derivations(key: &PSBTKey, val: &PSBTValue) -> Result<(), PSBTError> {
    // 34 = 33-byte pubkey + 1-byte type
    validate_fixed_key_length(key, 34)?;
    validate_expected_key_type(key, 2)?;
    validate_bip32_value(val)
}

/// Validate PSBT_OUT_BIP32_DERIVATION kv pairs. Checks that the
/// pubkey is 33 bytes long, and that the value can be interpreted as a 4-byte fingerprint with a
/// list of 0-or-more 32-bit integers.
pub fn validate_in_bip32_derivations(key: &PSBTKey, val: &PSBTValue) -> Result<(), PSBTError> {
    // 34 = 33-byte pubkey + 1-byte type
    validate_fixed_key_length(key, 34)?;
    validate_expected_key_type(key, 6)?;
    validate_bip32_value(val)
}

/// Validate a `PSBT_GLOBAL_UNSIGNED_TX` key-value pair in a global map
pub fn validate_tx(key: &PSBTKey, val: &PSBTValue) -> Result<(), PSBTError> {
    validate_single_byte_key_type(key)?;
    validate_expected_key_type(key, 0)?;
    validate_val_is_tx(val)
}

/// Validate PSBT_GLOBAL_XPUB kv pairs. Checks that the xpub is 78 bytes long, and that the value
/// can be interpreted as a 4-byte fingerprint with a list of 32-bit integers.
pub fn validate_xpub(key: &PSBTKey, val: &PSBTValue) -> Result<(), PSBTError> {
    validate_fixed_key_length(key, 79)?;
    validate_expected_key_type(key, 1)?;
    validate_bip32_value(val)
}

/// Validate version kv pair. Checks whether the version is exactly 32-bytes.
pub fn validate_version(key: &PSBTKey, val: &PSBTValue) -> Result<(), PSBTError> {
    validate_single_byte_key_type(key)?;
    validate_expected_key_type(key, 0xfb)?;
    validate_fixed_val_length(val, 4)
}
