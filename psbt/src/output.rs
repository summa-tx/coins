use std::collections::{btree_map, BTreeMap};

use coins_bip32::derived::DerivedPubkey;

use bitcoins::types::script::Script;

use crate::{
    common::{PSBTError, PSBTKey, PSBTValidate, PSBTValue, PSTMap},
    schema,
};

psbt_map!(PSBTOutput);

/// PSBT Output Key Types
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum OutputKey {
    /// Output key type for PSBT_OUT_REDEEM_SCRIPT as defined in BIP174
    REDEEM_SCRIPT = 0,
    /// Output key type for PSBT_OUT_WITNESS_SCRIPT as defined in BIP174
    WITNESS_SCRIPT = 1,
    /// Output key type for PSBT_OUT_BIP32_DERIVATION as defined in BIP174
    BIP32_DERIVATION = 2,
    /// Output key type for PSBT_OUT_PROPRIETARY as defined in BIP174
    PROPRIETARY = 0xfc,
}

impl From<OutputKey> for PSBTKey {
    fn from(k: OutputKey) -> PSBTKey {
        vec![k as u8].into()
    }
}

impl PSBTValidate for PSBTOutput {
    fn consistency_checks(&self) -> Result<(), PSBTError> {
        // No current checks
        Ok(())
    }

    fn standard_schema() -> schema::KVTypeSchema {
        let mut s: schema::KVTypeSchema = Default::default();
        s.insert(
            OutputKey::REDEEM_SCRIPT as u8,
            Box::new(|k, v| (schema::output::validate_redeem_script(k, v))),
        );
        s.insert(
            OutputKey::WITNESS_SCRIPT as u8,
            Box::new(|k, v| (schema::output::validate_witness_script(k, v))),
        );
        s.insert(
            OutputKey::BIP32_DERIVATION as u8,
            Box::new(|k, v| (schema::output::validate_bip32_derivations(k, v))),
        );
        s
    }
}

impl PSBTOutput {
    /// Returns the BIP174 PSBT_OUT_REDEEM_SCRIPT transaction if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    /// - Returns a PSBTError::InvalidTx error if the value at that key is not a valid TX.
    pub fn out_redeem_script(&self) -> Result<Script, PSBTError> {
        let script_bytes = self.must_get(&OutputKey::REDEEM_SCRIPT.into())?.items();
        Ok(script_bytes.into())
    }

    /// Returns the BIP174 PSBT_OUT_WITNESS_SCRIPT transaction if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    /// - Returns a PSBTError::InvalidTx error if the value at that key is not a valid TX.
    pub fn out_witness_script(&self) -> Result<Script, PSBTError> {
        let script_bytes = self.must_get(&OutputKey::WITNESS_SCRIPT.into())?.items();
        Ok(script_bytes.into())
    }

    /// Returns a range containing any PSBT_OUT_BIP32_DERIVATION.
    pub fn pubkey_kv_pairs(&self) -> btree_map::Range<PSBTKey, PSBTValue> {
        self.range_by_key_type(OutputKey::BIP32_DERIVATION as u8)
    }

    /// Returns a vec containing parsed public keys. Unparsable keys will be ignored
    pub fn parsed_pubkey_derivations(&self) -> Vec<DerivedPubkey> {
        self.pubkey_kv_pairs()
            .map(|(k, v)| schema::try_kv_pair_as_derived_pubkey(k, v))
            .filter_map(Result::ok)
            .collect()
    }
}
