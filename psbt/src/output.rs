use std::collections::{btree_map, BTreeMap};

use coins_bip32::derived::DerivedPubkey;

use bitcoins::types::script::Script;

use crate::{
    common::{PSBTKey, PSBTValue, PsbtError, PsbtValidate, PstMap},
    schema,
};

psbt_map!(PsbtOutput);

/// PSBT Output Key Types
#[repr(u8)]
pub enum OutputKey {
    /// Output key type for PSBT_OUT_REDEEM_SCRIPT as defined in BIP174
    RedeemScript = 0,
    /// Output key type for PSBT_OUT_WITNESS_SCRIPT as defined in BIP174
    WitnessScript = 1,
    /// Output key type for PSBT_OUT_BIP32_DERIVATION as defined in BIP174
    Bip32Derivation = 2,
    /// Output key type for PSBT_OUT_PROPRIETARY as defined in BIP174
    Proprietary = 0xfc,
}

impl From<OutputKey> for PSBTKey {
    fn from(k: OutputKey) -> PSBTKey {
        vec![k as u8].into()
    }
}

impl PsbtValidate for PsbtOutput {
    fn consistency_checks(&self) -> Result<(), PsbtError> {
        // No current checks
        Ok(())
    }

    fn standard_schema() -> schema::KvTypeSchema {
        let mut s: schema::KvTypeSchema = Default::default();
        s.insert(
            OutputKey::RedeemScript as u8,
            Box::new(|k, v| (schema::output::validate_redeem_script(k, v))),
        );
        s.insert(
            OutputKey::WitnessScript as u8,
            Box::new(|k, v| (schema::output::validate_witness_script(k, v))),
        );
        s.insert(
            OutputKey::Bip32Derivation as u8,
            Box::new(|k, v| (schema::output::validate_bip32_derivations(k, v))),
        );
        s
    }
}

impl PsbtOutput {
    /// Returns the BIP174 PSBT_OUT_REDEEM_SCRIPT transaction if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PsbtError::MissingKey` error if no value at that key.
    /// - Returns a PsbtError::InvalidTx error if the value at that key is not a valid TX.
    pub fn out_redeem_script(&self) -> Result<Script, PsbtError> {
        let script_bytes = self.must_get(&OutputKey::RedeemScript.into())?.items();
        Ok(script_bytes.into())
    }

    /// Returns the BIP174 PSBT_OUT_WITNESS_SCRIPT transaction if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PsbtError::MissingKey` error if no value at that key.
    /// - Returns a PsbtError::InvalidTx error if the value at that key is not a valid TX.
    pub fn out_witness_script(&self) -> Result<Script, PsbtError> {
        let script_bytes = self.must_get(&OutputKey::WitnessScript.into())?.items();
        Ok(script_bytes.into())
    }

    /// Returns a range containing any PSBT_OUT_BIP32_DERIVATION.
    pub fn pubkey_kv_pairs(&self) -> btree_map::Range<PSBTKey, PSBTValue> {
        self.range_by_key_type(OutputKey::Bip32Derivation as u8)
    }

    /// Returns a vec containing parsed public keys. Unparsable keys will be ignored
    pub fn parsed_pubkey_derivations(&self) -> Vec<DerivedPubkey> {
        self.pubkey_kv_pairs()
            .map(|(k, v)| schema::try_kv_pair_as_derived_pubkey(k, v))
            .filter_map(Result::ok)
            .collect()
    }
}
