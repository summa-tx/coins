use std::collections::{btree_map, BTreeMap};

use riemann_core::{primitives::PrefixVec, ser::Ser};

use rmn_bip32::{self as bip32, DerivedPubkey, PointSerialize, SigSerialize};

use crate::{
    psbt::{
        common::{PSBTError, PSBTKey, PSBTValidate, PSBTValue, PSTMap},
        schema,
    },
    types::{
        script::{Script, ScriptSig, Witness},
        transactions::{LegacyTx, Sighash},
        txout::TxOut,
    },
};

psbt_map!(PSBTInput);

/// PSBT Input Key Types
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum InputKey {
    /// Input key type for PSBT_IN_NON_WITNESS_UTXO as defined in BIP174
    NON_WITNESS_UTXO = 0,
    /// Input key type for PSBT_IN_WITNESS_UTXO as defined in BIP174
    WITNESS_UTXO = 1,
    /// Input key type for PSBT_IN_PARTIAL_SIG as defined in BIP174
    PARTIAL_SIG = 2,
    /// Input key type for PSBT_IN_SIGHASH_TYPE as defined in BIP174
    SIGHASH_TYPE = 3,
    /// Input key type for PSBT_IN_REDEEM_SCRIPT as defined in BIP174
    REDEEM_SCRIPT = 4,
    /// Input key type for PSBT_IN_WITNESS_SCRIPT as defined in BIP174
    WITNESS_SCRIPT = 5,
    /// Input key type for PSBT_IN_BIP32_DERIVATION as defined in BIP174
    BIP32_DERIVATION = 6,
    /// Input key type for PSBT_IN_FINAL_SCRIPTSIG as defined in BIP174
    FINAL_SCRIPTSIG = 7,
    /// Input key type for PSBT_IN_FINAL_SCRIPTWITNESS as defined in BIP174
    FINAL_SCRIPTWITNESS = 8,
    /// Input key type for PSBT_IN_POR_COMMITMENT as defined in BIP174
    POR_COMMITMENT = 9,
    /// Input key type for PSBT_IN_PROPRIETARY as defined in BIP174
    PROPRIETARY = 0xfc,
}

impl From<InputKey> for PSBTKey {
    fn from(k: InputKey) -> PSBTKey {
        vec![k as u8].into()
    }
}

impl PSBTValidate for PSBTInput {
    fn consistency_checks(&self) -> Result<(), PSBTError> {
        // Can't contain both witness and non-witness input info
        if self.has_witness_utxo() && self.has_non_witness_utxo() {
            return Err(PSBTError::InvalidPSBT); // TODO: differentiate error
        }
        // TODO
        // - validate that all signatures use the sighash type
        // - validate UTXO <> redeem_script <> witness_script consistency for this input

        Ok(())
    }

    fn standard_schema() -> schema::KVTypeSchema {
        let mut s: schema::KVTypeSchema = Default::default();
        s.insert(
            InputKey::NON_WITNESS_UTXO as u8,
            Box::new(|k, v| (schema::input::validate_in_non_witness(k, v))),
        );
        s.insert(
            InputKey::WITNESS_UTXO as u8,
            Box::new(|k, v| (schema::input::validate_in_witness(k, v))),
        );
        s.insert(
            InputKey::PARTIAL_SIG as u8,
            Box::new(|k, v| (schema::input::validate_in_partial_sig(k, v))),
        );
        s.insert(
            InputKey::SIGHASH_TYPE as u8,
            Box::new(|k, v| (schema::input::validate_sighash_type(k, v))),
        );
        s.insert(
            InputKey::REDEEM_SCRIPT as u8,
            Box::new(|k, v| (schema::input::validate_redeem_script(k, v))),
        );
        s.insert(
            InputKey::WITNESS_SCRIPT as u8,
            Box::new(|k, v| (schema::input::validate_witness_script(k, v))),
        );
        s.insert(
            InputKey::BIP32_DERIVATION as u8,
            Box::new(|k, v| (schema::input::validate_bip32_derivations(k, v))),
        );
        s.insert(
            InputKey::FINAL_SCRIPTSIG as u8,
            Box::new(|k, v| (schema::input::validate_finalized_script_sig(k, v))),
        );
        s.insert(
            InputKey::FINAL_SCRIPTWITNESS as u8,
            Box::new(|k, v| (schema::input::validate_finalized_script_witness(k, v))),
        );
        s.insert(
            InputKey::POR_COMMITMENT as u8,
            Box::new(|k, v| (schema::input::validate_por_commitment(k, v))),
        );
        s
    }
}

impl PSBTInput {
    /// Returns true if the map has a non-witness utxo in it.
    pub fn has_non_witness_utxo(&self) -> bool {
        self.contains_key(&InputKey::NON_WITNESS_UTXO.into())
    }

    /// Returns the BIP174 PSBT_IN_NON_WITNESS_UTXO transaction if present and valid.
    ///'
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    /// - Returns a `PSBTError::InvalidTx` error if the value at that key is not a valid TX.
    pub fn non_witness_utxo(&self) -> Result<LegacyTx, PSBTError> {
        let tx_val = self.must_get(&InputKey::NON_WITNESS_UTXO.into())?;
        schema::try_val_as_tx(tx_val)
    }

    /// Returns true if the map has a non-witness utxo in it.
    pub fn has_witness_utxo(&self) -> bool {
        self.contains_key(&InputKey::WITNESS_UTXO.into())
    }

    /// Returns the BIP174 PSBT_IN_WITNESS_UTXO TxOut if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    /// - Returns a `PSBTError::SerError` if the value at that key is not a valid tx out.
    pub fn witness_utxo(&self) -> Result<TxOut, PSBTError> {
        let out_val = self.must_get(&InputKey::WITNESS_UTXO.into())?;
        schema::try_val_as_tx_out(out_val)
    }

    /// Returns a range containing any PSBT_IN_PARTIAL_SIG
    pub fn partial_sigs(&self) -> btree_map::Range<PSBTKey, PSBTValue> {
        self.range_by_key_type(InputKey::PARTIAL_SIG as u8)
    }

    /// Inserts a signature into the map
    pub fn insert_partial_sig(&mut self, pk: bip32::Pubkey, sig: bip32::Signature) {
        let mut key = vec![InputKey::PARTIAL_SIG as u8];
        key.extend(pk.to_array().iter());

        let mut val = vec![];
        val.extend(sig.to_der());
        val.push(self.sighash_or_default() as u8);

        self.insert(key.into(), val.into());
    }

    /// Returns the BIP174 PSBT_IN_SIGHASH_TYPE if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    /// - Returns a `PSBTError::TxError(TxError::UnknownSighash)` if the sighash is abnormal
    pub fn sighash(&self) -> Result<Sighash, PSBTError> {
        let val = self.must_get(&InputKey::SIGHASH_TYPE.into())?;
        schema::try_val_as_sighash(&val)
    }

    /// Returns the BIP174 PSBT_IN_SIGHASH_TYPE if present and valid, otherwise defaults to
    /// `SIGHASH_ALL`. This ignores errors from invalid/unknown sighash flags
    pub fn sighash_or_default(&self) -> Sighash {
        self.sighash().unwrap_or(Sighash::All)
    }

    /// Returns the BIP174 PSBT_IN_REDEEM_SCRIPT if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    pub fn redeem_script(&self) -> Result<Script, PSBTError> {
        let script_bytes = self.must_get(&InputKey::REDEEM_SCRIPT.into())?.items();
        Ok(script_bytes.into())
    }

    /// Returns the BIP174 PSBT_IN_WITNESS_SCRIPT if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    pub fn witness_script(&self) -> Result<Script, PSBTError> {
        let script_bytes = self.must_get(&InputKey::WITNESS_SCRIPT.into())?.items();
        Ok(script_bytes.into())
    }

    /// Returns a range containing any PSBT_IN_BIP32_DERIVATION.
    pub fn pubkey_kv_pairs(&self) -> btree_map::Range<PSBTKey, PSBTValue> {
        self.range_by_key_type(InputKey::BIP32_DERIVATION as u8)
    }

    /// Returns a vec containing parsed public keys. Unparsable keys will be ignored
    pub fn parsed_pubkey_derivations(&self) -> Vec<DerivedPubkey> {
        self.pubkey_kv_pairs()
            .map(|(k, v)| schema::try_kv_pair_as_derived_pubkey(k, v))
            .filter_map(Result::ok)
            .collect()
    }

    /// Returns the BIP174 PSBT_IN_FINAL_SCRIPTSIG if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    pub fn finalized_script_sig(&self) -> Result<ScriptSig, PSBTError> {
        let script_bytes = self.must_get(&InputKey::FINAL_SCRIPTSIG.into())?.items();
        Ok(script_bytes.into())
    }

    /// Returns the BIP174 PSBT_IN_FINAL_SCRIPTWITNESS if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    /// - Returns a `PSBTError::SerError` if the witness fails to deserialize properly
    pub fn finalized_script_witness(&self) -> Result<Witness, PSBTError> {
        let wit_val = self.must_get(&InputKey::FINAL_SCRIPTWITNESS.into())?;
        schema::try_val_as_witness(&wit_val)
    }

    /// Returns the BIP174 PSBT_IN_POR_COMMITMENT if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    /// - Returns a ``PSBTError::SerError`` if deserialization fails
    pub fn por_commitment(&self) -> Result<Vec<u8>, PSBTError> {
        let por_bytes = self.must_get(&InputKey::POR_COMMITMENT.into())?.items();
        Ok(por_bytes.into())
    }
}
