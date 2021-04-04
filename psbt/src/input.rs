use coins_bip32::derived::DerivedPubkey;
use coins_core::ser::{self, ByteFormat};
use std::collections::{btree_map, BTreeMap};

use bitcoins::types::{LegacyTx, Script, ScriptSig, Sighash, TxOut, Witness, Utxo};

use crate::{
    common::{PSBTKey, PSBTValue, PsbtError, PsbtValidate, PstMap},
    schema,
};

psbt_map!(PsbtInput);

/// PSBT Input Key Types
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum InputKey {
    /// Input key type for PSBT_IN_NON_WITNESS_UTXO as defined in BIP174
    NonWitnessUtxo = 0,
    /// Input key type for PSBT_IN_WITNESS_UTXO as defined in BIP174
    WitnessUtxo = 1,
    /// Input key type for PSBT_IN_PARTIAL_SIG as defined in BIP174
    PartialSig = 2,
    /// Input key type for PSBT_IN_SIGHASH_TYPE as defined in BIP174
    SighashType = 3,
    /// Input key type for PSBT_IN_REDEEM_SCRIPT as defined in BIP174
    RedeemScript = 4,
    /// Input key type for PSBT_IN_WITNESS_SCRIPT as defined in BIP174
    WitnessScript = 5,
    /// Input key type for PSBT_IN_BIP32_DERIVATION as defined in BIP174
    Bip32Derivation = 6,
    /// Input key type for PSBT_IN_FINAL_SCRIPTSIG as defined in BIP174
    FinalScriptSig = 7,
    /// Input key type for PSBT_IN_FINAL_SCRIPTWITNESS as defined in BIP174
    FinalScriptWitness = 8,
    /// Input key type for PSBT_IN_POR_COMMITMENT as defined in BIP174
    PorCommitment = 9,
    /// Input key type for PSBT_IN_PROPRIETARY as defined in BIP174
    Proprietary = 0xfc,
}

impl From<InputKey> for PSBTKey {
    fn from(k: InputKey) -> PSBTKey {
        vec![k as u8].into()
    }
}

impl PsbtValidate for PsbtInput {
    fn consistency_checks(&self) -> Result<(), PsbtError> {
        // Can't contain both witness and non-witness input info
        if self.has_witness_utxo() && self.has_non_witness_utxo() {
            return Err(PsbtError::InvalidPsbt); // TODO: differentiate error
        }

        // TODO
        // - validate that all signatures use the sighash type
        // - validate UTXO <> redeem_script <> witness_script consistency for this input

        Ok(())
    }

    fn standard_schema() -> schema::KvTypeSchema {
        let mut s: schema::KvTypeSchema = Default::default();
        s.insert(
            InputKey::NonWitnessUtxo as u8,
            Box::new(|k, v| (schema::input::validate_in_non_witness(k, v))),
        );
        s.insert(
            InputKey::WitnessUtxo as u8,
            Box::new(|k, v| (schema::input::validate_in_witness(k, v))),
        );
        s.insert(
            InputKey::PartialSig as u8,
            Box::new(|k, v| (schema::input::validate_in_partial_sig(k, v))),
        );
        s.insert(
            InputKey::SighashType as u8,
            Box::new(|k, v| (schema::input::validate_sighash_type(k, v))),
        );
        s.insert(
            InputKey::RedeemScript as u8,
            Box::new(|k, v| (schema::input::validate_redeem_script(k, v))),
        );
        s.insert(
            InputKey::WitnessScript as u8,
            Box::new(|k, v| (schema::input::validate_witness_script(k, v))),
        );
        s.insert(
            InputKey::Bip32Derivation as u8,
            Box::new(|k, v| (schema::input::validate_bip32_derivations(k, v))),
        );
        s.insert(
            InputKey::FinalScriptSig as u8,
            Box::new(|k, v| (schema::input::validate_finalized_script_sig(k, v))),
        );
        s.insert(
            InputKey::FinalScriptWitness as u8,
            Box::new(|k, v| (schema::input::validate_finalized_script_witness(k, v))),
        );
        s.insert(
            InputKey::PorCommitment as u8,
            Box::new(|k, v| (schema::input::validate_por_commitment(k, v))),
        );
        s
    }
}

impl PsbtInput {
    /// Returns true if the map has a non-witness utxo in it.
    pub fn has_non_witness_utxo(&self) -> bool {
        self.contains_key(&InputKey::NonWitnessUtxo.into())
    }

    /// Returns the BIP174 PSBT_IN_NON_WITNESS_UTXO transaction if present and valid.
    ///'
    /// ## Errors
    ///
    /// - Returns a `PsbtError::MissingKey` error if no value at that key.
    /// - Returns a `PsbtError::InvalidTx` error if the value at that key is not a valid TX.
    pub fn non_witness_utxo(&self) -> Result<LegacyTx, PsbtError> {
        let tx_val = self.must_get(&InputKey::NonWitnessUtxo.into())?;
        schema::try_val_as_tx(tx_val)
    }

    /// Add a non-witness UTXO to the mapping. This function does not run consistency checks
    pub fn insert_non_witness_utxo(&mut self, tx: &LegacyTx) {
        let mut val = vec![];
        tx.write_to(&mut val).unwrap();

        self.insert(InputKey::NonWitnessUtxo.into(), val.into());
    }

    /// Returns true if the map has a non-witness utxo in it.
    pub fn has_witness_utxo(&self) -> bool {
        self.contains_key(&InputKey::WitnessUtxo.into())
    }

    /// Returns the BIP174 PSBT_IN_WITNESS_UTXO TxOut if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PsbtError::MissingKey` error if no value at that key.
    /// - Returns a `PsbtError::SerError` if the value at that key is not a valid tx out.
    pub fn witness_utxo(&self) -> Result<TxOut, PsbtError> {
        let out_val = self.must_get(&InputKey::WitnessUtxo.into())?;
        schema::try_val_as_tx_out(out_val)
    }

    /// Add a witness UTXO to the mapping. This function does not run consistency checks
    pub fn insert_witness_utxo(&mut self, tx_out: &TxOut) {
        let mut val = vec![];
        tx_out.write_to(&mut val).unwrap();

        self.insert(InputKey::WitnessUtxo.into(), val.into());
    }

    /// True if the PSBT knows its utxo, false otherwise
    pub fn has_utxo(&self) -> bool {
        self.has_non_witness_utxo()
    }

    /// Get the prevout details and return a UTXO object
    pub fn as_utxo(&self, outpoint: &bitcoins::types::BitcoinOutpoint) -> Result<Utxo, PsbtError> {
        if let Ok(tx_out) = self.witness_utxo() {
            // Witness UTXO.
            let mut utxo = Utxo::from_output_and_outpoint(&tx_out, outpoint);
            if let Ok(script) = self.witness_script() {
                utxo.set_spend_script(script);
            }
            Ok(utxo)
        } else if let Ok(prevout_tx) = self.non_witness_utxo() {
            // Non-witness. Need to extract the appropriate output
            let mut utxo = Utxo::from_tx_output(&prevout_tx, outpoint.idx as usize);
            if let Ok(script) = self.redeem_script() {
                utxo.set_spend_script(script);
            }
            Ok(utxo)
        } else {
            // Missing both UTXO keys
            Err(PsbtError::MissingKey(InputKey::NonWitnessUtxo as u8))
        }
    }

    /// Returns a range containing any PSBT_IN_PARTIAL_SIG
    pub fn raw_partial_sigs(&self) -> btree_map::Range<PSBTKey, PSBTValue> {
        self.range_by_key_type(InputKey::PartialSig as u8)
    }

    /// Returns an iterator over Pubkey/Signature pairs
    pub fn partial_sigs(
        &self,
    ) -> Vec<(
        coins_bip32::ecdsa::VerifyingKey,
        coins_bip32::ecdsa::Signature,
        Sighash,
    )> {
        self.raw_partial_sigs()
            .filter_map(|(k, v)| schema::try_kv_pair_as_pubkey_and_sig(k, v).ok())
            .collect::<Vec<_>>()
    }

    /// Inserts a signature into the map
    pub fn insert_partial_sig<K>(&mut self, pk: &K, sig: &coins_bip32::ecdsa::Signature)
    where
        K: AsRef<coins_bip32::ecdsa::VerifyingKey>,
    {
        let mut key = vec![InputKey::PartialSig as u8];
        key.extend(&pk.as_ref().to_bytes());

        let mut val = vec![];
        val.extend(sig.to_asn1().as_bytes());
        val.push(self.sighash_or_default() as u8);

        self.insert(key.into(), val.into());
    }

    /// Returns the BIP174 PSBT_IN_SIGHASH_TYPE if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PsbtError::MissingKey` error if no value at that key.
    /// - Returns a `PsbtError::TxError(TxError::UnknownSighash)` if the sighash is abnormal
    pub fn sighash(&self) -> Result<Sighash, PsbtError> {
        let val = self.must_get(&InputKey::SighashType.into())?;
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
    /// - Returns a `PsbtError::MissingKey` error if no value at that key.
    pub fn redeem_script(&self) -> Result<Script, PsbtError> {
        let script_bytes = self.must_get(&InputKey::RedeemScript.into())?.items();
        Ok(script_bytes.into())
    }

    /// True if the map has a redeem script, else false.
    pub fn has_redeem_script(&self) -> bool {
        self.contains_key(&InputKey::RedeemScript.into())
    }

    /// Returns the BIP174 PSBT_IN_WITNESS_SCRIPT if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PsbtError::MissingKey` error if no value at that key.
    pub fn witness_script(&self) -> Result<Script, PsbtError> {
        let script_bytes = self.must_get(&InputKey::WitnessScript.into())?.items();
        Ok(script_bytes.into())
    }

    /// True if the map has a witness script, else false.
    pub fn has_witness_script(&self) -> bool {
        self.contains_key(&InputKey::WitnessScript.into())
    }

    /// Returns a range containing any PSBT_IN_BIP32_DERIVATION.
    pub fn pubkey_kv_pairs(&self) -> btree_map::Range<PSBTKey, PSBTValue> {
        self.range_by_key_type(InputKey::Bip32Derivation as u8)
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
    /// - Returns a `PsbtError::MissingKey` error if no value at that key.
    pub fn finalized_script_sig(&self) -> Result<ScriptSig, PsbtError> {
        let script_bytes = self.must_get(&InputKey::FinalScriptSig.into())?.items();
        Ok(script_bytes.into())
    }

    /// Insert a finalized script sig into the input map
    pub fn insert_script_sig(&mut self, script_sig: &ScriptSig) {
        self.insert(InputKey::FinalScriptSig.into(), script_sig.items().into());
    }

    /// Returns the BIP174 PSBT_IN_FINAL_SCRIPTWITNESS if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PsbtError::MissingKey` error if no value at that key.
    /// - Returns a `PsbtError::SerError` if the witness fails to deserialize properly
    pub fn finalized_script_witness(&self) -> Result<Witness, PsbtError> {
        let wit_val = self.must_get(&InputKey::FinalScriptWitness.into())?;
        schema::try_val_as_witness(&wit_val)
    }

    /// Insert a finalized witness into the input map
    pub fn insert_witness(&mut self, witness: Witness) {
        let mut value = vec![];
        ser::write_compact_int(&mut value, witness.len() as u64).unwrap();
        witness.iter().for_each(|w| {
            w.write_to(&mut value).unwrap();
        });
        self.insert(InputKey::FinalScriptWitness.into(), value.into());
    }

    /// True if the input contains a finalized script sig, or a finalized script witness. False otherwise
    pub fn is_finalized(&self) -> bool {
        self.contains_key(&InputKey::FinalScriptWitness.into())
            || self.contains_key(&InputKey::FinalScriptSig.into())
    }

    /// Returns the BIP174 PSBT_IN_POR_COMMITMENT if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PsbtError::MissingKey` error if no value at that key.
    /// - Returns a ``PsbtError::SerError`` if deserialization fails
    pub fn por_commitment(&self) -> Result<Vec<u8>, PsbtError> {
        let por_bytes = self.must_get(&InputKey::PorCommitment.into())?.items();
        Ok(por_bytes.to_vec())
    }
}
