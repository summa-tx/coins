use std::{
    collections::{
        BTreeMap,
        btree_map::{Iter, IterMut, Range},
    },
    io::{Read, Write},
};

use riemann_core::{
    primitives::{PrefixVec},
    ser::{Ser},
};


use crate::{
    psbt::common::{PSBTError, PSBTKey, PSBTValue},
    types::{
        script::{Script, ScriptSig, Witness},
        txout::{TxOut},
        transactions::{LegacyTx, Sighash, sighash_from_u8, TxError},
    },
};

psbt_map!(PSBTInput);

impl PSBTInput {
    /// Returns the BIP174 PSBT_IN_NON_WITNESS_UTXO transaction if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    /// - Returns a PSBTError::InvalidTx error if the value at that key is not a valid TX.
    pub fn non_witness_utxo(&self) -> Result<LegacyTx, PSBTError> {
        let tx_key: PSBTKey = vec![0u8].into();
        let mut tx_bytes = self.get(&tx_key).ok_or(PSBTError::MissingKey)?.items();
        Ok(LegacyTx::deserialize(&mut tx_bytes, 0)?)
    }

    /// Returns the BIP174 PSBT_IN_WITNESS_UTXO TxOut if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    /// - Returns a PSBTError::SerError if the value at that key is not a valid tx out.
    pub fn witness_utxo(&self) -> Result<TxOut, PSBTError> {
        let out_key: PSBTKey = vec![1u8].into();
        let mut out_bytes = self.get(&out_key).ok_or(PSBTError::MissingKey)?.items();
        Ok(TxOut::deserialize(&mut out_bytes, 0)?)
    }

    /// Returns a range containing any PSBT_IN_PARTIAL_SIG
    pub fn partial_sigs(&self) -> Range<PSBTKey, PSBTValue> {
        self.range_by_key_type(0x02)
    }

    /// Returns the BIP174 PSBT_IN_SIGHASH_TYPE if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    /// - Returns a PSBTError::TxError(TxError::UnknownSighash) if the sighash is abnormal
    pub fn sighash(&self) -> Result<Sighash, PSBTError> {
        let sighash_key: PSBTKey = vec![3u8].into();
        let mut sighash_bytes = self.get(&sighash_key).ok_or(PSBTError::MissingKey)?.items();
        let sighash = Self::read_u32_le(&mut sighash_bytes)?;
        if sighash > 0xff {
            return Err(TxError::UnknownSighash(0xff).into())
        }
        sighash_from_u8(sighash as u8).map_err(|e| e.into())
    }

    /// Returns the BIP174 PSBT_IN_REDEEM_SCRIPT if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    pub fn redeem_script(&self) -> Result<Script, PSBTError> {
        let script_key: PSBTKey = vec![4u8].into();
        let script_bytes = self.get(&script_key).ok_or(PSBTError::MissingKey)?.items();
        Ok(script_bytes.into())
    }

    /// Returns the BIP174 PSBT_IN_WITNESS_SCRIPT if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    pub fn witness_script(&self) -> Result<Script, PSBTError> {
        let script_key: PSBTKey = vec![5u8].into();
        let script_bytes = self.get(&script_key).ok_or(PSBTError::MissingKey)?.items();
        Ok(script_bytes.into())
    }

    /// Returns a range containing any PSBT_IN_BIP32_DERIVATION.
    pub fn bip_32_derivations(&self) -> Range<PSBTKey, PSBTValue> {
        self.range_by_key_type(0x06)
    }

    /// Returns the BIP174 PSBT_IN_FINAL_SCRIPTSIG if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    pub fn finalized_script_sig(&self) -> Result<ScriptSig, PSBTError> {
        let script_key: PSBTKey = vec![7u8].into();
        let script_bytes = self.get(&script_key).ok_or(PSBTError::MissingKey)?.items();
        Ok(script_bytes.into())
    }

    /// Returns the BIP174 PSBT_IN_FINAL_SCRIPTWITNESS if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    /// - Returns a PSBTError
    pub fn finalized_script_witness(&self) -> Result<Witness, PSBTError> {
        let wit_key: PSBTKey = vec![7u8].into();
        let mut wit_bytes = self.get(&wit_key).ok_or(PSBTError::MissingKey)?.items();
        Ok(Witness::deserialize(&mut wit_bytes, 0)?)
    }

    /// Returns the BIP174 PSBT_IN_POR_COMMITMENT if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    /// - Returns a `PSBTError::SerError` if deserialization fails
    pub fn por_commitment(&self) -> Result<Vec<u8>, PSBTError> {
        let por_key: PSBTKey = vec![7u8].into();
        let por_bytes = self.get(&por_key).ok_or(PSBTError::MissingKey)?.items();
        Ok(por_bytes.into())
    }
}
