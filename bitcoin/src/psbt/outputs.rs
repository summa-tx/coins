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
    psbt::common::{PSBTError, PSBTKey, PSBTValue, KVTypeSchema},
    types::script::{Script},
};

psbt_map!(PSBTOutput);

impl PSBTOutput {
    /// Return a vector of the standard validation Schemas
    pub fn standard_schema<'a>() -> Vec<&'a KVTypeSchema<'a>> {
        // TODO: more
        let mut schema: Vec<&'a KVTypeSchema<'a>> = vec![];
        schema
    }

    /// Run standard validation on the map
    pub fn validate_standard(&self) -> Result<(), PSBTError> {
        self.validate(&Self::standard_schema())
    }

    /// Returns the BIP174 PSBT_OUT_REDEEM_SCRIPT transaction if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    /// - Returns a PSBTError::InvalidTx error if the value at that key is not a valid TX.
    pub fn out_redeem_script(&self) -> Result<Script, PSBTError> {
        let script_key: PSBTKey = vec![0].into();
        let script_bytes = self.must_get(&script_key)?.items();
        Ok(script_bytes.into())
    }

    /// Returns the BIP174 PSBT_OUT_WITNESS_SCRIPT transaction if present and valid.
    ///
    /// ## Errors
    ///
    /// - Returns a `PSBTError::MissingKey` error if no value at that key.
    /// - Returns a PSBTError::InvalidTx error if the value at that key is not a valid TX.
    pub fn out_witness_script(&self) -> Result<Script, PSBTError> {
        let script_key: PSBTKey = vec![1].into();
        let script_bytes = self.must_get(&script_key)?.items();
        Ok(script_bytes.into())
    }


    /// Returns a range containing any PSBT_OUT_BIP32_DERIVATION.
    pub fn bip_32_derivations(&self) -> Range<PSBTKey, PSBTValue> {
        self.range_by_key_type(2)
    }
}
