
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
    types::transactions::{LegacyTx},
};

psbt_map!(PSBTGlobal);

/// Validate a `PSBT_GLOBAL_UNSIGNED_TX` key-value pair in a global map
pub fn validate_tx(t: (&PSBTKey, &PSBTValue)) -> Result<(), PSBTError> {
    let (key, val) = t;
    if !(key.len() == 1 && key[0] == 0) {
        return Err(PSBTError::InvalidKeyFormat(key.clone()))
    }
    let mut tx_bytes = val.items();
    Ok(LegacyTx::deserialize(&mut tx_bytes, 0).map(|_| ())?)
}

impl PSBTGlobal {
    /// Return a vector of the standard validation Schemas
    pub fn standard_schema<'a>() -> Vec<&'a KVTypeSchema<'a>> {
        // TODO: more
        let mut schema: Vec<&'a KVTypeSchema<'a>> = vec![];
        schema.push(&(0, &move |v| (validate_tx(v))));
        schema
    }

    /// Run standard validation on the map
    pub fn validate_standard(&self) -> Result<(), PSBTError> {
        self.validate(&Self::standard_schema())
    }

    /// Get the global TX value as a deserialzed txn. Errors if the TX fails to deserialize or if
    /// there is no TX.
    pub fn tx(&self) -> Result<LegacyTx, PSBTError> {
        let tx_key: PSBTKey = vec![0].into();
        let mut tx_bytes = self.must_get(&tx_key)?.items();
        Ok(LegacyTx::deserialize(&mut tx_bytes, 0)?)
    }

    /// Get a range of XPUBs
    pub fn xpubs(&self) -> Range<PSBTKey, PSBTValue> {
        self.range_by_key_type(1)
    }

    /// Get the global PSBT version
    pub fn version(&self) -> Result<u32, PSBTError> {
        let version_key: PSBTKey = vec![0xFB].into();
        let mut version_bytes = self.must_get(&version_key)?.items();
        Self::read_u32_le(&mut version_bytes)
    }
}
