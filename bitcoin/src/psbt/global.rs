
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
    psbt::{
        common::{PSBTError, PSBTKey, PSBTValue},
        schema,
    },
    types::transactions::{LegacyTx},
};

psbt_map!(PSBTGlobal);


impl PSBTGlobal {
    /// Return a vector of the standard validation Schemas for a PSBTGlobal map. This enforces KV
    /// descriptions found in BIP174. Further KV pairs can be validated using the `validate`
    /// function
    pub fn standard_schema<'a>() -> Vec<&'a schema::KVTypeSchema<'a>> {
        // TODO: more
        let mut schema: Vec<&'a schema::KVTypeSchema<'a>> = vec![];
        schema.push(&(0, &move |k, v| (schema::validate_tx(k, v))));
        schema.push(&(1, &move |k, v| (schema::validate_xpub(k, v))));
        schema.push(&(0xfb, &move |k, v| (schema::validate_version(k, v))));
        schema
    }

    /// Run standard validation on the map
    pub fn validate(&self) -> Result<(), PSBTError> {
        self.validate_schema(&Self::standard_schema())
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
