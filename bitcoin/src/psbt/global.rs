
use std::{
    collections::{
        BTreeMap,
        btree_map,
    },
};

use riemann_core::{
    primitives::{PrefixVec},
    ser::{Ser},
};

use crate::{
    psbt::{
        common::{PSBTError, PSBTMap, PSBTKey, PSBTValidate, PSBTValue},
        schema,
    },
    types::transactions::{LegacyTx},
};

psbt_map!(PSBTGlobal);

/// PSBT Output Key Types
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum GlobalKey {
    /// Global key type for PSBT_GLOBAL_UNSIGNED_TX as defined in BIP174
    UNSIGNED_TX = 0,
    /// Global key type for PSBT_GLOBAL_XPUB as defined in BIP174
    XPUB = 1,
    /// Global key type for PSBT_GLOBAL_PSBT_GLOBAL_VERSION as defined in BIP174
    VERSION = 0xfb,
    /// Global key type for PSBT_GLOBAL_PROPRIETARY as defined in BIP174
    PROPRIETARY = 0xfc,
}

impl From<GlobalKey> for PSBTKey {
    fn from(k: GlobalKey) -> PSBTKey {
        vec![k as u8].into()
    }
}

impl PSBTValidate for PSBTGlobal {
    fn consistency_checks(&self) -> Result<(), PSBTError> {
        // A PSBT MUST have a transaction
        if !self.contains_key(&GlobalKey::UNSIGNED_TX.into()) {
            return Err(PSBTError::InvalidPSBT)
        }
        // A PSBT MUST have a version
        if !self.contains_key(&GlobalKey::VERSION.into()) {
            return Err(PSBTError::InvalidPSBT)
        }
        Ok(())
    }

    fn standard_schema() -> schema::KVTypeSchema {
        // TODO: more
        let mut s: schema::KVTypeSchema = Default::default();
        s.insert(GlobalKey::UNSIGNED_TX as u8, Box::new(|k, v| (schema::global::validate_tx(k, v))));
        s.insert(GlobalKey::XPUB as u8, Box::new(|k, v| (schema::global::validate_xpub(k, v))));
        s.insert(GlobalKey::VERSION as u8, Box::new(|k, v| (schema::global::validate_version(k, v))));
        s
    }
}

impl PSBTGlobal {
    /// Get the global TX value as a deserialzed txn. Errors if the TX fails to deserialize or if
    /// there is no TX.
    pub fn tx(&self) -> Result<LegacyTx, PSBTError> {
        let tx_val = self.must_get(&GlobalKey::UNSIGNED_TX.into())?;
        schema::try_val_as_tx(tx_val)
    }

    /// Get a range of XPUBs
    pub fn xpubs(&self) -> btree_map::Range<PSBTKey, PSBTValue> {
        self.range_by_key_type(GlobalKey::XPUB as u8)
    }

    /// Get the global PSBT version
    pub fn version(&self) -> Result<u32, PSBTError> {
        let version_key: PSBTKey = GlobalKey::VERSION.into();
        let mut version_bytes = self.must_get(&version_key)?.items();
        Self::read_u32_le(&mut version_bytes)
    }
}
