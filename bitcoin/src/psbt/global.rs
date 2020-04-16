
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
    types::transactions::{LegacyTx},
};

psbt_map!(PSBTGlobal);

impl PSBTGlobal {
    /// Get the global TX value as a deserialzed txn. Errors if the TX fails to deserialize or if
    /// there is no TX.
    pub fn tx(&self) -> Result<LegacyTx, PSBTError> {
        let tx_key: PSBTKey = vec![0u8].into();
        let mut tx_bytes = self.get(&tx_key).ok_or(PSBTError::InvalidPSBT)?.items();
        Ok(LegacyTx::deserialize(&mut tx_bytes, 0)?)
    }

    /// Get the global PSBT version
    pub fn version(&self) -> Result<u32, PSBTError> {
        let version_key: PSBTKey = vec![0xFB].into();
        let mut version_bytes = self.get(&version_key).ok_or(PSBTError::InvalidPSBT)?.items();
        Self::read_u32_le(&mut version_bytes)
    }

    /// Get a range of XPUBs
    pub fn xpubs(&self) -> Range<PSBTKey, PSBTValue> {
        self.range_by_key_type(0x01)
    }
}
