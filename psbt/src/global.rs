use std::collections::{btree_map, BTreeMap};

use bitcoins::types::{BitcoinTxIn, LegacyTx};
use coins_bip32::{
    derived::{DerivedKey, DerivedXPub},
    enc::XKeyEncoder as Bip32Encoder,
};
use coins_core::{
    ser::{self, ByteFormat},
    types::tx::Transaction,
};

use crate::{
    common::{PSBTKey, PSBTValue, PsbtError, PsbtValidate, PstMap},
    schema,
};

psbt_map!(PsbtGlobal);

/// PSBT Output Key Types
#[repr(u8)]
pub enum GlobalKey {
    /// Global key type for PSBT_GLOBAL_UNSIGNED_TX as defined in BIP174
    UnsignedTx = 0,
    /// Global key type for PSBT_GLOBAL_XPUB as defined in BIP174
    Xpub = 1,
    /// Global key type for PSBT_GLOBAL_PSBT_GLOBAL_VERSION as defined in BIP174
    Version = 0xfb,
    /// Global key type for PSBT_GLOBAL_PROPRIETARY as defined in BIP174
    Proprietary = 0xfc,
}

impl From<GlobalKey> for PSBTKey {
    fn from(k: GlobalKey) -> PSBTKey {
        vec![k as u8].into()
    }
}

impl PsbtValidate for PsbtGlobal {
    fn consistency_checks(&self) -> Result<(), PsbtError> {
        // A PSBT MUST have a transaction
        if !self.contains_key(&GlobalKey::UnsignedTx.into()) {
            return Err(PsbtError::InvalidPsbt); // TODO: differentiate error
        }
        // A PSBT MUST have a version
        if !self.contains_key(&GlobalKey::Version.into()) {
            return Err(PsbtError::InvalidPsbt); // TODO: differentiate error
        }
        Ok(())
    }

    fn standard_schema() -> schema::KvTypeSchema {
        // TODO: more
        let mut s: schema::KvTypeSchema = Default::default();
        s.insert(
            GlobalKey::UnsignedTx as u8,
            Box::new(|k, v| (schema::global::validate_tx(k, v))),
        );
        s.insert(
            GlobalKey::Xpub as u8,
            Box::new(|k, v| (schema::global::validate_xpub(k, v))),
        );
        s.insert(
            GlobalKey::Version as u8,
            Box::new(|k, v| (schema::global::validate_version(k, v))),
        );
        s
    }
}

impl PsbtGlobal {
    pub fn tx_bytes(&self) -> Result<&[u8], PsbtError> {
        let tx_val = self.must_get(&GlobalKey::UnsignedTx.into())?;
        Ok(tx_val.as_ref())
    }

    /// Get the global TX value as a deserialzed txn. Errors if the TX fails to deserialize or if
    /// there is no TX.
    pub fn tx(&self) -> Result<LegacyTx, PsbtError> {
        let tx_val = self.must_get(&GlobalKey::UnsignedTx.into())?;
        schema::try_val_as_tx(tx_val)
    }

    /// Set the tx key. This should only be done on instantiation.
    pub(crate) fn set_tx(&mut self, tx: &LegacyTx) {
        let tx_ins: Vec<BitcoinTxIn> = tx.inputs().iter().map(|i| i.unsigned()).collect();
        let new = LegacyTx::new(tx.version(), tx_ins, tx.outputs(), tx.locktime());

        if let Ok(tx) = new {
            let mut value = vec![];
            tx.write_to(&mut value).unwrap(); // no error on heap write
            self.insert(GlobalKey::UnsignedTx.into(), value.into());
        }
    }

    /// Get a range of XPUBs
    pub fn xpubs(&self) -> btree_map::Range<PSBTKey, PSBTValue> {
        self.range_by_key_type(GlobalKey::Xpub as u8)
    }

    /// Insert an xpub into the global map
    pub fn insert_xpub<E>(&mut self, xpub: &DerivedXPub)
    where
        E: Bip32Encoder,
    {
        let mut key = vec![GlobalKey::Xpub as u8];
        E::write_xpub(&mut key, &xpub).unwrap();

        let mut val = vec![];
        xpub.derivation().write_to(&mut val).unwrap();
        self.insert(key.into(), val.into());
    }

    /// Return a parsed vector of k/v pairs. Keys are parsed as XPubs with the provided backend.
    /// Values are parsed as `KeyDerivation` structs.
    pub fn parsed_xpubs<E>(&self) -> Result<Vec<DerivedXPub>, PsbtError>
    where
        E: Bip32Encoder,
    {
        let mut results = vec![];
        for (k, v) in self.xpubs() {
            let xpub = schema::try_key_as_xpub::<E>(k)?;
            let deriv = schema::try_val_as_key_derivation(v)?;
            results.push(DerivedXPub::new(xpub, deriv));
        }
        Ok(results)
    }

    /// Get the global PSBT version
    pub fn version(&self) -> Result<u32, PsbtError> {
        if let Some(version_val) = self.get(&GlobalKey::Version.into()) {
            let mut version_bytes = version_val.items();
            ser::read_u32_le(&mut version_bytes).map_err(Into::into)
        } else {
            Ok(0)
        }
    }

    pub fn set_version(&mut self, version: u32) {
        self.insert(
            GlobalKey::Version.into(),
            version.to_le_bytes().to_vec().into(),
        );
    }
}
