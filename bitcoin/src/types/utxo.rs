//! UTXO struct. Holds information necessary for signing future txns
use crate::types::{BitcoinOutpoint, Script, ScriptPubkey};
use crate::{hashes, types};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
/// Information necessary to spend an output.
pub struct UTXO {
    /// UTXO outpoint
    pub outpoint: BitcoinOutpoint,
    /// UTXO value
    pub value: u64,
    /// The prevout script pubkey
    pub script_pubkey: ScriptPubkey,
    /// The prevout redeem script or witness script hashed into the script pubkey (if any)
    pub spend_script: Option<Script>,
}

impl UTXO {
    /// Produce a UTXO from a transaction output
    pub fn from_tx_output<'a, T>(tx: &'a T, idx: usize) -> UTXO
    where
        T: riemann_core::types::tx::Transaction<
            'a,
            Digest = bitcoin_spv::types::Hash256Digest,
            TXID = hashes::TXID,
            TxOut = types::TxOut,
            TxIn = types::BitcoinTxIn,
            HashWriter = riemann_core::hashes::Hash256Writer,
        >,
    {
        let output = &tx.outputs()[idx];
        UTXO {
            outpoint: BitcoinOutpoint::new(tx.txid(), idx as u32),
            value: output.value,
            script_pubkey: output.script_pubkey.clone(),
            spend_script: None,
        }
    }

    /// Return a clone of the script pubkey
    pub fn script_pubkey(&self) -> ScriptPubkey {
        self.script_pubkey.clone()
    }

    /// Return a clone of the spend script
    pub fn spend_script(&self) -> Option<Script> {
        self.spend_script.as_ref().cloned()
    }
}
