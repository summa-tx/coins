//! UTXO struct. Holds information necessary for signing future txns.
//!
//! The UTXO struct holds the outpoint, value, and script pubkey of a previous output. It may also
//! hold the underlying witness script or redeem script if any. It aims to provide all necessary
//! info for future UTXO signers.
//!
//! # Note:
//!
//! This functionality does NOT currently support nested witness-via-p2sh prevouts. If you' like
//! to use those, you'll need a processing step in your tx signer.
use crate::types::{BitcoinOutpoint, BitcoinTransaction, Script, ScriptPubkey, ScriptType, TxOut};
use serde::{Deserialize, Serialize};

/// This type specifies whether a script is known to be none, or whether it is unknown.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum SpendScript {
    /// ScriptPubkey is known to have no spend script
    None,
    /// ScriptPubkey has a spend script, but it is unknown
    Missing,
    /// ScriptPubkey has a spend script, and we know what it is
    Known(Script),
}

impl SpendScript {
    /// Determine the spend script type from the script pubkey. This will always return `Missing`
    /// or `None`.
    pub fn from_script_pubkey(script: &ScriptPubkey) -> SpendScript {
        match script.standard_type() {
            ScriptType::SH(_) | ScriptType::WSH(_) => SpendScript::Missing,
            _ => SpendScript::None,
        }
    }
}

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
    spend_script: SpendScript,
}

impl UTXO {
    /// Instantiate a new UTXO with the given arguments
    pub fn new(
        outpoint: BitcoinOutpoint,
        value: u64,
        script_pubkey: ScriptPubkey,
        spend_script: SpendScript,
    ) -> UTXO {
        UTXO {
            outpoint,
            value,
            script_pubkey,
            spend_script,
        }
    }

    /// Produce a UTXO from a transaction output
    pub fn from_tx_output<T>(tx: &T, idx: usize) -> UTXO
    where
        T: BitcoinTransaction,
    {
        let output = &tx.outputs()[idx];
        UTXO {
            outpoint: BitcoinOutpoint::new(tx.txid(), idx as u32),
            value: output.value,
            script_pubkey: output.script_pubkey.clone(),
            spend_script: SpendScript::from_script_pubkey(&output.script_pubkey),
        }
    }

    /// Produce a UTXO from an output and the outpoint that identifies it
    pub fn from_output_and_outpoint(output: &TxOut, outpoint: &BitcoinOutpoint) -> UTXO {
        UTXO {
            outpoint: *outpoint,
            value: output.value,
            script_pubkey: output.script_pubkey.clone(),
            spend_script: SpendScript::from_script_pubkey(&output.script_pubkey),
        }
    }

    /// Return a reference to the script pubkey
    pub fn script_pubkey(&self) -> &ScriptPubkey {
        &self.script_pubkey
    }

    /// Return a reference to the spend script
    pub fn spend_script(&self) -> &SpendScript {
        &self.spend_script
    }

    /// Return the script that ought to be signed. This is the spend_script (redeem/witness
    /// script) if present, the script pubkey if legacy PKH, and the legacy PKH script if WPKH. .
    pub fn signing_script(&self) -> Option<Script> {
        match self.spend_script() {
            SpendScript::None => {
                let spk = self.script_pubkey();
                match spk.standard_type() {
                    ScriptType::PKH(_) => Some(spk.into()),
                    // TODO: break this out into a function
                    ScriptType::WPKH(payload) => {
                        let mut v = vec![0x76, 0xa9, 0x14];
                        v.extend(&payload);
                        v.extend(&[0x88, 0xac]);
                        Some(v.into())
                    }
                    _ => None, // Should be unreachable
                }
            }
            SpendScript::Known(script) => Some(script.clone()),
            SpendScript::Missing => None,
        }
    }

    /// Inspect the `Script` to determine its type.
    pub fn standard_type(&self) -> ScriptType {
        self.script_pubkey.standard_type()
    }

    /// Attempts to set the script. Returns true if succesful, false otherwise. Before setting, we
    /// check that the provided script's hash matches the payload of the script pubkey. As such,
    /// this will always fail for UTXOs with PKH or WPKH script pubkeys.
    pub fn set_spend_script(&mut self, script: Script) -> bool {
        match self.standard_type() {
            ScriptType::SH(data) => {
                if data == bitcoin_spv::btcspv::hash160(script.as_ref()) {
                    self.spend_script = SpendScript::Known(script);
                    return true;
                }
            }
            ScriptType::WSH(data) => {
                if data.as_ref() == <sha2::Sha256 as sha2::Digest>::digest(script.as_ref()).as_ref()
                {
                    self.spend_script = SpendScript::Known(script);
                    return true;
                }
            }
            _ => return false,
        }
        false
    }
}
