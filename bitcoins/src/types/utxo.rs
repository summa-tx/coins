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
use crate::types::{
    BitcoinOutpoint, BitcoinTransaction, LegacySighashArgs, Script, ScriptPubkey, ScriptType,
    Sighash, TxOut, WitnessSighashArgs,
};
use coins_core::hashes::{Digest, Hash160, MarkedDigest, MarkedDigestOutput, Sha256};
use serde::{Deserialize, Serialize};

/// This type specifies whether a script is known to be none, or whether it is unknown.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Hash)]
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
            ScriptType::Sh(_) | ScriptType::Wsh(_) => SpendScript::Missing,
            _ => SpendScript::None,
        }
    }
}

/// Information necessary to spend an output.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Utxo {
    /// UTXO outpoint
    pub outpoint: BitcoinOutpoint,
    /// UTXO value
    pub value: u64,
    /// The prevout script pubkey
    pub script_pubkey: ScriptPubkey,
    /// The prevout redeem script or witness script hashed into the script pubkey (if any)
    spend_script: SpendScript,
}

impl Utxo {
    /// Instantiate a new UTXO with the given arguments. If spend_script is provided, but the
    /// script_pubkey does not require a spend script, the spend_script will be discarded.
    pub fn new(
        outpoint: BitcoinOutpoint,
        value: u64,
        script_pubkey: ScriptPubkey,
        spend_script: SpendScript,
    ) -> Utxo {
        // Forbid nonsensical states, e.g. a p2pkh address with a spend_script
        let spend_script = match SpendScript::from_script_pubkey(&script_pubkey) {
            SpendScript::None => SpendScript::None,
            SpendScript::Missing => spend_script,
            SpendScript::Known(_) => panic!("unreachable"),
        };
        Utxo {
            outpoint,
            value,
            script_pubkey,
            spend_script,
        }
    }

    /// Produce a UTXO from a transaction output
    pub fn from_tx_output<T>(tx: &T, idx: usize) -> Utxo
    where
        T: BitcoinTransaction,
    {
        let output = &tx.outputs()[idx];
        Utxo {
            outpoint: BitcoinOutpoint::new(tx.txid(), idx as u32),
            value: output.value,
            script_pubkey: output.script_pubkey.clone(),
            spend_script: SpendScript::from_script_pubkey(&output.script_pubkey),
        }
    }

    /// Produce a UTXO from an output and the outpoint that identifies it
    pub fn from_output_and_outpoint(output: &TxOut, outpoint: &BitcoinOutpoint) -> Utxo {
        Utxo {
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
                    ScriptType::Pkh(_) => Some(spk.into()),
                    // TODO: break this out into a function
                    ScriptType::Wpkh(payload) => {
                        let mut v = vec![0x76, 0xa9, 0x14];
                        v.extend(payload.as_slice());
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
            ScriptType::Sh(data) => {
                if data == Hash160::digest_marked(script.as_ref()) {
                    self.spend_script = SpendScript::Known(script);
                    return true;
                }
            }
            ScriptType::Wsh(data) => {
                if data.as_slice() == Sha256::digest(script.as_ref()).as_slice() {
                    self.spend_script = SpendScript::Known(script);
                    return true;
                }
            }
            _ => return false,
        }
        false
    }

    /// Construct `LegacySighashArgs` from this UTXO. Returns `None` if the prevout is WSH or SH
    /// and the witness or redeem script is `Missing`.
    /// It is safe to unwrap this Option if the signing script is PKH, or WPKH, or if the
    /// underlying witness or redeem script is `Known`.
    pub fn sighash_args(&self, index: usize, flag: Sighash) -> Option<LegacySighashArgs> {
        if let Some(prevout_script) = self.signing_script() {
            Some(LegacySighashArgs {
                index,
                sighash_flag: flag,
                prevout_script,
            })
        } else {
            None
        }
    }

    /// Construct `WitnessSighashArgs` from this UTXO. Returns `None` if the prevout is WSH or SH
    /// and the witness or redeem script is `Missing`.
    /// It is safe to unwrap this Option if the signing script is PKH, or WPKH, or if the
    /// underlying witness or redeem script is `Known`.
    pub fn witness_sighash_args(&self, index: usize, flag: Sighash) -> Option<WitnessSighashArgs> {
        if let Some(prevout_script) = self.signing_script() {
            Some(WitnessSighashArgs {
                index,
                sighash_flag: flag,
                prevout_script,
                prevout_value: self.value,
            })
        } else {
            None
        }
    }
}
