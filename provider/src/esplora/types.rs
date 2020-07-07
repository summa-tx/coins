use riemann_core::prelude::*;
use rmn_btc::prelude::*;

use crate::esplora::*;

#[derive(serde::Deserialize, Clone, Debug)]
pub(crate) struct BlockStatus {
    pub in_best_chain: bool,
    #[serde(default = "Hash256Digest::default")]
    pub next_best: Hash256Digest,
}

#[derive(serde::Deserialize, Clone, Debug)]
pub(crate) struct TxStatus {
    pub confirmed: bool,
    #[serde(default = "usize::min_value")]
    pub block_height: usize,
    #[serde(default = "Hash256Digest::default")]
    pub block_hash: Hash256Digest,
}

impl TxStatus {
    pub(crate) async fn fetch_by_txid(api_root: &str, txid: TXID) -> Result<Self, FetchError> {
        let url = format!(
            "{}/tx/{}/status",
            api_root,
            txid.reversed().serialize_hex().unwrap()
        );
        Ok(utils::ez_fetch_json(&url).await?)
    }
}

#[derive(serde::Deserialize, Clone, Debug)]
pub(crate) struct EsploraUTXO {
    /// TXID in BE format
    pub txid: String,
    /// Index in vout
    pub vout: usize,
    /// UTXO value
    pub value: usize,
}

impl EsploraUTXO {
    pub(crate) async fn fetch_by_address(
        api_root: &str,
        addr: &Address,
    ) -> Result<Vec<EsploraUTXO>, FetchError> {
        let url = format!("{}/address/{}/utxo", api_root, addr.as_string());
        Ok(utils::ez_fetch_json(&url).await?)
    }

    pub(crate) fn into_utxo(self, addr: &Address) -> Result<UTXO, EsploraError> {
        let script_pubkey = rmn_btc::Network::decode_address(addr)?;
        let outpoint = BitcoinOutpoint::from_explorer_format(
            TXID::deserialize_hex(&self.txid)?,
            self.vout as u32,
        );
        let spend_script = SpendScript::from_script_pubkey(&script_pubkey);
        Ok(UTXO::new(
            outpoint,
            self.value as u64,
            script_pubkey,
            spend_script,
        ))
    }
}

#[derive(serde::Deserialize, Clone, Debug)]
pub(crate) struct Outspend {
    /// Whether the output has been spent
    pub spent: bool,
    /// The TXID that spend it
    #[serde(default = "String::new")]
    pub txid_be: String,
    /// The index of the spending input in that transaction's Vin
    #[serde(default = "usize::max_value")]
    pub vin: usize,
    /// The status of the spending TX
    pub status: TxStatus,
}

impl Outspend {
    /// Fetch an Outspend by an outpoint referencing it
    pub(crate) async fn fetch_by_outpoint(
        api_root: &str,
        outpoint: &BitcoinOutpoint,
    ) -> Result<Option<Outspend>, FetchError> {
        let txid_be = outpoint.txid_be_hex();
        let idx = outpoint.idx;
        Outspend::fetch_one(api_root, &txid_be, idx).await
    }

    /// Fetch the outspend at a specific index. If this index does not exist, an error will be
    /// returned.
    pub(crate) async fn fetch_one(
        api_root: &str,
        txid_be_hex: &str,
        idx: u32,
    ) -> Result<Option<Outspend>, FetchError> {
        let url = format!("{}/tx/{}/outspend/{}", api_root, txid_be_hex, idx);
        let o: Outspend = utils::ez_fetch_json(&url).await?;
        if o.txid_be == "" {
            Ok(None)
        } else {
            Ok(Some(o))
        }
    }
}
