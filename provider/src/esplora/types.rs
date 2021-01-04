use bitcoins::prelude::*;

use crate::esplora::*;
use crate::{provider::ProviderError, reqwest_utils};

#[derive(serde::Deserialize, Clone, Debug)]
pub(crate) struct MerkleProof {
    pub block_height: usize,
    pub merkle: Vec<String>,
    pub pos: usize,
}

impl MerkleProof {
    pub(crate) async fn fetch_by_txid(
        client: &reqwest::Client,
        api_root: &str,
        txid: TXID,
    ) -> Result<Self, FetchError> {
        let url = format!("{}/tx/{}/MerkleProof", api_root, txid.to_be_hex());
        Ok(reqwest_utils::ez_fetch_json(client, &url).await?)
    }
}

#[derive(serde::Deserialize, Clone, Debug)]
pub(crate) struct BlockStatus {
    pub in_best_chain: bool,
    #[serde(default = "String::new")]
    pub next_best: String,
}

impl BlockStatus {
    pub(crate) async fn fetch_by_digest(
        client: &reqwest::Client,
        api_root: &str,
        digest: BlockHash,
    ) -> Result<Self, FetchError> {
        let url = format!("{}/block/{}/status", api_root, digest.to_be_hex());
        Ok(reqwest_utils::ez_fetch_json(client, &url).await?)
    }
}

#[derive(serde::Deserialize, Clone, Debug)]
pub(crate) struct EsploraTxStatus {
    pub confirmed: bool,
    #[serde(default = "usize::min_value")]
    pub block_height: usize,
    #[serde(default = "String::new")]
    pub block_hash: String,
}

impl EsploraTxStatus {
    pub(crate) async fn fetch_by_txid(
        client: &reqwest::Client,
        api_root: &str,
        txid: TXID,
    ) -> Result<Self, FetchError> {
        let url = format!("{}/tx/{}/status", api_root, txid.to_be_hex());
        Ok(reqwest_utils::ez_fetch_json(client, &url).await?)
    }
}

#[derive(serde::Deserialize, Clone, Debug)]
pub(crate) struct EsploraTx {
    pub status: EsploraTxStatus,
    pub txid: String,
}

impl EsploraTx {
    pub(crate) async fn fetch_by_txid(
        client: &reqwest::Client,
        api_root: &str,
        txid: TXID,
    ) -> Result<Self, FetchError> {
        let url = format!("{}/tx/{}", api_root, txid.to_be_hex());
        Ok(reqwest_utils::ez_fetch_json(client, &url).await?)
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
        client: &reqwest::Client,
        api_root: &str,
        addr: &Address,
    ) -> Result<Vec<EsploraUTXO>, FetchError> {
        let url = format!("{}/address/{}/utxo", api_root, addr.as_string());
        Ok(reqwest_utils::ez_fetch_json(client, &url).await?)
    }

    pub(crate) fn into_utxo(self, addr: &Address) -> Result<UTXO, ProviderError> {
        let script_pubkey = bitcoins::Net::decode_address(addr);
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
    pub status: EsploraTxStatus,
}

impl Outspend {
    /// Fetch an Outspend by an outpoint referencing it
    pub(crate) async fn fetch_by_outpoint(
        client: &reqwest::Client,
        api_root: &str,
        outpoint: &BitcoinOutpoint,
    ) -> Result<Option<Outspend>, FetchError> {
        let txid_be = outpoint.txid_be_hex();
        let idx = outpoint.idx;
        Outspend::fetch_one(client, api_root, &txid_be, idx).await
    }

    /// Fetch the outspend at a specific index. If this index does not exist, an error will be
    /// returned.
    pub(crate) async fn fetch_one(
        client: &reqwest::Client,
        api_root: &str,
        txid_be_hex: &str,
        idx: u32,
    ) -> Result<Option<Outspend>, FetchError> {
        let url = format!("{}/tx/{}/outspend/{}", api_root, txid_be_hex, idx);
        let o: Outspend = reqwest_utils::ez_fetch_json(client, &url).await?;
        if o.txid_be.is_empty() {
            Ok(None)
        } else {
            Ok(Some(o))
        }
    }
}

#[derive(serde::Deserialize, Clone, Debug)]
pub(crate) struct EsploraBlock {
    pub(crate) id: String,
    pub(crate) height: usize,
    pub(crate) version: u32,
    pub(crate) timestamp: u32,
    pub(crate) bits: u32,
    pub(crate) nonce: u32,
    // difficulty
    pub(crate) merkle_root: String,
    pub(crate) tx_count: usize,
    pub(crate) size: usize,
    pub(crate) weight: usize,
    pub(crate) previousblockhash: String,
}

impl EsploraBlock {
    pub(crate) fn serialize(&self) -> RawHeader {
        let mut h = [0u8; 80];
        h[0..4].copy_from_slice(&self.version.to_le_bytes());
        h[4..36].copy_from_slice(
            BlockHash::from_be_hex(&self.previousblockhash)
                .expect("no malformed from API")
                .as_slice(),
        );
        h[36..68].copy_from_slice(
            BlockHash::from_be_hex(&self.merkle_root)
                .expect("no malformed from API")
                .as_slice(),
        );
        h[68..72].copy_from_slice(&self.timestamp.to_le_bytes());
        h[72..76].copy_from_slice(&self.bits.to_le_bytes());
        h[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        h.into()
    }

    pub(crate) async fn fetch_by_digest(
        client: &reqwest::Client,
        api_root: &str,
        digest: BlockHash,
    ) -> Result<Self, FetchError> {
        let url = format!("{}/block/{}", api_root, digest.to_be_hex());
        Ok(reqwest_utils::ez_fetch_json(client, &url).await?)
    }

    // pub(crate) async fn fetch_from_height(
    //     client: &reqwest::Client,
    //     api_root: &str,
    //     height: usize,
    // ) -> Result<[Self; 10], FetchError> {
    //     let url = format!("{}/block/{}", api_root, height);
    //     Ok(reqwest_utils::ez_fetch_json(client, &url).await?)
    // }
}
