mod utils;
use utils::*;

use std::time::Duration;
use futures::lock::Mutex;
use async_trait::async_trait;
use lru::LruCache;
use thiserror::Error;

use riemann_core::prelude::*;
use rmn_btc::prelude::*;

use crate::{BTCProvider, PollingBTCProvider};

#[cfg(feature = "mainnet")]
static BLOCKSTREAM: &str = "https://blockstream.info/api";

#[cfg(feature = "testnet")]
static BLOCKSTREAM: &str = "https://blockstream.info/testnet/api";


/// An updater that uses the Esplora API and caches responses
#[derive(Debug)]
pub struct EsploraProvider {
    interval: usize,
    api_root: String,
    cache: Mutex<LruCache<TXID, BitcoinTx>>,
}

impl Default for EsploraProvider {
    fn default() -> Self {
        Self::with_api_root(BLOCKSTREAM)
    }
}

impl EsploraProvider {
    /// Instantiate the API pointing at a specific URL
    pub fn with_api_root(api_root: &str) -> Self {
        Self {
            interval: 300,
            api_root: api_root.to_owned(),
            cache: Mutex::new(LruCache::new(100)),
        }
    }

    /// Set the polling interval
    pub fn set_interval(&mut self, interval: usize) {
        self.interval = interval;
    }

    /// Return true if the cache has the tx in it
    pub async fn has_tx(&self, txid: TXID) -> bool {
        self.cache.lock().await.contains(&txid)
    }

    /// Return a reference to the TX, if it's in the cache.
    pub async fn peek_tx(&self, txid: TXID) -> Option<BitcoinTx> {
        self.cache.lock().await.peek(&txid).cloned()
    }
}

/// Enum of errors that can be produced by this updater
#[derive(Debug, Error)]
pub enum EsploraError {
    /// Bubbled up from the Tx Deserializer.
    #[error(transparent)]
    TxError(#[from] rmn_btc::types::transactions::TxError),

    /// Error in networking
    #[error("Fetch Error: {0:?}")]
    FetchError(utils::FetchError),

    /// Bubbled up from riemann
    #[error(transparent)]
    EncoderError(#[from] rmn_btc::enc::bases::EncodingError),

    /// Bubbled up from Riemann
    #[error(transparent)]
    RmnSerError(#[from] riemann_core::ser::SerError),
}

impl From<FetchError> for EsploraError {
    fn from(v: FetchError) -> EsploraError {
        EsploraError::FetchError(v)
    }
}

#[async_trait]
impl BTCProvider for EsploraProvider {
    type Error = EsploraError;

    // async fn tip_hash(&self) -> Result<Hash256Digest, Self::Error> {
    //     let url = format!("{}/blocks/tip/hash", self.api_root);
    //     let response = ez_fetch_string(&url).await?;
    //     let mut digest = Hash256Digest::deserialize_hex(&response)?;
    //     digest.reverse();
    //     Ok(digest)
    // }
    //
    // async fn tip_height(&self) -> Result<usize, Self::Error> {
    //     let url = format!("{}/blocks/tip/height", self.api_root);
    //     let response = ez_fetch_string(&url).await?;
    //     Ok(response.parse().unwrap())
    // }
    //
    // async fn in_best_chain(&self, digest: Hash256Digest) -> Result<BlockStatus, Self::Error> {
    //     let status =
    // }

    async fn get_confs(&self, _txid: TXID) -> Result<Option<usize>, Self::Error> {
        unimplemented!()
    }

    async fn get_tx(&self, txid: TXID) -> Result<Option<BitcoinTx>, Self::Error> {
        if !self.has_tx(txid).await {
            let tx_hex = fetch_tx_hex_by_id(&self.api_root, txid).await?;
            if let Ok(tx) = BitcoinTx::deserialize_hex(&tx_hex) {
                self.cache.lock().await.put(txid, tx);
            }
        }
        Ok(self.cache.lock().await.get(&txid).cloned())
    }

    async fn get_outspend(&self, outpoint: BitcoinOutpoint) -> Result<Option<TXID>, Self::Error> {
        let outspend_opt = Outspend::fetch_by_outpoint(&self.api_root, &outpoint).await?;

        match outspend_opt {
            Some(outspend) => {
                if outspend.spent {
                    let txid = Default::default();
                    Ok(Some(txid))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    async fn get_utxos_by_address(&self, address: &Address) -> Result<Vec<UTXO>, Self::Error> {
        let res: Result<Vec<_>, EsploraError> = EsploraUTXO::fetch_by_address(&self.api_root, address)
            .await?
            .into_iter()
            .map(|e| e.into_utxo(address))
            .collect();
        Ok(res?)
    }

    async fn broadcast(&self, tx: BitcoinTx) -> Result<TXID, Self::Error> {
        let url = format!("{}/tx", self.api_root);
        let response = utils::post_hex(&url, tx.serialize_hex()?).await?;
        Ok(TXID::deserialize_hex(&response)?)
    }
}

#[async_trait]
impl PollingBTCProvider for EsploraProvider {
    fn interval(&self) -> Duration {
        Duration::from_secs(self.interval as u64)
    }

    fn set_interval(&mut self, interval: usize) {
        self.interval = interval;
    }
}

#[derive(serde::Deserialize, Clone, Debug)]
struct BlockStatus {
    pub in_best_chain: bool,
    #[serde(default = "Hash256Digest::default")]
    pub next_best: Hash256Digest,
}

#[derive(serde::Deserialize, Clone, Debug)]
struct TxStatus {
    pub confirmed: bool,
    #[serde(default = "usize::min_value")]
    pub block_height: usize,
    #[serde(default = "Hash256Digest::default")]
    pub block_hash: Hash256Digest,
}

impl TxStatus {
    async fn fetch_by_txid(api_root: &str, txid: TXID) -> Result<Self, FetchError> {
        let url = format!("{}/tx/{}/status", api_root, txid.reversed().serialize_hex().unwrap());
        Ok(utils::ez_fetch_json(&url).await?)
    }
}

#[derive(serde::Deserialize, Clone, Debug)]
struct EsploraUTXO {
    /// TXID in BE format
    pub txid: String,
    /// Index in vout
    pub vout: usize,
    /// UTXO value
    pub value: usize,
}

impl EsploraUTXO {
    async fn fetch_by_address(
        api_root: &str,
        addr: &Address,
    ) -> Result<Vec<EsploraUTXO>, FetchError> {
        let url = format!("{}/address/{}/utxo", api_root, addr.as_string());
        Ok(utils::ez_fetch_json(&url).await?)
    }

    fn into_utxo(self, addr: &Address) -> Result<UTXO, EsploraError> {
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
struct Outspend {
    /// Whether the output has been spent
    pub spent: bool,
    /// The TXID that spend it
    #[serde(default = "String::new")]
    pub txid_be: String,
    /// The index of the spending input in that transaction's Vin
    #[serde(default = "usize::max_value")]
    pub vin: usize,
}

impl Outspend {
    /// Fetch an Outspend by an outpoint referencing it
    async fn fetch_by_outpoint(
        api_root: &str,
        outpoint: &BitcoinOutpoint,
    ) -> Result<Option<Outspend>, FetchError> {
        let txid_be = outpoint.txid_be_hex();
        let idx = outpoint.idx;
        Outspend::fetch_one(api_root, &txid_be, idx).await
    }

    /// Fetch the outspend at a specific index. If this index does not exist, an error will be
    /// returned.
    async fn fetch_one(
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
