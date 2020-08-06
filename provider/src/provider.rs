use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

use bitcoins::{
    enc::Address,
    hashes::{BlockHash, TXID},
    prelude::RawHeader,
    types::*,
};
use coins_core::prelude::*;
use futures_util::lock::Mutex;
use lru::LruCache;

use crate::{chain::Tips, pending::PendingTx, watcher::PollingWatcher, DEFAULT_CACHE_SIZE};

/// Errors thrown by providers
#[derive(Debug, Error)]
pub enum ProviderError {
    /// Serde issue
    #[cfg(any(feature = "rpc", feature = "esplora"))]
    #[error(transparent)]
    SerdeJSONError(#[from] serde_json::Error),

    /// Bubbled up from bitcoins
    #[error(transparent)]
    EncoderError(#[from] coins_core::enc::bases::EncodingError),

    /// Bubbled up from core
    #[error(transparent)]
    CoinsSerError(#[from] coins_core::ser::SerError),

    /// Unsupported action. Provider should give a string describing the action and reason
    #[error("Unsupported action: {0}")]
    Unsupported(String),

    /// RPC Error Response
    #[cfg(feature = "rpc")]
    #[error("RPC Error Response: {0}")]
    RPCErrorResponse(crate::rpc::common::ErrorResponse),

    /// Custom provider error. Indicates whether the request should be retried
    #[error("Proivder error {e}")]
    Custom {
        /// Whether the Custom error suggests that the request be retried
        from_parsing: bool,
        /// The error
        e: Box<dyn std::error::Error>,
    },
}

impl ProviderError {
    /// Shortcut for instantiating a custom error
    pub fn custom(from_parsing: bool, e: Box<dyn std::error::Error>) -> Self {
        Self::Custom { from_parsing, e }
    }
    /// Returns true if the request failed due to a local parsing error.
    ///
    /// ## Note:
    ///
    /// This usually indicates that a requested object was not found. It is common for Bitcoin
    /// APIs to violate JSON RPC conventions, and return raw strings in this case.
    #[cfg(any(feature = "rpc", feature = "esplora"))]
    pub fn from_parsing(&self) -> bool {
        match self {
            ProviderError::Custom {
                from_parsing: true,
                e: _,
            } => true,
            ProviderError::SerdeJSONError(_) => true,
            ProviderError::CoinsSerError(_) => true,
            ProviderError::EncoderError(_) => true,
            _ => false,
        }
    }
    /// Returns true if the request failed due to a local parsing error.
    ///
    /// ## Note:
    ///
    /// This usually indicates that a requested object was not found. It is common for Bitcoin
    /// APIs to violate JSON RPC conventions, and return raw strings in this case.
    #[cfg(not(any(feature = "rpc", feature = "esplora")))]
    pub fn from_parsing(&self) -> bool {
        match self {
            ProviderError::Custom {
                from_parsing: true,
                e: _,
            } => true,
            ProviderError::CoinsSerError(_) => true,
            ProviderError::EncoderError(_) => true,
            _ => false,
        }
    }
}

/// A Bitcoin Provider
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait BTCProvider: Sync + Send {
    /// Explicitly drop the provider, closing connections and freeing resources
    fn close(self)
    where
        Self: Sized,
    {
    }

    // -- CHAIN UTILS -- //

    /// Fetch the LE digest of the chain tip
    async fn tip_hash(&self) -> Result<BlockHash, ProviderError>;

    /// Fetch the height of the chain tip
    async fn tip_height(&self) -> Result<usize, ProviderError>;

    /// Query the backend to determine if the header with `digest` is in the main chain.
    async fn in_best_chain(&self, digest: BlockHash) -> Result<bool, ProviderError>;

    /// Return `headers` blockhashes starting at height `start`. If the range is longer than the
    /// chain, it will return as many headers as possible. If the start is above the tip height,
    /// it will return an empty vector/
    async fn get_digest_range(
        &self,
        start: usize,
        headers: usize,
    ) -> Result<Vec<BlockHash>, ProviderError>;

    /// Return `headers` raw headers starting at height `start`. If the range is longer than the
    /// chain, it will return as many headers as possible. If the start is above the tip height,
    /// it will return an empty vector/
    async fn get_raw_header_range(
        &self,
        start: usize,
        headers: usize,
    ) -> Result<Vec<RawHeader>, ProviderError>;

    /// Get the header at `height` in the remote data source's best known chain. If no header is
    /// known at that height, return `None`.
    async fn get_header_at_height(
        &self,
        height: usize,
    ) -> Result<Option<RawHeader>, ProviderError> {
        Ok(self.get_raw_header_range(height, 1).await?.first().copied())
    }

    /// Return the raw header corresponding to a block hash. Returns `None` if the header is
    /// unknown to the remote API
    async fn get_raw_header(&self, digest: BlockHash) -> Result<Option<RawHeader>, ProviderError>;

    /// Return the height of a header, or `None` if the header is unknown.
    ///
    /// ## Warning: Having a height does NOT mean that the header is part of the main chain.
    async fn get_height_of(&self, digest: BlockHash) -> Result<Option<usize>, ProviderError>;

    // -- TX UTILS -- //

    /// Get confirming height of the tx. Ok(None) if unknown
    async fn get_confirmed_height(&self, txid: TXID) -> Result<Option<usize>, ProviderError>;

    /// Get the number of confs a tx has. If the TX is unconfirmed this will be `Ok(Some(0))`. If
    /// the TX is unknown to the API, it will be `Ok(None)`.
    async fn get_confs(&self, txid: TXID) -> Result<Option<usize>, ProviderError>;

    /// Fetch a transaction from the remote API. If the tx is not found, the result will be
    /// `Ok(None)`
    async fn get_tx(&self, txid: TXID) -> Result<Option<BitcoinTx>, ProviderError>;

    /// Broadcast a transaction to the network. Resolves to a TXID when broadcast.
    async fn broadcast(&self, tx: BitcoinTx) -> Result<TXID, ProviderError>;

    // -- SPEND UTILS -- //

    /// Fetch the ID of a transaction that spends an outpoint. If no TX known to the remote source
    /// spends that outpoint, the result will be `Ok(None)`.
    ///
    /// Note: some providers may not implement this functionality.
    async fn get_outspend(&self, outpoint: BitcoinOutpoint) -> Result<Option<TXID>, ProviderError>;

    /// Fetch the UTXOs belonging to an address from the remote API
    ///
    /// ## Note: some providers may not implement this functionality.
    ///
    /// ## Note: when using Bitcoin Core, this may take upwards of 40 second
    async fn get_utxos_by_address(&self, address: &Address) -> Result<Vec<UTXO>, ProviderError>;

    /// Fetch the UTXOs belonging to a script pubkey from the remote API
    ///
    /// Note: some providers may not implement this functionality.
    ///
    /// ## Note: when using Bitcoin Core, this may take upwards of 40 second
    async fn get_utxos_by_script(&self, spk: &ScriptPubkey) -> Result<Vec<UTXO>, ProviderError> {
        self.get_utxos_by_address(&crate::Encoder::encode_address(spk)?)
            .await
    }

    // -- MERKLE UTILS -- //

    /// Get the merkle proof for a transaction. This will be `None` if the tx is not confirmed
    async fn get_merkle(
        &self,
        txid: TXID,
    ) -> Result<Option<(usize, Vec<Hash256Digest>)>, ProviderError>;

    /// TODO: make less brittle
    async fn get_confirming_digests(
        &self,
        txid: TXID,
        confs: usize,
    ) -> Result<Vec<BlockHash>, ProviderError> {
        let height = {
            let height_opt = self.get_confirmed_height(txid).await?;
            if height_opt.is_none() {
                return Ok(vec![]);
            }
            height_opt.unwrap()
        };
        self.get_digest_range(height, confs).await
    }

    /// TODO: make less brittle
    async fn get_confirming_headers(
        &self,
        txid: TXID,
        confs: usize,
    ) -> Result<Vec<RawHeader>, ProviderError> {
        let height = {
            let height_opt = self.get_confirmed_height(txid).await?;
            if height_opt.is_none() {
                return Ok(vec![]);
            }
            height_opt.unwrap()
        };
        self.get_raw_header_range(height, confs).await
    }
}

/// An extension trait that adds polling watchers for a provider
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait PollingBTCProvider: BTCProvider {
    /// Return the polling duration of the provider
    fn interval(&self) -> Duration;

    /// Set the polling interval of the provider. Interval is seconds.
    fn set_interval(&mut self, interval: usize);

    /// Broadcast a transaction, get a future that resolves when the tx is confirmed. This
    /// returns a `PendingTx` future. The tx will not be braodcast until that future is scheduled
    /// to run.
    fn send(&self, tx: BitcoinTx, confirmations: usize) -> PendingTx
    where
        Self: Sized,
    {
        PendingTx::new(tx, self)
            .confirmations(confirmations)
            .interval(self.interval())
    }

    /// Track a txid that may or may not already be in the mempool. Returns `None` if the txid is
    /// not known to the remote node.
    async fn track(&self, txid: TXID, confirmations: usize) -> Option<PendingTx<'_>>
    where
        Self: Sized,
    {
        let tx = self.get_tx(txid).await.ok().flatten()?;
        Some(
            PendingTx::new(tx, self)
                .confirmations(confirmations)
                .interval(self.interval()),
        )
    }

    /// Watch the chain tip. Get notified of the new `BlockHash` every time it changes.
    ///
    /// Note: A new hash does not necessarily mean the chain height has increased. Reorgs may
    /// result in the height remaining the same, or decreasing in rare cases.
    fn tips(&self, limit: usize) -> Tips
    where
        Self: Sized,
    {
        Tips::new(limit, self).interval(self.interval())
    }

    /// Watch an outpoint, waiting for a tx to spend it. This returns a `PollingWatcher` future.
    /// The observation will not start until that future is scheduled to run.
    ///
    /// Note: some providers may not implement this functionality.
    fn watch(&self, outpoint: BitcoinOutpoint, confirmations: usize) -> PollingWatcher
    where
        Self: Sized,
    {
        PollingWatcher::new(outpoint, self)
            .confirmations(confirmations)
            .interval(self.interval())
    }
}

/// A provider that caches API responses whose values will never change.
pub struct CachingProvider<T: BTCProvider> {
    provider: T,
    tx_cache: Mutex<LruCache<TXID, BitcoinTx>>,
    header_cache: Mutex<LruCache<BlockHash, RawHeader>>,
    height_cache: Mutex<LruCache<BlockHash, usize>>,
}

impl<T: BTCProvider> From<T> for CachingProvider<T> {
    fn from(provider: T) -> Self {
        Self {
            provider,
            tx_cache: Mutex::new(LruCache::new(DEFAULT_CACHE_SIZE)),
            header_cache: Mutex::new(LruCache::new(DEFAULT_CACHE_SIZE)),
            height_cache: Mutex::new(LruCache::new(DEFAULT_CACHE_SIZE)),
        }
    }
}

impl<T: BTCProvider> CachingProvider<T> {
    /// Return a reference to the TX, if it's in the cache.
    pub async fn peek_tx(&self, txid: TXID) -> Option<BitcoinTx> {
        self.tx_cache.lock().await.peek(&txid).cloned()
    }

    /// Return true if the cache has the tx in it
    pub async fn has_tx(&self, txid: TXID) -> bool {
        self.tx_cache.lock().await.contains(&txid)
    }

    /// Return true if the cache has the header in it
    pub async fn has_header(&self, digest: BlockHash) -> bool {
        self.header_cache.lock().await.contains(&digest)
    }

    /// Return true if the cache has the height in it
    pub async fn has_height(&self, digest: BlockHash) -> bool {
        self.height_cache.lock().await.contains(&digest)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<T> BTCProvider for CachingProvider<T>
where
    T: BTCProvider,
{
    async fn tip_hash(&self) -> Result<BlockHash, ProviderError> {
        self.provider.tip_hash().await
    }

    async fn tip_height(&self) -> Result<usize, ProviderError> {
        self.provider.tip_height().await
    }

    async fn in_best_chain(&self, digest: BlockHash) -> Result<bool, ProviderError> {
        self.provider.in_best_chain(digest).await
    }

    async fn get_digest_range(
        &self,
        start: usize,
        headers: usize,
    ) -> Result<Vec<BlockHash>, ProviderError> {
        self.provider.get_digest_range(start, headers).await
    }

    async fn get_raw_header_range(
        &self,
        start: usize,
        headers: usize,
    ) -> Result<Vec<RawHeader>, ProviderError> {
        self.provider.get_raw_header_range(start, headers).await
    }

    async fn get_raw_header(&self, digest: BlockHash) -> Result<Option<RawHeader>, ProviderError> {
        if self.has_header(digest).await {
            return Ok(self.header_cache.lock().await.get(&digest).cloned());
        }

        let header_opt = { self.provider.get_raw_header(digest).await? };
        if header_opt.is_none() {
            return Ok(None);
        }
        let header = header_opt.unwrap();
        self.header_cache.lock().await.put(digest, header);
        Ok(Some(header))
    }

    async fn get_height_of(&self, digest: BlockHash) -> Result<Option<usize>, ProviderError> {
        if self.has_header(digest).await {
            return Ok(self.height_cache.lock().await.get(&digest).cloned());
        }

        let height_opt = { self.provider.get_height_of(digest).await? };
        if height_opt.is_none() {
            return Ok(None);
        }
        let height = height_opt.unwrap();
        self.height_cache.lock().await.put(digest, height);
        Ok(Some(height))
    }

    async fn get_confirmed_height(&self, txid: TXID) -> Result<Option<usize>, ProviderError> {
        self.provider.get_confirmed_height(txid).await
    }

    async fn get_confs(&self, txid: TXID) -> Result<Option<usize>, ProviderError> {
        self.provider.get_confs(txid).await
    }

    async fn get_tx(&self, txid: TXID) -> Result<Option<BitcoinTx>, ProviderError> {
        if self.has_tx(txid).await {
            return Ok(self.tx_cache.lock().await.get(&txid).cloned());
        }

        let tx_opt = { self.provider.get_tx(txid).await? };
        if tx_opt.is_none() {
            return Ok(None);
        }
        let tx = tx_opt.unwrap();
        self.tx_cache.lock().await.put(txid, tx.clone());
        Ok(Some(tx))
    }

    async fn broadcast(&self, tx: BitcoinTx) -> Result<TXID, ProviderError> {
        self.provider.broadcast(tx).await
    }

    async fn get_outspend(&self, outpoint: BitcoinOutpoint) -> Result<Option<TXID>, ProviderError> {
        self.provider.get_outspend(outpoint).await
    }

    async fn get_utxos_by_address(&self, address: &Address) -> Result<Vec<UTXO>, ProviderError> {
        self.provider.get_utxos_by_address(address).await
    }

    async fn get_merkle(
        &self,
        txid: TXID,
    ) -> Result<Option<(usize, Vec<Hash256Digest>)>, ProviderError> {
        self.provider.get_merkle(txid).await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<T> PollingBTCProvider for CachingProvider<T>
where
    T: PollingBTCProvider,
{
    fn interval(&self) -> Duration {
        self.provider.interval()
    }
    fn set_interval(&mut self, interval: usize) {
        self.provider.set_interval(interval)
    }
}
