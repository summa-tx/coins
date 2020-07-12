use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

use riemann_core::prelude::*;
use rmn_btc::{
    prelude::RawHeader,
    enc::Address,
    hashes::{BlockHash, TXID},
    types::*,
};

use crate::{chain::Tips, pending::PendingTx, watcher::PollingWatcher};

/// Errors thrown by providers
#[derive(Debug, Error)]
pub enum ProviderError {
    /// Serde issue
    #[error(transparent)]
    SerdeJSONError(#[from] serde_json::Error),

    /// Bubbled up from riemann
    #[error(transparent)]
    EncoderError(#[from] rmn_btc::enc::bases::EncodingError),

    /// Bubbled up from Riemann
    #[error(transparent)]
    RmnSerError(#[from] riemann_core::ser::SerError),

    /// Unsupported action. Provider should give a string describing the action and reason
    #[error("Unsupported action: {0}")]
    Unsupported(String),

    /// Custom provider error. Indicates whether the request should be retried
    #[error("Proivder error {e}")]
    Custom {
        /// Whether the Custom error suggests that the request be retried
        should_retry: bool,
        /// The error
        e: Box<dyn std::error::Error>,
    },

    /// RPC Error Response
    #[cfg(feature = "rpc")]
    #[error("RPC Error Response: {0}")]
    RPCErrorResponse(crate::rpc::common::ErrorResponse),
}

impl ProviderError {
    /// Returns true if the request should be retried. E.g. it failed due to a network issue.
    ///
    /// This is used to determine if retrying a request is appropriate
    pub fn should_retry(&self) -> bool {
        match self {
            ProviderError::Custom {
                should_retry: true,
                e: _,
            } => true,
            _ => false,
        }
    }
}

/// A Bitcoin Provider
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait BTCProvider: Sync + Send {
    /// Fetch the LE digest of the chain tip
    async fn tip_hash(&self) -> Result<BlockHash, ProviderError>;

    /// Fetch the height of the chain tip
    async fn tip_height(&self) -> Result<usize, ProviderError>;

    /// Query the backend to determine if the header with `digest` is in the main chain.
    async fn in_best_chain(&self, digest: BlockHash) -> Result<bool, ProviderError>;

    /// Return `headers` blockhashes starting at height `start`
    async fn header_digests(&self, start: usize, headers: usize) -> Result<Vec<BlockHash>, ProviderError>;

    /// Return `headers` raw headers starting at height `start`
    async fn raw_headers(&self, start: usize, headers: usize) -> Result<Vec<RawHeader>, ProviderError>;

    /// Get confirming height of the tx. Ok(None) if unknown
    async fn confirmed_height(&self, txid: TXID) -> Result<Option<usize>, ProviderError>;

    /// Get the number of confs a tx has. If the TX is unconfirmed this will be `Ok(Some(0))`. If
    /// the TX is unknown to the API, it will be `Ok(None)`.
    async fn get_confs(&self, txid: TXID) -> Result<Option<usize>, ProviderError>;

    /// Fetch a transaction from the remote API. If the tx is not found, the result will be
    /// `Ok(None)`
    async fn get_tx(&self, txid: TXID) -> Result<Option<BitcoinTx>, ProviderError>;

    /// Broadcast a transaction to the network. Resolves to a TXID when broadcast.
    async fn broadcast(&self, tx: BitcoinTx) -> Result<TXID, ProviderError>;

    /// Fetch the ID of a transaction that spends an outpoint. If no TX known to the remote source
    /// spends that outpoint, the result will be `Ok(None)`.
    ///
    /// Note: some providers may not implement this functionality.
    async fn get_outspend(&self, outpoint: BitcoinOutpoint) -> Result<Option<TXID>, ProviderError>;

    /// Fetch the UTXOs belonging to an address from the remote API
    ///
    /// Note: some providers may not implement this functionality.
    async fn get_utxos_by_address(&self, address: &Address) -> Result<Vec<UTXO>, ProviderError>;

    /// Get the merkle proof for a transaction. This will be `None` if the tx is not confirmed
    async fn get_merkle(&self, txid: TXID) -> Result<Option<(usize, Vec<TXID>)>, ProviderError>;

    /// Fetch the UTXOs belonging to a script pubkey from the remote API
    ///
    /// Note: some providers may not implement this functionality.
    async fn get_utxos_by_script(&self, spk: &ScriptPubkey) -> Result<Vec<UTXO>, ProviderError> {
        self.get_utxos_by_address(&crate::Encoder::encode_address(spk)?)
            .await
    }

    /// TODO: make less brittle
    async fn get_confirming_headers(&self, txid: TXID, confs: usize) -> Result<Vec<BlockHash>, ProviderError> {
        let height = {
            let height_opt = self.confirmed_height(txid).await?;
            if height_opt.is_none() { return Ok(vec![])}
            height_opt.unwrap()
        };
        self.header_digests(height, confs).await
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

    /// Watch the chain tip. Get notified of the new `BlockHash` every time it changes.
    ///
    /// Note: A new hash does not necessarily mean the chain height has increased. Reorgs may
    /// result in the height decreasing in rare cases.
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
