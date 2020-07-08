use async_trait::async_trait;
use std::time::Duration;

use riemann_core::prelude::*;
use rmn_btc::{
    enc::Address,
    hashes::{BlockHash, TXID},
    types::*,
};

use crate::{pending::PendingTx, watcher::PollingWatcher};

/// A Bitcoin Provider
#[async_trait]
pub trait BTCProvider: Sized {
    /// An error type
    type Error: From<rmn_btc::enc::bases::EncodingError>;

    /// Fetch the LE digest of the chain tip
    async fn tip_hash(&self) -> Result<BlockHash, Self::Error>;

    /// Fetch the height of the chain tip
    async fn tip_height(&self) -> Result<usize, Self::Error>;

    /// Query the backend to determine if the header with `digest` is in the main chain.
    async fn in_best_chain(&self, digest: BlockHash) -> Result<bool, Self::Error>;

    /// Get the number of confs a tx has. If the TX is unconfirmed this will be `Ok(Some(0))`. If
    /// the TX is unknown to the API, it will be `Ok(None)`.
    async fn get_confs(&self, txid: TXID) -> Result<Option<usize>, Self::Error>;

    /// Fetch a transaction from the remote API. If the tx is not found, the result will be
    /// `Ok(None)`
    async fn get_tx(&self, txid: TXID) -> Result<Option<BitcoinTx>, Self::Error>;

    /// Fetch the ID of a transaction that spends an outpoint. If no TX known to the remote source
    /// spends that outpoint, the result will be `Ok(None)`.
    async fn get_outspend(&self, outpoint: BitcoinOutpoint) -> Result<Option<TXID>, Self::Error>;

    /// Fetch the UTXOs belonging to an address from the remote API
    async fn get_utxos_by_address(&self, address: &Address) -> Result<Vec<UTXO>, Self::Error>;

    /// Broadcast a transaction to the network. Resolves to a TXID when broadcast.
    async fn broadcast(&self, tx: BitcoinTx) -> Result<TXID, Self::Error>;

    /// Fetch the UTXOs belonging to a script pubkey from the remote API
    async fn get_utxos_by_script(&self, spk: &ScriptPubkey) -> Result<Vec<UTXO>, Self::Error> {
        self.get_utxos_by_address(&crate::Encoder::encode_address(spk)?)
            .await
    }
}

/// An extension trait that adds polling watchers for
#[async_trait]
pub trait PollingBTCProvider: BTCProvider {
    /// Return the polling duration of the provider
    fn interval(&self) -> Duration;

    /// Set the polling interval of the provider. Interval is seconds.
    fn set_interval(&mut self, interval: usize);

    /// Broadcast a transaction, get a future that resolves when the tx is confirmed. This
    /// returns a `PendingTx` future. The tx will not be braodcast until that future is scheduled
    /// to run.
    fn send(&self, tx: BitcoinTx, confirmations: usize) -> PendingTx<Self> {
        PendingTx::new(tx, self)
            .confirmations(confirmations)
            .interval(self.interval())
    }

    /// Watch an outpoint, waiting for a tx to spend it. This returns a `PollingWatcher` future.
    /// The observation will not start until that future is scheduled to run.
    fn watch(&self, outpoint: BitcoinOutpoint, confirmations: usize) -> PollingWatcher<Self> {
        PollingWatcher::new(outpoint, self)
            .confirmations(confirmations)
            .interval(self.interval())
    }
}
