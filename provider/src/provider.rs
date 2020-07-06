use async_trait::async_trait;

use riemann_core::enc::AddressEncoder;
use rmn_btc::{enc::Address, hashes::TXID, types::*};

use crate::{pending::PendingTx, watcher::PollingWatcher};

/// A Bitcoin Provider
#[async_trait]
pub trait BTCProvider: Sized {
    /// An error type
    type Error: From<rmn_btc::enc::bases::EncodingError>;

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

    /// Fetch the UTXOs belonging to a script pubkey from the remote API
    async fn get_utxos_by_script(&self, spk: &ScriptPubkey) -> Result<Vec<UTXO>, Self::Error> {
        self.get_utxos_by_address(&crate::Encoder::encode_address(spk)?)
            .await
    }

    /// Broadcast a transaction, get a future that resolves when the tx is confirmed
    async fn send_tx(&self, tx: &BitcoinTx) -> PendingTx<'_, Self>;

    /// Watch an outpoint, waiting for a tx to spend it
    async fn watch(&self, outpoint: BitcoinOutpoint, confirmations: usize) -> PollingWatcher<'_, Self>;

    /// Broadcast a transaction to the network
    async fn broadcast(&self, tx: &BitcoinTx) -> Result<TXID, Self::Error>;
}
