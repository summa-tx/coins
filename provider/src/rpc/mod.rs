/// JSON RPC Common
pub mod common;

/// HTTP Transport
pub mod http;

/// Bitcoin RPC types
pub mod rpc_types;

use async_trait::async_trait;
use rmn_btc::prelude::*;
use thiserror::Error;
use secrecy::SecretString;

use crate::{
    reqwest_utils::FetchError,
    rpc::{
        common::{ErrorResponse, JsonRPCTransport},
        http::HttpTransport,
        rpc_types::*,
    },
    BTCProvider, ProviderError,
};

/// Enum of errors that can be produced by this updater
#[derive(Debug, Error)]
pub enum RPCError {
    /// Error in networking
    #[error(transparent)]
    FetchError(#[from] FetchError),

    /// Bubbled up from riemann
    #[error(transparent)]
    EncoderError(#[from] rmn_btc::enc::bases::EncodingError),

    /// Bubbled up from Riemann
    #[error(transparent)]
    RmnSerError(#[from] riemann_core::ser::SerError),

    /// Received an Error response from the RPC server
    #[error("Error Response: {0}")]
    ErrorResponse(ErrorResponse),
}

impl From<ErrorResponse> for RPCError {
    fn from(e: ErrorResponse) -> Self {
        RPCError::ErrorResponse(e)
    }
}

impl From<reqwest::Error> for RPCError {
    fn from(e: reqwest::Error) -> Self {
        FetchError::from(e).into()
    }
}

impl ProviderError for RPCError {
    fn is_network(&self) -> bool {
        match self {
            RPCError::FetchError(FetchError::ReqwestError(_)) => true,
            _ => false,
        }
    }
}

/// A Bitcoin RPC connection
#[derive(Debug, Default)]
pub struct BitcoinRPC<T: JsonRPCTransport> {
    transport: T,
}

impl<T: JsonRPCTransport> From<T> for BitcoinRPC<T> {
    fn from(transport: T) -> Self {
        Self { transport }
    }
}

impl BitcoinRPC<HttpTransport> {
    /// Instantiate a transport with BasicAuth credentials
    pub fn with_credentials(username: SecretString, password: SecretString) -> Self {
        HttpTransport::with_credentials(username, password).into()
    }

    /// Instantiate a transport with BasicAuth credentials and a url
    pub fn with_credentials_and_url(
        username: SecretString,
        password: SecretString,
        url: &str,
    ) -> Self {
        HttpTransport::with_credentials_and_url(username, password, url).into()
    }
}

impl<T: JsonRPCTransport> BitcoinRPC<T> {
    /// Get the digest of the best block
    pub async fn get_best_block_hash(&self) -> Result<String, RPCError> {
        unimplemented!()
    }

    /// Get a block by its digest
    pub async fn get_block(&self, block: BlockHash) -> Result<GetBlockResponse, RPCError> {
        unimplemented!()
    }

    /// Get a TX by its txid
    pub async fn get_transaction(&self, txid: TXID) -> Result<GetTransactionResponse, RPCError> {
        unimplemented!()
    }

    /// Send a raw transaction to the network
    pub async fn send_raw_transaction(&self, tx: BitcoinTx) -> Result<TXID, RPCError> {
        unimplemented!()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<T: JsonRPCTransport + Send + Sync> BTCProvider for BitcoinRPC<T> {
    type Error = RPCError;

    async fn tip_hash(&self) -> Result<BlockHash, Self::Error> {
        Ok(BlockHash::from_be_hex(&self.get_best_block_hash().await?)?)
    }

    async fn tip_height(&self) -> Result<usize, Self::Error> {
        let tip = self.tip_hash().await?;
        Ok(self.get_block(tip).await?.height)
    }

    async fn in_best_chain(&self, digest: BlockHash) -> Result<bool, Self::Error> {
        Ok(self.get_block(digest).await?.confirmations != -1)
    }

    async fn get_confs(&self, txid: TXID) -> Result<Option<usize>, Self::Error> {
        let tx_res = self.get_transaction(txid).await;
        match tx_res {
            Err(e) => {
                if e.is_network() { Err(e) } else { Ok(None) }
            },
            Ok(tx) => {
                if tx.confirmations == -1 {
                    Ok(Some(0))
                } else {
                    Ok(Some(tx.confirmations as usize))
                }
            }
        }
    }

    async fn get_tx(&self, txid: TXID) -> Result<Option<BitcoinTx>, Self::Error> {
        let tx_res = self.get_transaction(txid).await;
        match tx_res {
            Err(e) => {
                if e.is_network() { Err(e) } else { Ok(None) }
            },
            Ok(tx) => {
                Ok(Some(BitcoinTx::deserialize_hex(&tx.hex).expect("No invalid tx from RPC")))
            }
        }
    }

    async fn get_outspend(&self, outpoint: BitcoinOutpoint) -> Result<Option<TXID>, Self::Error> {
        unimplemented!()
    }

    async fn get_utxos_by_address(&self, address: &Address) -> Result<Vec<UTXO>, Self::Error> {
        unimplemented!()
    }

    async fn broadcast(&self, tx: BitcoinTx) -> Result<TXID, Self::Error> {
        self.send_raw_transaction(tx).await
    }
}
