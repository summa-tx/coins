/// JSON RPC Common
pub mod common;

/// HTTP Transport
pub mod http;

/// Bitcoin RPC types
pub mod rpc_types;

use async_trait::async_trait;
use futures_util::lock::Mutex;
use rmn_btc::prelude::*;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

use crate::{
    reqwest_utils::FetchError,
    rpc::{
        common::{ErrorResponse, JsonRPCTransport},
        http::HttpTransport,
        rpc_types::*,
    },
    BTCProvider, PollingBTCProvider, ProviderError,
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
#[derive(Debug)]
pub struct BitcoindRPC<T: JsonRPCTransport> {
    transport: T,
    interval: Duration,
    scan_guard: Mutex<()>,
}

impl<T: JsonRPCTransport> Default for BitcoindRPC<T> {
    fn default() -> Self {
        Self {
            transport: Default::default(),
            interval: crate::DEFAULT_POLL_INTERVAL,
            scan_guard: Mutex::new(()),
        }
    }
}

impl<T: JsonRPCTransport> From<T> for BitcoindRPC<T> {
    fn from(transport: T) -> Self {
        Self {
            transport,
            ..Default::default()
        }
    }
}

impl BitcoindRPC<HttpTransport> {
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

impl<T: JsonRPCTransport> BitcoindRPC<T> {
    async fn request<P: Serialize + Send + Sync, R: for<'a> Deserialize<'a>>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R, RPCError> {
        self.transport
            .request(method, params)
            .await
            .map_err(Into::into)
    }

    /// Get the digest of the best block
    pub async fn get_best_block_hash(&self) -> Result<String, RPCError> {
        self.request("getbestblockhash", Vec::<String>::new()).await
    }

    /// Get a block by its digest
    pub async fn get_block(&self, block: BlockHash) -> Result<GetBlockResponse, RPCError> {
        self.request("getblock", vec![block.to_be_hex()]).await
    }

    /// Get a TX by its txid
    pub async fn get_raw_transaction(
        &self,
        txid: TXID,
    ) -> Result<GetRawTransactionResponse, RPCError> {
        self.request("getrawtransaction", GetRawTxParams(txid.to_be_hex(), 1))
            .await
    }

    /// Send a raw transaction to the network
    pub async fn send_raw_transaction(&self, tx: BitcoinTx) -> Result<TXID, RPCError> {
        let txid_be: String = self.request("sendrawtransaction", vec![tx.serialize_hex()]).await?;
        Ok(TXID::from_be_hex(&txid_be)?)
    }

    /// Start a txout scan. This may take some time, and will be interrupted by future requests.
    /// So we acquire a lock for it
    pub async fn scan_tx_out_set_for_address_start(
        &self,
        addr: Address,
    ) -> Result<ScanTxOutResponse, RPCError> {
        let _lock = self.scan_guard.lock().await;
        self.request(
            "scantxoutset",
            ScanTxOutParams("start".to_owned(), vec![addr.to_descriptor()]),
        )
        .await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<T: JsonRPCTransport + Send + Sync> BTCProvider for BitcoindRPC<T> {
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
        let tx_res = self.get_raw_transaction(txid).await;
        match tx_res {
            Err(e) => {
                if e.is_network() {
                    Err(e)
                } else {
                    Ok(None)
                }
            }
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
        let tx_res = self.get_raw_transaction(txid).await;
        match tx_res {
            Err(e) => {
                if e.is_network() {
                    Err(e)
                } else {
                    Ok(None)
                }
            }
            Ok(tx) => Ok(Some(
                BitcoinTx::deserialize_hex(&tx.hex).expect("No invalid tx from RPC"),
            )),
        }
    }

    async fn broadcast(&self, tx: BitcoinTx) -> Result<TXID, Self::Error> {
        self.send_raw_transaction(tx).await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<T: JsonRPCTransport + Send + Sync> PollingBTCProvider for BitcoindRPC<T> {
    fn interval(&self) -> Duration {
        self.interval
    }

    fn set_interval(&mut self, interval: usize) {
        self.interval = Duration::from_secs(interval as u64);
    }
}
//
// #[cfg(test)]
// mod test {
//     use super::*;
//     use tokio::runtime;
//
//     use riemann_core::ser::ByteFormat;
//
//     // runs against live API. leave commented
//     #[test]
//     #[allow(unused_must_use)]
//     fn it_prints_headers() {
//         let fut = async move {
//             let provider = BitcoindRPC::with_credentials_and_url(
//                 "x".parse().unwrap(),
//                 "xxx".parse().unwrap(),
//                 &"xxxxx",
//             );
//
//
//             dbg!(provider.tip_hash().await.map(|s| s.serialize_hex()));
//             dbg!(provider.tip_height().await);
//             dbg!(
//                 provider.in_best_chain(
//                     BlockHash::deserialize_hex(
//                         &"26dc77c6d3c722e63bcd6de9725663714821cfa410f40a000000000000000000"
//                     ).unwrap()
//                 ).await
//             );
//             dbg!(
//                 provider.get_confs(
//                     TXID::from_be_hex("d0aeac56b3a1f3460e9a79c9aea21a7f81933e66126c6f479b5ca3d75280c515").unwrap()
//                 ).await
//             );
//
//             let tx = provider.get_tx(
//                 TXID::from_be_hex("d0aeac56b3a1f3460e9a79c9aea21a7f81933e66126c6f479b5ca3d75280c515").unwrap()
//             ).await
//              .unwrap()
//              .unwrap();
//
//             dbg!(&tx.serialize_hex());
//
//             dbg!(provider.broadcast(tx).await.unwrap().serialize_hex());
//             // let mut tips = provider
//             //     .tips(10)
//             //     .interval(Duration::from_secs(10));
//             //
//             // while let Some(next) = tips.next().await {
//             //     dbg!(next.serialize_hex());
//             // }
//         };
//         runtime::Runtime::new().unwrap().block_on(fut);
//     }
// }
