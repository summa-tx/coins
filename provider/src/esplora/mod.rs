mod types;

use types::*;

use crate::reqwest_utils::*;

use async_trait::async_trait;
use std::time::Duration;

use riemann_core::prelude::*;
use rmn_btc::prelude::*;

use crate::provider::{BTCProvider, PollingBTCProvider, ProviderError};

#[cfg(feature = "mainnet")]
static BLOCKSTREAM: &str = "https://blockstream.info/api";

#[cfg(feature = "testnet")]
static BLOCKSTREAM: &str = "https://blockstream.info/testnet/api";

/// A Provider that uses the Esplora API and caches some responses
#[derive(Debug)]
pub struct EsploraProvider {
    interval: std::time::Duration,
    api_root: String,
    client: reqwest::Client,
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
            interval: crate::DEFAULT_POLL_INTERVAL,
            api_root: api_root.to_owned(),
            client: Default::default(),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl BTCProvider for EsploraProvider {
    async fn tip_hash(&self) -> Result<BlockHash, ProviderError> {
        let url = format!("{}/blocks/tip/hash", self.api_root);
        let response = ez_fetch_string(&self.client, &url).await?;
        Ok(BlockHash::from_be_hex(&response)?)
    }

    async fn tip_height(&self) -> Result<usize, ProviderError> {
        let url = format!("{}/blocks/tip/height", self.api_root);
        let response = ez_fetch_string(&self.client, &url).await?;
        Ok(response.parse().unwrap())
    }

    async fn in_best_chain(&self, digest: BlockHash) -> Result<bool, ProviderError> {
        Ok(
            BlockStatus::fetch_by_digest(&self.client, &self.api_root, digest)
                .await?
                .in_best_chain,
        )
    }

    // TODO: rewrite to not make O(2 * n) requests using the /blocks/ endpoint
    async fn get_raw_header_range(
        &self,
        start: usize,
        headers: usize,
    ) -> Result<Vec<RawHeader>, ProviderError> {
        let digests = self.get_digest_range(start, headers).await?;
        let mut h = vec![];
        for digest in digests.into_iter() {
            if let Some(header) = self.get_raw_header(digest).await? {
                h.push(header);
            } else {
                break;
            }
        }
        Ok(h)
    }

    // TODO: rewrite to not make O(n) requests using the /blocks/ endpoint
    async fn get_digest_range(
        &self,
        start: usize,
        headers: usize,
    ) -> Result<Vec<BlockHash>, ProviderError> {
        let mut h = vec![];
        for i in 0..headers {
            let url = format!("{}/block-height/{}", self.api_root, start + i);
            h.push(BlockHash::from_be_hex(
                &ez_fetch_string(&self.client, &url).await?,
            )?);
        }

        Ok(h)
    }

    async fn get_raw_header(&self, digest: BlockHash) -> Result<Option<RawHeader>, ProviderError> {
        let header = none_if_unparsable!(EsploraBlock::fetch_by_digest(&self.client, &self.api_root, digest).await);
        Ok(Some(header.serialize()))
    }

    async fn get_height_of(&self, digest: BlockHash) -> Result<Option<usize>, ProviderError> {
        let block = none_if_unparsable!(EsploraBlock::fetch_by_digest(&self.client, &self.api_root, digest).await);
        Ok(Some(block.height))
    }

    async fn get_confirmed_height(&self, txid: TXID) -> Result<Option<usize>, ProviderError> {
        let tx = none_if_unparsable!(EsploraTxStatus::fetch_by_txid(&self.client, &self.api_root, txid).await);
        Ok(Some(tx.block_height))
    }

    async fn get_confs(&self, txid: TXID) -> Result<Option<usize>, ProviderError> {
        let tx = none_if_unparsable!(EsploraTx::fetch_by_txid(&self.client, &self.api_root, txid).await);

        if !tx.status.confirmed { return Ok(Some(0)); }
        let digest = BlockHash::from_be_hex(&tx.status.block_hash)
            .expect("No bad hex in API response");
        if !self.in_best_chain(digest).await? { return Ok(Some(0)); }
        let height = self.tip_height().await?;
        Ok(Some(height - tx.status.block_height + 1))

    }

    async fn get_tx(&self, txid: TXID) -> Result<Option<BitcoinTx>, ProviderError> {
        let tx_hex = fetch_tx_hex_by_id(&self.client, &self.api_root, txid).await?;
        if let Ok(tx) = BitcoinTx::deserialize_hex(&tx_hex) {
            Ok(Some(tx))
        } else {
            Ok(None)
        }
    }

    async fn broadcast(&self, tx: BitcoinTx) -> Result<TXID, ProviderError> {
        let url = format!("{}/tx", self.api_root);
        let response = post_hex(&self.client, &url, tx.serialize_hex()).await?;
        Ok(TXID::deserialize_hex(&response)?)
    }

    async fn get_outspend(&self, outpoint: BitcoinOutpoint) -> Result<Option<TXID>, ProviderError> {
        let outspend_opt =
            Outspend::fetch_by_outpoint(&self.client, &self.api_root, &outpoint).await?;

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

    async fn get_utxos_by_address(&self, address: &Address) -> Result<Vec<UTXO>, ProviderError> {
        let res: Result<Vec<_>, _> =
            EsploraUTXO::fetch_by_address(&self.client, &self.api_root, address)
                .await?
                .into_iter()
                .map(|e| e.into_utxo(address))
                .collect();
        Ok(res?)
    }

    async fn get_merkle(
        &self,
        txid: TXID,
    ) -> Result<Option<(usize, Vec<Hash256Digest>)>, ProviderError> {
        let proof_res = MerkleProof::fetch_by_txid(&self.client, &self.api_root, txid).await;
        match proof_res {
            Ok(proof) => {
                let ids = proof
                    .merkle
                    .iter()
                    .map(|s| {
                        TXID::from_be_hex(&s)
                            .expect("No malformed txids in api response")
                            .internal()
                    })
                    .collect();
                Ok(Some((proof.pos, ids)))
            }
            Err(FetchError::SerdeError(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl PollingBTCProvider for EsploraProvider {
    fn interval(&self) -> Duration {
        self.interval
    }

    fn set_interval(&mut self, interval: usize) {
        self.interval = Duration::from_secs(interval as u64);
    }
}

#[cfg(test)]
mod test {
    // use super::*;
    // use futures_core::stream::StreamExt;
    // use tokio::runtime;
    //
    // // runs against live API. leave commented
    // #[test]
    // fn it_prints_headers() {
    //     let fut = async move {
    //         let provider = EsploraProvider::default();
    //         let mut tips = provider.tips(10).interval(Duration::from_secs(10));
    //
    //         while let Some(next) = tips.next().await {
    //             dbg!(next.serialize_hex().unwrap());
    //         }
    //     };
    //
    //     runtime::Runtime::new().unwrap().block_on(fut);
    // }
}
