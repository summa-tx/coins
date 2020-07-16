# rmn-btc-provider

This crate provides a generic chain-data API for Bitcoin apps. It aims to give
a simple consistent interface to chain data, so that wallets can easily support
a wide range of backends out of the box.

Apps that are generic over a `BTCProvider` can seamlessly accept different
sources. We have implemented a `BTCProvider` calling the Blockstream Esplora
API, and more options are coming.

The `PollingBTCProvider` trait can extend the `BTCProvider` with useful
functionality like a polling chain-tip stream, a pending tx that streams
confirmations, and a UTXO watcher that streams spend notifications.

## Usage example

```rust
use futures_core::stream::StreamExt;
use tokio::runtime;

use rmn_btc_provider::{
  BTCProvider,
  PollingBTCProvider,
  esplora::EsploraProvider
};

let fut = async move {
    // Defaults to blockstream.info/api/
    let provider = EsploraProvider::default();

    // Get a stream that emits the next 10 chain tips, polling every 10 seconds
    let mut tips = provider.tips(10).interval(Duration::from_secs(10));

    // Print each header as it comes in
    while let Some(next) = tips.next().await {
        dbg!(next.serialize_hex().unwrap());
    }
};

runtime::Runtime::new().unwrap().block_on(fut);
```
