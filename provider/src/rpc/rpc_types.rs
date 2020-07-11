/// The params for getrawtransaction
#[derive(serde::Serialize)]
pub struct GetRawTxParams(pub String, pub usize);

/// The repsonse for the `getblock` command
///
/// https://bitcoincore.org/en/doc/0.20.0/rpc/blockchain/getblock/
#[derive(serde::Deserialize)]
pub struct GetBlockResponse {
    /// The blockhash
    pub hash: String,
    /// The block height
    pub height: usize,
    /// The number of confirmations the block has received. -1 for not main chain.
    pub confirmations: isize,
}

/// Response for the `gettransaction` command
///
/// https://bitcoincore.org/en/doc/0.20.0/rpc/rawtransactions/getrawtransaction/
#[derive(serde::Deserialize)]
pub struct GetRawTransactionResponse {
    /// The transaction ID in BE format
    pub txid: String,
    /// The hex-serialized transaction
    pub hex: String,
    /// The blockhash
    #[serde(default = "String::new")]
    pub blockhash: String,
    /// The number of confirmations the tx has received. -1 for unconfirmed
    pub confirmations: isize,
}
