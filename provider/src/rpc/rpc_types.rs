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

/// The ScanTxOut paramaters
#[derive(serde::Serialize)]
pub struct ScanTxOutParams(pub String, pub Vec<String>);

/// The RPC UTXO in the `ScanTxOutResponse` struct
#[allow(non_snake_case)]
#[derive(serde::Deserialize)]
pub struct RPCUTXO {
    /// the id of the tx that created the utxo
    pub txid: String,
    /// the index of the utxo in the tx's vout
    pub vout: u32,
    /// the spk controlling the UTXO, in hex
    pub scriptPubKey: String,
    /// the utxo value
    pub amount: u64,
    /// the height of the UTXO
    pub height: usize,
}

/// The response for `scantxoutset` command
///
/// https://bitcoincore.org/en/doc/0.20.0/rpc/blockchain/scantxoutset/
#[derive(serde::Deserialize)]
pub struct ScanTxOutResponse {
    /// Whether the scan was completed
    pub success: bool,
    /// The hash of the tip at the scan
    pub bestblock: String,
    /// The unspent txns
    pub unspents: Vec<RPCUTXO>,
}
