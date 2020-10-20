use coins_core::enc::AddressEncoder;

#[cfg(feature = "mainnet")]
pub mod network {
    /// The default network, selected by feature flag
    pub type Net = crate::nets::BitcoinMainnet;
    /// The default encoder, selected by feature flag
    pub type Encoder = crate::enc::MainnetEncoder;
}

#[cfg(feature = "testnet")]
pub mod network {
    /// The default network, selected by feature flag
    pub type Net = crate::nets::BitcoinTestnet;
    /// The default encoder, selected by feature flag
    pub type Encoder = crate::enc::TestnetEncoder;
}

#[cfg(feature = "signet")]
pub mod network {
    /// The default network, selected by feature flag
    pub type Net = crate::nets::BitcoinSignet;
    /// The default encoder, selected by feature flag
    pub type Encoder = crate::enc::SignetEncoder;
}

impl std::str::FromStr for crate::enc::Address {
    type Err = <network::Encoder as AddressEncoder>::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        network::Encoder::string_to_address(s)
    }
}

impl std::str::FromStr for crate::types::ScriptPubkey {
    type Err = <network::Encoder as AddressEncoder>::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(network::Encoder::decode_address(&network::Encoder::string_to_address(s)?))
    }
}

impl serde::Serialize for crate::enc::Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}

impl<'de> serde::Deserialize<'de> for crate::enc::Address {
    fn deserialize<D>(deserializer: D) -> Result<crate::enc::Address, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: &str = serde::Deserialize::deserialize(deserializer)?;
        network::Encoder::string_to_address(s).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}
