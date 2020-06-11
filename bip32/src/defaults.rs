use crate::enc::XKeyEncoder;

/// The default encoder, selected by feature flag
#[cfg(feature = "mainnet")]
pub type Encoder = crate::enc::MainnetEncoder;

/// The default encoder, selected by feature flag
#[cfg(feature = "testnet")]
pub type Encoder = crate::enc::TestnetEncoder;

impl serde::Serialize for crate::XPub {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded =
            Encoder::xpub_to_base58(self).map_err(|e| serde::ser::Error::custom(e.to_string()))?;
        serializer.serialize_str(&encoded)
    }
}

impl<'de> serde::Deserialize<'de> for crate::XPub {
    fn deserialize<D>(deserializer: D) -> Result<crate::XPub, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: &str = serde::Deserialize::deserialize(deserializer)?;
        Encoder::xpub_from_base58(s, Some(crate::Secp256k1::static_ref()))
            .map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

impl serde::Serialize for crate::XPriv {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded =
            Encoder::xpriv_to_base58(self).map_err(|e| serde::ser::Error::custom(e.to_string()))?;
        serializer.serialize_str(&encoded)
    }
}

impl<'de> serde::Deserialize<'de> for crate::XPriv {
    fn deserialize<D>(deserializer: D) -> Result<crate::XPriv, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: &str = serde::Deserialize::deserialize(deserializer)?;
        Encoder::xpriv_from_base58(s, Some(crate::Secp256k1::static_ref()))
            .map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}
