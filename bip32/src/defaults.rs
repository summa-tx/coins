use serde::{ser::SerializeStruct, de::Visitor};

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

impl serde::Serialize for crate::DerivedXPriv {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("DerivedXPriv", 2)?;
        state.serialize_field("derivation", &self.derivation)?;
        state.serialize_field("xpriv", &self.xpriv)?;
        state.end()
    }
}

struct DerivedXPrivVisitor;

impl<'de> Visitor<'de> for DerivedXPrivVisitor {
    type Value = crate::DerivedXPriv;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("struct DerivedXPriv")
    }

    fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
    where
        V: serde::de::MapAccess<'de>
    {
        let mut xpriv = None;
        let mut derivation = None;

        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field { XPriv, Derivation }

        while let Some(key) = map.next_key()? {
            match key {
                Field::XPriv => {
                    if xpriv.is_some() {
                        return Err(serde::de::Error::duplicate_field("xpriv"));
                    }
                    xpriv = Some(map.next_value()?);
                }
                Field::Derivation => {
                    if derivation.is_some() {
                        return Err(serde::de::Error::duplicate_field("derivation"));
                    }
                    derivation = Some(map.next_value()?);
                }
            }
        }

        let xpriv = xpriv.ok_or_else(|| serde::de::Error::missing_field("xpriv"))?;
        let derivation = derivation.ok_or_else(|| serde::de::Error::missing_field("derivation"))?;

        Ok(crate::DerivedXPriv {
            xpriv,
            derivation,
        })
    }


}

impl<'de> serde::Deserialize<'de> for crate::DerivedXPriv {
    fn deserialize<D>(deserializer: D) -> Result<crate::DerivedXPriv, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["xpriv", "derivation"];
        deserializer.deserialize_struct("Duration", FIELDS, DerivedXPrivVisitor)
    }
}

impl serde::Serialize for crate::DerivedXPub {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("DerivedXPub", 2)?;
        state.serialize_field("derivation", &self.derivation)?;
        state.serialize_field("xpub", &self.xpub)?;
        state.end()
    }
}

struct DerivedXPubVisitor;

impl<'de> Visitor<'de> for DerivedXPubVisitor {
    type Value = crate::DerivedXPub;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("struct DerivedXPub")
    }

    fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
    where
        V: serde::de::MapAccess<'de>
    {
        let mut xpub = None;
        let mut derivation = None;

        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field { XPub, Derivation }

        while let Some(key) = map.next_key()? {
            match key {
                Field::XPub => {
                    if xpub.is_some() {
                        return Err(serde::de::Error::duplicate_field("xpub"));
                    }
                    xpub = Some(map.next_value()?);
                }
                Field::Derivation => {
                    if derivation.is_some() {
                        return Err(serde::de::Error::duplicate_field("derivation"));
                    }
                    derivation = Some(map.next_value()?);
                }
            }
        }

        let xpub = xpub.ok_or_else(|| serde::de::Error::missing_field("xpub"))?;
        let derivation = derivation.ok_or_else(|| serde::de::Error::missing_field("derivation"))?;

        Ok(crate::DerivedXPub {
            xpub,
            derivation,
        })
    }


}

impl<'de> serde::Deserialize<'de> for crate::DerivedXPub {
    fn deserialize<D>(deserializer: D) -> Result<crate::DerivedXPub, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["xpub", "derivation"];
        deserializer.deserialize_struct("Duration", FIELDS, DerivedXPubVisitor)
    }
}
