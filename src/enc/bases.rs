use bech32::{Error as FromBase32Error, FromBase32, ToBase32};
use base58::{/* FromBase58Error, FromBase58, */ ToBase58};

static BECH_HRP: &str = "bc1";


pub fn base58_encode<T>(v: T) -> String
where
    T: ToBase58
{
    v.to_base58()
}

// pub fn base58_decode<T>(encoded: String) -> Result<T, FromBase58Error>
// where
//     T: FromBase58
// {
//
// }

pub fn bech32_encode<T>(v: T) -> String
where
    T: ToBase32
{
    bech32::encode(BECH_HRP, v.to_base32()).unwrap()
}

pub fn bech32_decode<T>(encoded: String) -> Result<T, FromBase32Error>
where
    T: FromBase32
{
    let (hrp, data) = bech32::decode(&encoded)?;
    if hrp != "bc1" {
        return Err(FromBase32Error::MissingSeparator);
    }
    T::from_base32(&data).map_err(|_| FromBase32Error::InvalidPadding)
}
