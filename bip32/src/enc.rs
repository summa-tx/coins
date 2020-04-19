use crate::xkeys::{Hint, XKey, XPriv, XPub};

// TODO: BIP49 and BIP84

/// Contains network-specific serialization information
pub trait NetworkParams {
    /// The Bip32 privkey version bytes
    const PRIV_VERSION: u32;
    /// The Bip49 privkey version bytes
    const BIP49_PRIV_VERSION: u32;
    /// The Bip84 pubkey version bytes
    const BIP84_PRIV_VERSION: u32;
    /// The Bip32 pubkey version bytes
    const PUB_VERSION: u32;
    /// The Bip49 pubkey version bytes
    const BIP49_PUB_VERSION: u32;
    /// The Bip84 pubkey version bytes
    const BIP84_PUB_VERSION: u32;
}

/// Bip32/49/84 encoder
pub trait Encoder<P: NetworkParams> {
    #[doc(hidden)]
    fn write_key_details<K, W>(writer: &mut W, key: &K) -> Result<usize, std::io::Error>
    where
        K: XKey,
        W: std::io::Write
    {
        let mut written = writer.write(&[key.depth()])?;
        written += writer.write(&key.parent().0)?;
        written += writer.write(&key.index().to_be_bytes())?;
        written += writer.write(&key.chain_code().0)?;
        Ok(written)
    }

    /// Serialize the xpub to `std::io::Write`
    fn write_xpub<W>(writer: &mut W, key: &XPub) -> Result<usize, std::io::Error>
    where
        W: std::io::Write
    {
        let version = match key.hint() {
            Hint::Legacy => P::PUB_VERSION,
            Hint::Compatibility => P::BIP49_PUB_VERSION,
            Hint::SegWit => P::BIP84_PUB_VERSION,
        };
        let mut written = writer.write(&version.to_be_bytes())?;
        written += Self::write_key_details(writer, key)?;
        written += writer.write(&key.compressed_pubkey())?;
        Ok(written)
    }

    /// Serialize the xpriv to `std::io::Write`
    fn write_xpriv<W>(writer: &mut W, key: &XPriv) -> Result<usize, std::io::Error>
    where
        W: std::io::Write
    {
        let version = match key.hint() {
            Hint::Legacy => P::PRIV_VERSION,
            Hint::Compatibility => P::BIP49_PRIV_VERSION,
            Hint::SegWit => P::BIP84_PRIV_VERSION,
        };
        let mut written = writer.write(&version.to_be_bytes())?;
        written += Self::write_key_details(writer, key)?;
        written += writer.write(&[0])?;
        written += writer.write(&key.secret_key())?;
        Ok(written)
    }
}

macro_rules! params {
    (
        $(#[$outer:meta])*
        $name:ident{
            bip32: $bip32:expr,
            bip49: $bip49:expr,
            bip84: $bip84:expr,
            bip32_pub: $bip32pub:expr,
            bip49_pub: $bip49pub:expr,
            bip84_pub: $bip84pub:expr
        }
    ) => {
        $(#[$outer])*
        pub struct $name;

        impl NetworkParams for $name {
            const PRIV_VERSION: u32 = $bip32;
            const BIP49_PRIV_VERSION: u32 = $bip49;
            const BIP84_PRIV_VERSION: u32 = $bip84;
            const PUB_VERSION: u32 = $bip32pub;
            const BIP49_PUB_VERSION: u32 = $bip49pub;
            const BIP84_PUB_VERSION: u32 = $bip84pub;
        }
    }
}

params!(
    /// Mainnet encoding param
    Main{
        bip32: 0x0488_ADE4,
        bip49: 0x049d_7878,
        bip84: 0x04b2_430c,
        bip32_pub: 0x0488_B21E,
        bip49_pub: 0x049d_7cb2,
        bip84_pub: 0x04b2_4746
    }
);

params!(
    /// Testnet encoding param
    Test{
        bip32: 0x0435_8394,
        bip49: 0x044a_4e28,
        bip84: 0x045f_18bc,
        bip32_pub: 0x0435_87CF,
        bip49_pub: 0x044a_5262,
        bip84_pub: 0x045f_1cf6
    }
);
