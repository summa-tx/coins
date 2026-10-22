use std::fmt;

/// A Ledger hardware model.
///
/// Over USB the product ID identifies it: the high byte names the model,
/// except on old firmware where the whole ID is a small legacy code. Other
/// transports may identify models their own way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Model {
    /// Ledger Blue.
    Blue,
    /// Ledger Nano S.
    NanoS,
    /// Ledger Nano X.
    NanoX,
    /// Ledger Nano S Plus.
    NanoSPlus,
    /// Ledger Stax.
    Stax,
    /// Ledger Flex.
    Flex,
    /// A product ID this crate does not know. Carries the whole ID.
    Unknown(u16),
}

impl Model {
    /// Identify a model from its USB product ID.
    pub const fn from_product_id(product_id: u16) -> Self {
        match product_id {
            // Legacy codes from firmware before the high-byte scheme.
            0x0000 => Self::Blue,
            0x0001 => Self::NanoS,
            0x0004 => Self::NanoX,
            0x0005 => Self::NanoSPlus,
            0x0006 => Self::Stax,
            0x0007 => Self::Flex,
            _ => match product_id >> 8 {
                0x00 => Self::Blue,
                0x10 => Self::NanoS,
                0x40 => Self::NanoX,
                0x50 => Self::NanoSPlus,
                0x60 => Self::Stax,
                0x70 => Self::Flex,
                _ => Self::Unknown(product_id),
            },
        }
    }
}

impl fmt::Display for Model {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blue => f.write_str("Blue"),
            Self::NanoS => f.write_str("Nano S"),
            Self::NanoX => f.write_str("Nano X"),
            Self::NanoSPlus => f.write_str("Nano S Plus"),
            Self::Stax => f.write_str("Stax"),
            Self::Flex => f.write_str("Flex"),
            Self::Unknown(id) => write!(f, "unknown model {id:#06x}"),
        }
    }
}

#[cfg(test)]
#[path = "../ai-tests/model.rs"]
mod ai_tests;
