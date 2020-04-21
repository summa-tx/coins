use std::{
    convert::{TryFrom},
    iter::{FromIterator, IntoIterator},
    slice::{Iter},
};

use crate::{Bip32Error, BIP32_HARDEN};

fn try_parse_index(s: &str) -> Result<u32, Bip32Error> {
    let mut index_str = s.to_owned();
    let harden = if s.ends_with('\'') || s.ends_with('h') {
        index_str.pop();
        true
    } else {
        false
    };

    index_str.parse::<u32>()
        .map(|v| if harden { v + BIP32_HARDEN } else { v })
        .map_err(|_| Bip32Error::MalformattedIndex(s.to_owned()))
}

fn try_parse_path(path: &str) -> Result<DerivationPath, Bip32Error> {
    path.to_owned()
        .split('/')
        .filter(|v| v != &"m")
        .map(try_parse_index)
        .collect::<Result<Vec<u32>, Bip32Error>>()
        .map(Into::into)
}

/// A Bip32 derivation path
pub struct DerivationPath(Vec<u32>);

impl DerivationPath {
    /// Returns `True` if there are no indices in the path
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The number of derivations in the path
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Make an iterator over the path indices
    pub fn iter(&self) -> Iter<u32> {
        self.0.iter()
    }
}

impl From<Vec<u32>> for DerivationPath {
    fn from(v: Vec<u32>) -> Self {
        Self(v)
    }
}

impl From<&[u32]> for DerivationPath {
    fn from(v: &[u32]) -> Self {
        Self(v.to_owned())
    }
}

impl TryFrom<&str> for DerivationPath {
    type Error = Bip32Error;

   fn try_from(s: &str) -> Result<Self, Self::Error> {
       try_parse_path(s)
   }
}

impl FromIterator<u32> for DerivationPath
{
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = u32>
    {
        Vec::from_iter(iter).into()
    }
}
