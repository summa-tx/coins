use std::{
    convert::TryFrom,
    io::{Read, Write},
    iter::{FromIterator, IntoIterator},
    slice::Iter,
};

use riemann_core::ser::{Ser, SerError};

use crate::{primitives::KeyFingerprint, Bip32Error, BIP32_HARDEN};

fn try_parse_index(s: &str) -> Result<u32, Bip32Error> {
    let mut index_str = s.to_owned();
    let harden = if s.ends_with('\'') || s.ends_with('h') {
        index_str.pop();
        true
    } else {
        false
    };

    index_str
        .parse::<u32>()
        .map(|v| if harden { v + BIP32_HARDEN } else { v })
        .map_err(|_| Bip32Error::MalformattedIndex(s.to_owned()))
}

fn try_parse_path(path: &str) -> Result<Vec<u32>, Bip32Error> {
    path.to_owned()
        .split('/')
        .filter(|v| v != &"m")
        .map(try_parse_index)
        .collect::<Result<Vec<u32>, Bip32Error>>()
}

/// A Bip32 derivation path
#[derive(Default, Debug, Clone, Eq, PartialEq)]
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

    /// `true` if `other` is a prefix of `self`
    pub fn starts_with(&self, other: &Self) -> bool {
        self.0.starts_with(&other.0)
    }

    /// Remove a prefix from a derivation. Return a new DerivationPath without the prefix.
    /// This is useful for determining the path to rech some descendant from some ancestor.
    pub fn remove_prefix(&self, prefix: &Self) -> Option<DerivationPath> {
        if !self.starts_with(prefix) {
            None
        } else {
            Some(self.0[prefix.len()..].to_vec().into())
        }
    }

    /// Convenience function for finding the last hardened derivation in a path.
    /// Returns the index and the element. If there is no hardened derivation, it
    /// will return (0, None).
    pub fn last_hardened(&self) -> (usize, Option<u32>) {
        match self.iter().rev().position(|v| *v >= BIP32_HARDEN) {
            Some(rev_pos) => {
                let pos = self.len() - rev_pos - 1;
                (pos, Some(self.0[pos]))
            }
            None => (0, None),
        }
    }

    /// Append an additional derivation to the end, return a clone
    pub fn extended(&self, idx: u32) -> Self {
        let mut child = self.clone();
        child.0.push(idx);
        child
    }
}

impl From<&DerivationPath> for DerivationPath {
    fn from(v: &DerivationPath) -> Self {
        v.clone()
    }
}

impl From<Vec<u32>> for DerivationPath {
    fn from(v: Vec<u32>) -> Self {
        Self(v)
    }
}

impl From<&[u32]> for DerivationPath {
    fn from(v: &[u32]) -> Self {
        Self(Vec::from(v))
    }
}

impl FromIterator<u32> for DerivationPath {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = u32>,
    {
        Vec::from_iter(iter).into()
    }
}

impl TryFrom<&str> for DerivationPath {
    type Error = Bip32Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        try_parse_path(s).map(Into::into)
    }
}

/// A Derivation Path for a bip32 key
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeyDerivation {
    /// The root key fingerprint
    pub root: KeyFingerprint,
    /// The derivation path from the root key
    pub path: DerivationPath,
}

impl KeyDerivation {
    /// `true` if the keys share a root fingerprint, `false` otherwise. Note that on key
    /// fingerprints, which may collide accidentally, or be intentionally collided.
    pub fn same_root(&self, other: &Self) -> bool {
        self.root == other.root
    }

    /// `true` if this key is an ancestor of other, `false` otherwise. Note that on key
    /// fingerprints, which may collide accidentally, or be intentionally collided.
    pub fn is_possible_ancestor_of(&self, other: &Self) -> bool {
        self.same_root(other) && other.path.starts_with(&self.path)
    }

    /// Returns the path to the decendant.
    pub fn path_to_descendant(&self, descendant: &Self) -> Option<DerivationPath> {
        descendant.path.remove_prefix(&self.path)
    }

    /// Append an additional derivation to the end, return a clone
    pub fn extended(&self, idx: u32) -> Self {
        Self {
            root: self.root,
            path: self.path.extended(idx),
        }
    }
}

impl Ser for KeyDerivation {
    type Error = Bip32Error;

    fn to_json(&self) -> String {
        unimplemented!()
    }

    fn serialized_length(&self) -> usize {
        4 + 4 * self.path.len()
    }

    fn deserialize<T>(reader: &mut T, limit: usize) -> Result<Self, Self::Error>
    where
        T: Read,
        Self: std::marker::Sized,
    {
        if limit == 0 {
            return Err(SerError::RequiresLimit.into());
        }

        if limit > 255 {
            return Err(Bip32Error::InvalidBip32Path);
        }

        let mut finger = [0u8; 4];
        reader.read_exact(&mut finger)?;

        let mut path = vec![];
        for _ in 0..limit {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            path.push(u32::from_le_bytes(buf));
        }

        Ok(KeyDerivation {
            root: finger.into(),
            path: path.into(),
        })
    }

    fn serialize<T>(&self, writer: &mut T) -> Result<usize, Self::Error>
    where
        T: Write,
    {
        let mut length = writer.write(&self.root.0)?;
        for i in self.path.iter() {
            length += writer.write(&i.to_le_bytes())?;
        }
        Ok(length)
    }
}
