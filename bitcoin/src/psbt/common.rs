use std::{
    collections::{
        BTreeMap,
        btree_map::{Iter, IterMut},
    },
    io::{Read, Write},
    ops::{Index, IndexMut},
};

use riemann_core::{
    ser::{Ser},
    types::{
        primitives::{ConcretePrefixVec, PrefixVec},
    },
};

use crate::psbt::{PSBTError};

wrap_prefixed_byte_vector!(
    /// A PSBT Key
    PSBTKey
);

wrap_prefixed_byte_vector!(
    /// A PSBT Value
    PSBTValue
);

impl PSBTKey {
    /// The BIP174 type of the key (its first byte)
    pub fn key_type(&self) -> u8 {
        self[0]
    }
}

/// A newtype wrapping a BTreeMap. Provides a simplified interface
pub struct PSBTMap{
    tree: BTreeMap<PSBTKey, PSBTValue>,
}

impl PSBTMap {
    /// Returns a reference to the value corresponding to the key.
    pub fn get(&self, key: &PSBTKey) -> Option<&PSBTValue> {
        self.tree.get(key)
    }

    /// Returns a mutable reference to the value corresponding to the key.
    pub fn get_mut(&mut self, key: &PSBTKey) -> Option<&mut PSBTValue> {
        self.tree.get_mut(key)
    }

    /// Gets an iterator over the entries of the map, sorted by key.
    pub fn iter(&self) -> Iter<PSBTKey, PSBTValue> {
        self.tree.iter()
    }

    /// Gets a mutable iterator over the entries of the map, sorted by key
    pub fn iter_mut(&mut self) -> IterMut<PSBTKey, PSBTValue> {
        self.tree.iter_mut()
    }

    /// Gets an iterator over the entries of the map, sorted by key.
    pub fn insert(&mut self, key: PSBTKey, value: PSBTValue) -> Option<PSBTValue> {
        self.tree.insert(key, value)
    }
}

impl Ser for PSBTMap {
    type Error = PSBTError;

    fn to_json(&self) -> String {
        unimplemented!("TODO")
    }

    fn serialized_length(&self) -> usize {
        let kv_length: usize = self.iter()
            .map(|(k, v)| k.serialized_length() + v.serialized_length())
            .sum();
        kv_length + 1  // terminates in a 0 byte (null key)
    }

    fn deserialize<R>(reader: &mut R, _limit: usize) -> Result<Self, PSBTError>
    where
        R: Read,
        Self: std::marker::Sized
    {
        let mut map = PSBTMap{
            tree: BTreeMap::default()
        };

        loop {
            let key = PSBTKey::deserialize(reader, 0)?;
            if key.len() == 0 {
                break;
            }
            let value = PSBTValue::deserialize(reader, 0)?;
            map.insert(key, value);
        }
        Ok(map)
    }

    fn serialize<W>(&self, writer: &mut W) -> Result<usize, PSBTError>
    where
        W: Write
    {
        let mut length: usize = 0;
        for (k, v) in self.iter() {
            length += k.serialize(writer)?;
            length += v.serialize(writer)?;
        }
        length += (0u8).serialize(writer)?;
        Ok(length)
    }
}
