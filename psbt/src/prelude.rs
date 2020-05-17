macro_rules! psbt_map {
    ($name:ident) => {
        /// A newtype wrapping a BTreeMap. Provides a simplified interface
        #[derive(PartialEq, Eq, Clone, Default, Debug, Ord, PartialOrd)]
        pub struct $name {
            map: std::collections::BTreeMap<PSBTKey, PSBTValue>,
        }

        impl crate::common::PSTMap for $name {
            /// Returns a reference to the value corresponding to the key.
            fn get(&self, key: &PSBTKey) -> Option<&PSBTValue> {
                self.map.get(key)
            }

            fn contains_key(&self, key: &PSBTKey) -> bool {
                self.map.contains_key(key)
            }

            fn remove(&mut self, key: &PSBTKey) -> Option<PSBTValue> {
                self.map.remove(key)
            }

            fn keys(&self) -> std::collections::btree_map::Keys<PSBTKey, PSBTValue> {
                self.map.keys()
            }

            fn range<R>(&self, range: R) -> std::collections::btree_map::Range<PSBTKey, PSBTValue>
            where
                R: std::ops::RangeBounds<PSBTKey>,
            {
                self.map.range(range)
            }

            /// Returns a mutable reference to the value corresponding to the key.
            fn get_mut(&mut self, key: &PSBTKey) -> Option<&mut PSBTValue> {
                self.map.get_mut(key)
            }

            /// Gets an iterator over the entries of the map, sorted by key.
            fn iter(&self) -> std::collections::btree_map::Iter<PSBTKey, PSBTValue> {
                self.map.iter()
            }

            /// Gets a mutable iterator over the entries of the map, sorted by key
            fn iter_mut(&mut self) -> std::collections::btree_map::IterMut<PSBTKey, PSBTValue> {
                self.map.iter_mut()
            }

            /// Gets an iterator over the entries of the map, sorted by key.
            fn insert(&mut self, key: PSBTKey, value: PSBTValue) -> Option<PSBTValue> {
                self.map.insert(key, value)
            }
        }

        impl riemann_core::ser::ByteFormat for $name {
            type Error = PSBTError;

            fn serialized_length(&self) -> usize {
                let kv_length: usize = self
                    .iter()
                    .map(|(k, v)| k.serialized_length() + v.serialized_length())
                    .sum();
                kv_length + 1 // terminates in a 0 byte (null key)
            }

            fn read_from<R>(reader: &mut R, _limit: usize) -> Result<Self, crate::common::PSBTError>
            where
                R: std::io::Read,
                Self: std::marker::Sized,
            {
                let mut map = Self {
                    map: BTreeMap::default(),
                };

                loop {
                    let key = PSBTKey::read_from(reader, 0)?;
                    if map.contains_key(&key) {
                        return Err(crate::common::PSBTError::DuplicateKey(key));
                    }
                    if key.len() == 0 {
                        break;
                    }
                    let value = PSBTValue::read_from(reader, 0)?;
                    map.insert(key, value);
                }
                Ok(map)
            }

            fn write_to<W>(&self, writer: &mut W) -> Result<usize, crate::common::PSBTError>
            where
                W: std::io::Write,
            {
                let mut length: usize = 0;
                for (k, v) in self.iter() {
                    length += k.write_to(writer)?;
                    length += v.write_to(writer)?;
                }
                length += (0u8).write_to(writer)?;
                Ok(length)
            }
        }
    };
}
