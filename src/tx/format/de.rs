use serde::Deserialize;
use serde::de::{
    self, Visitor
};

use super::error::{Error, Result};

pub struct Deserializer<'de> {
    input: &'de Vec<u8>,
    location: usize
}

impl<'de> Deserializer<'de> {
    pub fn from_bytes(input: &'de Vec<u8>) -> Self {
        Deserializer { input, location: 0 }
    }
}

pub fn from_bytes<'a, T>(s: &'a Vec<u8>) -> Result<T>
where
    T: Deserialize<'a>,
{
    let mut deserializer = Deserializer::from_bytes(s);

    let t = T::deserialize(&mut deserializer)?;
    if deserializer.input.is_empty() {
        Ok(t)
    } else {
        Err(Error::TrailingBytes)
    }
}

impl<'de> Deserializer<'de> {
    fn peek(&mut self) -> Result<u8> {
        self.input.get(self.location).ok_or(Error::EndOfInput).map(|v| *v)
    }

    fn next(&mut self) -> Result<u8> {
        let next = self.peek()?;
        self.location += 1;
        Ok(next)
    }

    fn next_chunk(&mut self, number: usize) -> Result<Vec<u8>> {
        let chunk = self.input[self.location..self.location+number].to_vec();
        self.location += number;
        Ok(chunk)
    }
}


impl<'de, 'a> de::Deserializer<'de> for &'a mut Deserializer<'de> {
    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!("Type not needed in bitcoin txns")
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!("Type not needed in bitcoin txns")
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!("Type not needed in bitcoin txns")
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!("Type not needed in bitcoin txns")
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!("Type not needed in bitcoin txns")
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!("Type not needed in bitcoin txns")
    }
}
