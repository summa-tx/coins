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

    let t = T::deserialize::<&mut Deserializer>(&mut deserializer)?;
    if deserializer.location == deserializer.input.len() {
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
    // type Error = Error;

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!("Type not needed in bitcoin txns")
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        match self.peek()? {
            0 => {
                self.location += 2;
                visitor.visit_bool(true)
            }
            _ => visitor.visit_bool(false)
        }
    }

    fn deserialize_i8<V>(self, _visitor: V) -> Result<V::Value>
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

    fn deserialize_i32<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!("Type not needed in bitcoin txns")
    }

    fn deserialize_i64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!("Type not needed in bitcoin txns")
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u8(self.next()?)
    }

    fn deserialize_u16<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!("Type not needed in bitcoin txns")
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.next_chunk(4)?);
        visitor.visit_u32(u32::from_le_bytes(buf))
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.next_chunk(8)?);
        visitor.visit_u64(u64::from_le_bytes(buf))
    }

    fn deserialize_f32<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!("Type not needed in bitcoin txns")
    }

    fn deserialize_f64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!("Type not needed in bitcoin txns")
    }

    fn deserialize_char<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!("Type not needed in bitcoin txns")
    }

    fn deserialize_str<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!("Type not needed in bitcoin txns")
    }

    fn deserialize_string<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!("Type not needed in bitcoin txns")
    }

    fn deserialize_bytes<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!("Type not needed in bitcoin txns")
    }

    fn deserialize_byte_buf<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!("Type not needed in bitcoin txns")
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // Invoked by flag and scriptsig
        match self.peek()? {
            0 => visitor.visit_none(),
            _ => visitor.visit_some(self)
        }
    }
    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!("Type not needed in bitcoin txns")
    }

    fn deserialize_unit_struct<V>(
          self,
          _name: &'static str,
          visitor: V,
    ) -> Result<V::Value>
    where
      V: Visitor<'de>,
    {
      unimplemented!("Type not needed in bitcoin txns")
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!("Type not needed in bitcoin txns")
    }

    fn deserialize_seq<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let value = visitor.visit_seq()?;
        Ok(value)
    }
}
