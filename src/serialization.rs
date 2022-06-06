//! Serialization helpers

use core::fmt;
use serde::{
    de::{self, value, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

/// Serde handler to allow specifying any of [], "foo",
/// ["foo"], or ["foo", "bar"].
pub mod string_or_vec {
    use super::*;

    pub fn serialize<S>(v: &Vec<String>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if v.len() == 1 {
            s.serialize_str(&v[0])
        } else {
            v.serialize(s)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringOrVec;

        impl<'de> Visitor<'de> for StringOrVec {
            type Value = Vec<String>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("string or list of strings")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(vec![s.to_owned()])
            }

            fn visit_seq<S>(self, seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                Deserialize::deserialize(value::SeqAccessDeserializer::new(seq))
            }
        }

        deserializer.deserialize_any(StringOrVec)
    }
}
