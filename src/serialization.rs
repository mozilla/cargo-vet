//! Serialization helpers

use crate::format::{DependencyCriteria, SortedMap};
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

/// Similar to the above, but distinguishes an empty list from an absent one.
///
/// Fields using these handlers must be annotated with #[serde(default)]
pub mod string_or_vec_or_none {
    use super::*;

    pub fn serialize<S>(maybe_v: &Option<Vec<String>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(v) = maybe_v {
            string_or_vec::serialize(v, s)
        } else {
            s.serialize_none()
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        // If the value isn't present in the stream, this deserializer won't be
        // invoked at all and the #[serde(default)] will result in `None`.
        string_or_vec::deserialize(deserializer).map(Some)
    }
}

/// Allows the Vec<String> map value in dependency-criteria to support string_or_vec semantics.
pub mod dependency_criteria {
    use crate::format::{CriteriaName, PackageName};

    use super::*;
    #[derive(Serialize, Deserialize)]
    struct Wrapper(#[serde(with = "string_or_vec")] Vec<CriteriaName>);

    pub fn serialize<S>(c: &DependencyCriteria, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let m: SortedMap<PackageName, Wrapper> = c
            .iter()
            .map(|(k, v)| (k.clone(), Wrapper(v.clone())))
            .collect();
        m.serialize(s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DependencyCriteria, D::Error>
    where
        D: Deserializer<'de>,
    {
        let m: SortedMap<PackageName, Wrapper> = SortedMap::deserialize(deserializer)?;
        Ok(m.into_iter().map(|(k, Wrapper(v))| (k, v)).collect())
    }
}

/// tables with these names will be rendered by TomlFormatter as inline tables,
/// rather than dotted tables.
fn always_render_inline(key: &str) -> bool {
    key == "dependency-criteria"
}

/// Serialize the given data structure as a formatted `toml_edit::Document`.
///
/// The returned document can be converted to a string or otherwise written out
/// using it's `Display` implementation.
///
/// Can fail if `T`'s implementation of `Serialize` fails.
pub fn to_formatted_toml<T>(val: T) -> Result<toml_edit::Document, toml_edit::ser::Error>
where
    T: Serialize,
{
    use toml_edit::visit_mut::VisitMut;

    struct TomlFormatter;
    impl VisitMut for TomlFormatter {
        fn visit_table_mut(&mut self, node: &mut toml_edit::Table) {
            // Hide unnecessary implicit table headers for tables containing
            // only other tables. We don't do this for empty tables as otherwise
            // they could be hidden.
            if !node.is_empty() {
                node.set_implicit(true);
            }
            for (k, v) in node.iter_mut() {
                if !always_render_inline(&k) {
                    // Try to convert the value into either a table or an array of
                    // tables if it is currently an inline table or inline array of
                    // tables.
                    *v = std::mem::take(v)
                        .into_table()
                        .map(toml_edit::Item::Table)
                        .unwrap_or_else(|i| i)
                        .into_array_of_tables()
                        .map(toml_edit::Item::ArrayOfTables)
                        .unwrap_or_else(|i| i);
                }
                self.visit_item_mut(v);
            }
        }
    }

    let mut toml_document = toml_edit::ser::to_document(&val)?;
    TomlFormatter.visit_document_mut(&mut toml_document);
    Ok(toml_document)
}
