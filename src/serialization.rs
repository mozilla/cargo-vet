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

/// Inline arrays which have a representation longer than this will be rendered
/// over multiple lines.
const ARRAY_WRAP_THRESHOLD: usize = 80;

/// Tables which would be rendered inline (see `INLINE_TABLE_KEYS`) and have an
/// inline representation larger than this threshold will be rendered by
/// TomlFormatter as non-inline tables.
const INLINE_TABLE_THRESHOLD: usize = 120;

/// Names for tables which should be rendered inline by TomlFormatter unless
/// their inline representation exceeds `INLINE_TABLE_THRESHOLD`.
const INLINE_TABLE_KEYS: &[&str] = &["dependency-criteria"];

fn inline_length(key: &str, value: &toml_edit::Item) -> usize {
    // Length of the string " = " which will appear between the key and value.
    const DECORATION_LENGTH: usize = 3;

    // The `Display` implementation for toml_edit values will produce the final
    // serialized representation of the value in the TOML document, which we can
    // use to determine the line length in utf-8 characters.
    let value_repr = value.to_string();
    key.chars().count() + value_repr.chars().count() + DECORATION_LENGTH
}

/// Tables with these names will be rendered by TomlFormatter as inline tables,
/// rather than dotted tables unless their inline representation exceeds
/// `INLINE_TABLE_THRESHOLD` UTF-8 characters in length.
fn table_should_be_inline(key: &str, value: &toml_edit::Item) -> bool {
    if !INLINE_TABLE_KEYS.contains(&key) {
        return false;
    }
    inline_length(key, value) <= INLINE_TABLE_THRESHOLD
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
                if !table_should_be_inline(&k, v) {
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

                // If we didn't convert the array into an array of tables above,
                // check if it would be too long and wrap it onto multiple lines
                // if it would.
                if v.is_array() && inline_length(&k, v) > ARRAY_WRAP_THRESHOLD {
                    let array = v.as_array_mut().unwrap();
                    for item in array.iter_mut() {
                        item.decor_mut().set_prefix("\n    ");
                    }
                    array.set_trailing("\n");
                    array.set_trailing_comma(true);
                }

                self.visit_item_mut(v);
            }
        }
    }

    let mut toml_document = toml_edit::ser::to_document(&val)?;
    TomlFormatter.visit_document_mut(&mut toml_document);
    Ok(toml_document)
}

#[cfg(test)]
mod test {
    use crate::format::*;

    #[test]
    fn toml_formatter_wrapping() {
        let mut dc_long = SortedMap::new();
        dc_long.insert(
            "example-crate-1".to_owned(),
            vec![
                "criteria-one-very-long".to_owned(),
                "criteria-two-very-long".to_owned(),
            ],
        );
        dc_long.insert(
            "example-crate-2".to_owned(),
            vec![
                // This array would wrap over multiple lines if byte length was
                // used rather than utf-8 character length.
                "criteria-one-✨✨✨✨✨✨✨✨✨✨".to_owned(),
                "criteria-two-✨✨✨✨✨✨✨✨✨✨".to_owned(),
            ],
        );
        dc_long.insert(
            "example-crate-3".to_owned(),
            vec![
                "criteria-one-very-long".to_owned(),
                "criteria-two-very-long".to_owned(),
                "criteria-three-extremely-long-this-array-should-wrap".to_owned(),
            ],
        );

        let mut dc_short = SortedMap::new();
        dc_short.insert(
            "example-crate-1".to_owned(),
            vec!["criteria-one".to_owned()],
        );

        let mut audits = SortedMap::new();
        audits.insert(
            "test".to_owned(),
            vec![
                AuditEntry {
                    who: None,
                    criteria: vec!["long-criteria".to_owned()],
                    kind: AuditKind::Full {
                        version: "1.0.0".parse().unwrap(),
                        dependency_criteria: dc_long,
                    },
                    notes: Some("notes go here!".to_owned()),
                },
                AuditEntry {
                    who: None,
                    criteria: vec!["short-criteria".to_owned()],
                    kind: AuditKind::Full {
                        version: "1.0.0".parse().unwrap(),
                        dependency_criteria: dc_short,
                    },
                    notes: Some("notes go here!".to_owned()),
                },
            ],
        );

        let formatted = super::to_formatted_toml(AuditsFile {
            criteria: SortedMap::new(),
            audits,
        })
        .unwrap()
        .to_string();

        insta::assert_snapshot!("formatted_toml_long_inline", formatted);
    }
}
