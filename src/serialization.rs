//! Serialization helpers

use crate::format::{DependencyCriteria, SortedMap};
use core::fmt;
use serde::{
    de::{self, value, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use spanned::Spanned;

/// Serde handler to allow specifying any of [], "foo", ["foo"], or ["foo", "bar"],
/// with the strings getting proper toml spans from the original source. Specifically,
/// we deserialize `Vec<Spanned<String>>`.
///
/// This needs to solve three problems:
///
/// 1. Getting spans from toml deserialization, in general
/// 2. Being able to take two very different inputs and squish them into one form
/// 3. Wiring the span machinery into that process
///
/// Problem 1 is solved by toml-rs having a [Spanned] type for this exact thing.
/// It's genuinely magic in that the deserializer just checks if it's deserializing
/// a struct with its exact magic field names and then emits two extra values for the span.
/// We fork the actual Spanned type here to make it more ergonomic/transparent
///
/// Problem 2 is solved by [string_or_vec_inner], which is based on an example in serde's
/// own docs. We create a custom visitor that can be visited with either a sequence or
/// a string. In the sequence case we just do a normal deserialization of our target.
/// In the string case we create a new Vec to wrap our string.
///
/// Problem 3 is where things get messy. Our solution to Problem 2 naturally gets spanned
/// for the sequence case, but in the string case we're "too late" to request spanning,
/// as we no longer have a deserializer, just a `str`. All we can do is emit a dummy Spanned.
///
/// Our solution to this is to recognize that in this case we have an array of one element,
/// and so a span over the entire array is just as good as a span over the element.
/// So we deserialize a `Spanned<Vec<Spanned<String>>>` and if the Vec has `len == 1`,
/// we edit the dummy inner span to equal the outer span. We then just discard the outer span
/// (or we could keep it if we decide that's useful later).
///
/// To make this a bit easier to do, we wrap Problem 2's solution in a `StringOrVec` struct,
/// deserialize `Spanned<StringOrVec>`, and then transform that into `Vec<Spanned<String>>`
pub mod string_or_vec {
    use super::*;

    /// A type using string_or_vec_inner to make it easy to wrap in Spanned.
    #[derive(Serialize, Deserialize)]
    pub struct StringOrVec(
        #[serde(default)]
        #[serde(with = "string_or_vec_inner")]
        pub Vec<Spanned<String>>,
    );

    pub fn serialize<S>(v: &Vec<Spanned<String>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if v.len() == 1 {
            s.serialize_str(&v[0])
        } else {
            v.serialize(s)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Spanned<String>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Get a Spanned<StringOrVec> and then use it to fixup a dummy span for len == 1
        let spanned_vec = Spanned::<StringOrVec>::deserialize(deserializer)?;
        let start = Spanned::start(&spanned_vec);
        let end = Spanned::end(&spanned_vec);
        let mut vec = Spanned::into_inner(spanned_vec).0;
        if vec.len() == 1 {
            Spanned::update_span(&mut vec[0], start, end);
        }
        Ok(vec)
    }
}

/// See [string_or_vec]
pub mod string_or_vec_inner {
    use super::*;

    pub fn serialize<S>(v: &Vec<Spanned<String>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if v.len() == 1 {
            s.serialize_str(&v[0])
        } else {
            v.serialize(s)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Spanned<String>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringOrVec;

        impl<'de> Visitor<'de> for StringOrVec {
            type Value = Vec<Spanned<String>>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("string or list of strings")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(vec![Spanned::from(s.to_owned())])
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

    pub fn serialize<S>(maybe_v: &Option<Vec<Spanned<String>>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(v) = maybe_v {
            string_or_vec::serialize(v, s)
        } else {
            s.serialize_none()
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<Spanned<String>>>, D::Error>
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
    struct Wrapper(#[serde(with = "string_or_vec")] Vec<Spanned<CriteriaName>>);

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
        let m = SortedMap::<PackageName, Wrapper>::deserialize(deserializer)?;
        Ok(m.into_iter().map(|(k, v)| (k, v.0)).collect())
    }
}

pub mod audit {
    use super::*;

    use crate::format::{
        AuditEntry, AuditKind, CriteriaName, Delta, DependencyCriteria, VersionReq,
    };
    use cargo_metadata::Version;

    #[derive(Serialize, Deserialize)]
    pub struct AuditEntryAll {
        who: Option<String>,
        #[serde(default)]
        #[serde(with = "string_or_vec")]
        criteria: Vec<Spanned<CriteriaName>>,
        version: Option<Version>,
        delta: Option<Delta>,
        violation: Option<VersionReq>,
        #[serde(rename = "dependency-criteria")]
        #[serde(skip_serializing_if = "DependencyCriteria::is_empty")]
        #[serde(with = "dependency_criteria")]
        #[serde(default)]
        dependency_criteria: DependencyCriteria,
        notes: Option<String>,
    }

    impl TryFrom<AuditEntryAll> for AuditEntry {
        type Error = String;
        fn try_from(val: AuditEntryAll) -> Result<AuditEntry, Self::Error> {
            let kind = match (val.version, val.delta, val.violation) {
                (Some(version), None, None) => Ok(AuditKind::Full {
                    version,
                    dependency_criteria: val.dependency_criteria,
                }),
                (None, Some(delta), None) => Ok(AuditKind::Delta {
                    delta,
                    dependency_criteria: val.dependency_criteria,
                }),
                (None, None, Some(violation)) => {
                    if val.dependency_criteria.is_empty() {
                        Ok(AuditKind::Violation { violation })
                    } else {
                        Err("'violation' can't have dependency_criteria".to_string())
                    }
                }
                _ => Err(
                    "audit entires must have exactly one of 'version', 'delta', and 'violation'"
                        .to_string(),
                ),
            };
            Ok(AuditEntry {
                who: val.who,
                notes: val.notes,
                criteria: val.criteria,
                kind: kind?,
                // By default, always read entries as non-fresh. The import code
                // will set this flag to true for imported entries.
                is_fresh_import: false,
            })
        }
    }

    impl From<AuditEntry> for AuditEntryAll {
        fn from(val: AuditEntry) -> AuditEntryAll {
            let (version, delta, violation, dependency_criteria) = match val.kind {
                AuditKind::Full {
                    version,
                    dependency_criteria,
                } => (Some(version), None, None, dependency_criteria),
                AuditKind::Delta {
                    delta,
                    dependency_criteria,
                } => (None, Some(delta), None, dependency_criteria),
                AuditKind::Violation { violation } => {
                    (None, None, Some(violation), DependencyCriteria::new())
                }
            };
            AuditEntryAll {
                who: val.who,
                notes: val.notes,
                criteria: val.criteria,
                version,
                delta,
                violation,
                dependency_criteria,
            }
        }
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

pub mod spanned {
    use std::{
        borrow::Borrow,
        cmp::Ordering,
        fmt::{self, Display},
        hash::{Hash, Hasher},
        ops::{Deref, DerefMut},
    };

    use miette::SourceSpan;
    use serde::{ser, Deserialize};

    /// A spanned value, indicating the range at which it is defined in the source.
    #[derive(Clone, Default, Deserialize)]
    #[serde(from = "toml::Spanned<T>")]
    pub struct Spanned<T> {
        start: usize,
        end: usize,
        value: T,
    }

    impl<T> Spanned<T> {
        /// Access the start of the span of the contained value.
        pub fn start(this: &Self) -> usize {
            this.start
        }

        /// Access the end of the span of the contained value.
        pub fn end(this: &Self) -> usize {
            this.end
        }

        /// Update the span
        pub fn update_span(this: &mut Self, start: usize, end: usize) {
            this.start = start;
            this.end = end;
        }

        /// Get the span of the contained value.
        pub fn span(this: &Self) -> SourceSpan {
            (Self::start(this)..Self::end(this)).into()
        }

        /// Consumes the spanned value and returns the contained value.
        pub fn into_inner(this: Self) -> T {
            this.value
        }
    }

    impl<T> IntoIterator for Spanned<T>
    where
        T: IntoIterator,
    {
        type IntoIter = T::IntoIter;
        type Item = T::Item;
        fn into_iter(self) -> Self::IntoIter {
            self.value.into_iter()
        }
    }

    impl<'a, T> IntoIterator for &'a Spanned<T>
    where
        &'a T: IntoIterator,
    {
        type IntoIter = <&'a T as IntoIterator>::IntoIter;
        type Item = <&'a T as IntoIterator>::Item;
        fn into_iter(self) -> Self::IntoIter {
            self.value.into_iter()
        }
    }

    impl<'a, T> IntoIterator for &'a mut Spanned<T>
    where
        &'a mut T: IntoIterator,
    {
        type IntoIter = <&'a mut T as IntoIterator>::IntoIter;
        type Item = <&'a mut T as IntoIterator>::Item;
        fn into_iter(self) -> Self::IntoIter {
            self.value.into_iter()
        }
    }

    impl<T> fmt::Debug for Spanned<T>
    where
        T: fmt::Debug,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.value.fmt(f)
        }
    }

    impl<T> Display for Spanned<T>
    where
        T: Display,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.value.fmt(f)
        }
    }

    impl<T> Deref for Spanned<T> {
        type Target = T;
        fn deref(&self) -> &Self::Target {
            &self.value
        }
    }

    impl<T> DerefMut for Spanned<T> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.value
        }
    }

    impl Borrow<str> for Spanned<String> {
        fn borrow(&self) -> &str {
            self
        }
    }

    impl<T, U: ?Sized> AsRef<U> for Spanned<T>
    where
        T: AsRef<U>,
    {
        fn as_ref(&self) -> &U {
            self.value.as_ref()
        }
    }

    impl<T: PartialEq> PartialEq for Spanned<T> {
        fn eq(&self, other: &Self) -> bool {
            self.value.eq(&other.value)
        }
    }

    impl<T: PartialEq<T>> PartialEq<T> for Spanned<T> {
        fn eq(&self, other: &T) -> bool {
            self.value.eq(other)
        }
    }

    impl<T: Eq> Eq for Spanned<T> {}

    impl<T: Hash> Hash for Spanned<T> {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.value.hash(state);
        }
    }

    impl<T: PartialOrd> PartialOrd for Spanned<T> {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            self.value.partial_cmp(&other.value)
        }
    }

    impl<T: PartialOrd<T>> PartialOrd<T> for Spanned<T> {
        fn partial_cmp(&self, other: &T) -> Option<Ordering> {
            self.value.partial_cmp(other)
        }
    }

    impl<T: Ord> Ord for Spanned<T> {
        fn cmp(&self, other: &Self) -> Ordering {
            self.value.cmp(&other.value)
        }
    }

    impl<T> From<T> for Spanned<T> {
        fn from(value: T) -> Self {
            Self {
                start: 0,
                end: 0,
                value,
            }
        }
    }

    impl<T> From<toml::Spanned<T>> for Spanned<T> {
        fn from(value: toml::Spanned<T>) -> Self {
            Self {
                start: value.start(),
                end: value.end(),
                value: value.into_inner(),
            }
        }
    }

    impl<T: ser::Serialize> ser::Serialize for Spanned<T> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: ser::Serializer,
        {
            self.value.serialize(serializer)
        }
    }
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
                "criteria-one-very-long".to_owned().into(),
                "criteria-two-very-long".to_owned().into(),
            ],
        );
        dc_long.insert(
            "example-crate-2".to_owned(),
            vec![
                // This array would wrap over multiple lines if byte length was
                // used rather than utf-8 character length.
                "criteria-one-✨✨✨✨✨✨✨✨✨✨".to_owned().into(),
                "criteria-two-✨✨✨✨✨✨✨✨✨✨".to_owned().into(),
            ],
        );
        dc_long.insert(
            "example-crate-3".to_owned(),
            vec![
                "criteria-one-very-long".to_owned().into(),
                "criteria-two-very-long".to_owned().into(),
                "criteria-three-extremely-long-this-array-should-wrap"
                    .to_owned()
                    .into(),
            ],
        );

        let mut dc_short = SortedMap::new();
        dc_short.insert(
            "example-crate-1".to_owned(),
            vec!["criteria-one".to_owned().into()],
        );

        let mut audits = SortedMap::new();
        audits.insert(
            "test".to_owned(),
            vec![
                AuditEntry {
                    who: None,
                    criteria: vec!["long-criteria".to_owned().into()],
                    kind: AuditKind::Full {
                        version: "1.0.0".parse().unwrap(),
                        dependency_criteria: dc_long,
                    },
                    notes: Some("notes go here!".to_owned()),
                    is_fresh_import: false, // ignored
                },
                AuditEntry {
                    who: None,
                    criteria: vec!["short-criteria".to_owned().into()],
                    kind: AuditKind::Full {
                        version: "1.0.0".parse().unwrap(),
                        dependency_criteria: dc_short,
                    },
                    notes: Some("notes go here!".to_owned()),
                    is_fresh_import: true, // ignored
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
