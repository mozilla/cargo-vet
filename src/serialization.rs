//! Serialization helpers

use crate::format::{CratesCacheUser, CratesUserId, CriteriaMap, FastMap, SortedMap};
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

    pub fn serialize<S, T>(v: &Vec<T>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<str> + Serialize,
    {
        if v.len() == 1 {
            s.serialize_str(v[0].as_ref())
        } else {
            v.serialize(s)
        }
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: StringOrVecLike,
    {
        // Get a Spanned<StringOrVec> and then use it to fixup a dummy span for len == 1
        let spanned_vec = Spanned::<StringOrVec>::deserialize(deserializer)?;
        let start = Spanned::start(&spanned_vec);
        let end = Spanned::end(&spanned_vec);
        let mut vec = Spanned::into_inner(spanned_vec).0;
        if vec.len() == 1 {
            Spanned::update_span(&mut vec[0], start, end);
        }
        Ok(StringOrVecLike::convert(vec))
    }

    // Helper trait to allow non-spanned deserialization of string_or_vec.
    pub trait StringOrVecLike {
        fn convert(from: Vec<Spanned<String>>) -> Self;
    }
    impl StringOrVecLike for Vec<Spanned<String>> {
        fn convert(from: Vec<Spanned<String>>) -> Self {
            from
        }
    }
    impl StringOrVecLike for Vec<String> {
        fn convert(from: Vec<Spanned<String>>) -> Self {
            from.into_iter().map(Spanned::into_inner).collect()
        }
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

/// Allows the `Vec<String>` map value in dependency-criteria or criteria-map to
/// support `string_or_vec` semantics.
pub mod criteria_map {
    use crate::format::CriteriaName;

    use super::*;
    #[derive(Serialize, Deserialize)]
    struct Wrapper(#[serde(with = "string_or_vec")] Vec<Spanned<CriteriaName>>);

    pub fn serialize<S>(c: &CriteriaMap, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let m: SortedMap<Spanned<String>, Wrapper> = c
            .iter()
            .map(|(k, v)| (k.clone(), Wrapper(v.clone())))
            .collect();
        m.serialize(s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<CriteriaMap, D::Error>
    where
        D: Deserializer<'de>,
    {
        let m = SortedMap::<Spanned<String>, Wrapper>::deserialize(deserializer)?;
        Ok(m.into_iter().map(|(k, v)| (k, v.0)).collect())
    }
}

pub mod policy {
    use super::*;
    use crate::format::{PackageName, PackagePolicyEntry, Policy, PolicyEntry, VetVersion};

    const VERSION_SEPARATOR: &str = ":";

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(transparent)]
    pub struct AllPolicies(SortedMap<String, PolicyEntry>);

    #[derive(Debug, thiserror::Error)]
    pub enum FromAllPoliciesError {
        #[error("cannot mix versioned and unversioned policies for {name}")]
        MixedVersioning { name: PackageName },
        #[error("more than one policy provided for {name}:{version}")]
        Duplicate {
            name: PackageName,
            version: VetVersion,
        },
        #[error(transparent)]
        VersionParse(#[from] crate::errors::VersionParseError),
    }

    impl std::convert::TryFrom<AllPolicies> for Policy {
        type Error = FromAllPoliciesError;

        fn try_from(value: AllPolicies) -> Result<Self, Self::Error> {
            let mut policy = Policy::default();
            for (name, entry) in value.0 {
                match name.split_once(VERSION_SEPARATOR) {
                    Some((crate_name, crate_version)) => {
                        match policy
                            .package
                            .entry(crate_name.to_owned())
                            .or_insert_with(|| PackagePolicyEntry::Versioned {
                                version: Default::default(),
                            }) {
                            PackagePolicyEntry::Versioned { version } => {
                                version.insert(crate_version.parse()?, entry);
                            }
                            PackagePolicyEntry::Unversioned(_) => {
                                return Err(FromAllPoliciesError::MixedVersioning {
                                    name: crate_name.to_owned(),
                                });
                            }
                        }
                    }
                    None => {
                        if policy
                            .package
                            .insert(name.clone(), PackagePolicyEntry::Unversioned(entry))
                            .is_some()
                        {
                            // The entry _must_ have been `PackagePolicyEntry::Versioned`, because
                            // if it were unversioned there would be no way for more than one entry
                            // to exist in the AllPolicies map.
                            return Err(FromAllPoliciesError::MixedVersioning { name });
                        }
                    }
                }
            }
            Ok(policy)
        }
    }

    impl From<Policy> for AllPolicies {
        fn from(policy: Policy) -> Self {
            let mut ret = SortedMap::default();

            for (name, v) in policy.package {
                match v {
                    PackagePolicyEntry::Versioned { version } => {
                        for (version, entry) in version {
                            ret.insert(format!("{name}{VERSION_SEPARATOR}{version}"), entry);
                        }
                    }
                    PackagePolicyEntry::Unversioned(entry) => {
                        ret.insert(name, entry);
                    }
                }
            }

            AllPolicies(ret)
        }
    }
}

pub mod audit {
    use super::*;

    use crate::format::{AuditEntry, AuditKind, CriteriaName, Delta, VersionReq, VetVersion};

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AuditEntryAll {
        #[serde(default)]
        #[serde(skip_serializing_if = "Vec::is_empty")]
        #[serde(with = "string_or_vec")]
        who: Vec<Spanned<String>>,
        #[serde(default)]
        #[serde(with = "string_or_vec")]
        criteria: Vec<Spanned<CriteriaName>>,
        version: Option<VetVersion>,
        delta: Option<Delta>,
        violation: Option<VersionReq>,
        importable: Option<bool>,
        notes: Option<String>,
        #[serde(rename = "aggregated-from")]
        #[serde(skip_serializing_if = "Vec::is_empty")]
        #[serde(with = "string_or_vec")]
        #[serde(default)]
        pub aggregated_from: Vec<Spanned<String>>,
    }

    impl TryFrom<AuditEntryAll> for AuditEntry {
        type Error = String;
        fn try_from(val: AuditEntryAll) -> Result<AuditEntry, Self::Error> {
            let kind = match (val.version, val.delta, val.violation) {
                (Some(version), None, None) => Ok(AuditKind::Full { version }),
                (None, Some(delta), None) => {
                    if let Some(from) = delta.from {
                        Ok(AuditKind::Delta { from, to: delta.to })
                    } else {
                        Err("'delta' must be a delta of the form 'VERSION -> VERSION'".to_string())
                    }
                }
                (None, None, Some(violation)) => Ok(AuditKind::Violation { violation }),
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
                importable: val.importable.unwrap_or(true),
                aggregated_from: val.aggregated_from,
                // By default, always read entries as non-fresh. The import code
                // will set this flag to true for imported entries.
                is_fresh_import: false,
            })
        }
    }

    impl From<AuditEntry> for AuditEntryAll {
        fn from(val: AuditEntry) -> AuditEntryAll {
            let (version, delta, violation) = match val.kind {
                AuditKind::Full { version } => (Some(version), None, None),
                AuditKind::Delta { from, to } => (
                    None,
                    Some(Delta {
                        from: Some(from),
                        to,
                    }),
                    None,
                ),
                AuditKind::Violation { violation } => (None, None, Some(violation)),
            };
            AuditEntryAll {
                who: val.who,
                notes: val.notes,
                criteria: val.criteria,
                version,
                delta,
                violation,
                importable: if val.importable { None } else { Some(false) },
                aggregated_from: val.aggregated_from,
            }
        }
    }
}

/// Trait implemented by format data types which may want to be cleaned up
/// before they are serialized.
pub trait Tidyable {
    /// Ensure that the data structure is tidy and ready to be serialized.
    /// This may remove empty entries from maps, ensure lists are sorted, etc.
    fn tidy(&mut self);
}

/// Helper for tidying the common audit data structure, removing empty entries,
/// and sorting audit lists.
impl<K: Ord, E: Ord> Tidyable for SortedMap<K, Vec<E>> {
    fn tidy(&mut self) {
        self.retain(|_, entries| {
            entries.sort();
            !entries.is_empty()
        });
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
pub fn to_formatted_toml<T>(
    val: T,
    user_info: Option<&FastMap<CratesUserId, CratesCacheUser>>,
) -> Result<toml_edit::DocumentMut, toml_edit::ser::Error>
where
    T: Serialize,
{
    use toml_edit::visit_mut::VisitMut;

    struct TomlFormatter<'a> {
        user_info: Option<&'a FastMap<CratesUserId, CratesCacheUser>>,
    }
    impl TomlFormatter<'_> {
        fn add_user_login_comments(&self, v: &mut toml_edit::Item) {
            let Some(user_info) = &self.user_info else {
                return;
            };
            let Some(v) = v.as_value_mut() else { return };
            let Some(user_id) = v.as_integer() else {
                return;
            };
            let Some(info) = user_info.get(&(user_id as u64)) else {
                return;
            };
            v.decor_mut().set_suffix(format!(" # {}", info));
        }
    }
    impl VisitMut for TomlFormatter<'_> {
        fn visit_table_mut(&mut self, node: &mut toml_edit::Table) {
            // Hide unnecessary implicit table headers for tables containing
            // only other tables. We don't do this for empty tables as otherwise
            // they could be hidden.
            if !node.is_empty() {
                node.set_implicit(true);
            }
            let is_publisher_entry = node.get("user-login").is_some();
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

                if k == "user-id" && !is_publisher_entry {
                    self.add_user_login_comments(v);
                }

                self.visit_item_mut(v);
            }
        }
    }

    let mut toml_document = toml_edit::ser::to_document(&val)?;
    TomlFormatter { user_info }.visit_document_mut(&mut toml_document);
    Ok(toml_document)
}

/// Deserialize the given data structure from a toml::Value, without falling
/// over due to Spanned failing to parse.
pub fn parse_from_value<T>(value: toml::Value) -> Result<T, toml::de::Error>
where
    T: for<'a> Deserialize<'a>,
{
    spanned::DISABLE_SPANNED_DESERIALIZATION.with(|disabled| {
        let prev = disabled.replace(true);
        let rv = T::deserialize(value);
        disabled.set(prev);
        rv
    })
}

pub mod spanned {
    use std::{
        borrow::Borrow,
        cell::Cell,
        cmp::Ordering,
        fmt::{self, Display},
        hash::{Hash, Hasher},
        ops::{Deref, DerefMut},
    };

    use miette::SourceSpan;
    use serde::{de, ser};

    thread_local! {
        /// Hack to work around `toml::Spanned` failing to be deserialized when
        /// used with the `toml::Value` deserializer.
        pub(super) static DISABLE_SPANNED_DESERIALIZATION: Cell<bool> = const { Cell::new(false) };
    }

    /// A spanned value, indicating the range at which it is defined in the source.
    #[derive(Clone, Default)]
    pub struct Spanned<T> {
        start: usize,
        end: usize,
        value: T,
    }

    impl<T> Spanned<T> {
        /// Create a Spanned with a specific SourceSpan.
        pub fn with_source_span(value: T, source: SourceSpan) -> Self {
            Spanned {
                start: source.offset(),
                end: source.offset() + source.len(),
                value,
            }
        }

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

        /// Alter a span to a length anchored from the end.
        pub fn from_end(mut this: Self, length: usize) -> Self {
            this.start = this.end - length;
            this
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

    impl<T> Borrow<T> for Spanned<T> {
        fn borrow(&self) -> &T {
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

    impl<'de, T: de::Deserialize<'de>> de::Deserialize<'de> for Spanned<T> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            Ok(if DISABLE_SPANNED_DESERIALIZATION.with(|d| d.get()) {
                T::deserialize(deserializer)?.into()
            } else {
                toml::Spanned::<T>::deserialize(deserializer)?.into()
            })
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
            "example-crate-1".to_owned().into(),
            vec![
                "criteria-one-very-long".to_owned().into(),
                "criteria-two-very-long".to_owned().into(),
            ],
        );
        dc_long.insert(
            "example-crate-2".to_owned().into(),
            vec![
                // This array would wrap over multiple lines if byte length was
                // used rather than utf-8 character length.
                "criteria-one-✨✨✨✨✨✨✨✨✨✨".to_owned().into(),
                "criteria-two-✨✨✨✨✨✨✨✨✨✨".to_owned().into(),
            ],
        );
        dc_long.insert(
            "example-crate-3".to_owned().into(),
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
            "example-crate-1".to_owned().into(),
            vec!["criteria-one".to_owned().into()],
        );

        let mut policy = Policy::default();
        policy.insert(
            "long-criteria".to_owned(),
            PackagePolicyEntry::Unversioned(PolicyEntry {
                audit_as_crates_io: None,
                criteria: Some(vec!["long-criteria".to_owned().into()]),
                dev_criteria: None,
                dependency_criteria: dc_long,
                notes: Some("notes go here!".to_owned()),
            }),
        );
        policy.insert(
            "short-criteria".to_owned(),
            PackagePolicyEntry::Unversioned(PolicyEntry {
                audit_as_crates_io: None,
                criteria: Some(vec!["short-criteria".to_owned().into()]),
                dev_criteria: None,
                dependency_criteria: dc_short,
                notes: Some("notes go here!".to_owned()),
            }),
        );

        let formatted = super::to_formatted_toml(
            ConfigFile {
                cargo_vet: CargoVetConfig {
                    version: StoreVersion { major: 1, minor: 0 },
                },
                default_criteria: get_default_criteria(),
                imports: SortedMap::new(),
                policy,
                exemptions: SortedMap::new(),
            },
            None,
        )
        .unwrap()
        .to_string();

        insta::assert_snapshot!("formatted_toml_long_inline", formatted);
    }
}
