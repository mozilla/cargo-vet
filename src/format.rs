//! Details of the file formats used by cargo vet

use crate::cli::FetchMode;
use crate::errors::{StoreVersionParseError, VersionParseError};
use crate::resolver::{DiffRecommendation, ViolationConflict};
use crate::serialization::{spanned::Spanned, CacheFileVersion, Tidyable};
use crate::{flock::Filesystem, serialization};
use core::{cmp, fmt};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use cargo_metadata::{semver, Package};
use serde::{de, de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

// Collections based on how we're using, so it's easier to swap them out.
pub type FastMap<K, V> = HashMap<K, V>;
pub type FastSet<T> = HashSet<T>;
pub type SortedMap<K, V> = BTreeMap<K, V>;
pub type SortedSet<T> = BTreeSet<T>;

pub type CriteriaName = String;
pub type CriteriaStr<'a> = &'a str;
pub type ForeignCriteriaName = String;
pub type PackageName = String;
pub type PackageStr<'a> = &'a str;
pub type ImportName = String;
pub type ImportStr<'a> = &'a str;
pub type CratesUserId = u64;
pub type CratesTrustpubSignature = String;

// newtype VersionReq so that we can implement PartialOrd on it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionReq(pub semver::VersionReq);
impl fmt::Display for VersionReq {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl FromStr for VersionReq {
    type Err = <semver::VersionReq as FromStr>::Err;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        semver::VersionReq::from_str(s).map(VersionReq)
    }
}
impl core::ops::Deref for VersionReq {
    type Target = semver::VersionReq;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl cmp::PartialOrd for VersionReq {
    fn partial_cmp(&self, other: &VersionReq) -> Option<cmp::Ordering> {
        format!("{self}").partial_cmp(&format!("{other}"))
    }
}
impl VersionReq {
    pub fn parse(text: &str) -> Result<Self, <Self as FromStr>::Err> {
        cargo_metadata::semver::VersionReq::parse(text).map(VersionReq)
    }
    pub fn matches(&self, version: &VetVersion) -> bool {
        self.0.matches(&version.semver)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VetVersion {
    pub semver: semver::Version,
    pub git_rev: Option<String>,
}
impl VetVersion {
    pub fn parse(s: &str) -> Result<Self, VersionParseError> {
        if let Some((ver, rev)) = s.split_once('@') {
            if let Some(hash) = rev.trim_start().strip_prefix("git:") {
                if hash.len() != 40 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                    Err(VersionParseError::InvalidGitHash)
                } else {
                    Ok(VetVersion {
                        semver: ver.trim_end().parse()?,
                        git_rev: Some(hash.to_owned()),
                    })
                }
            } else {
                Err(VersionParseError::UnknownRevision)
            }
        } else {
            Ok(VetVersion {
                semver: s.parse()?,
                git_rev: None,
            })
        }
    }

    /// Check if this VetVersion exactly matches the given semver version with
    /// no git revision metadata.
    pub fn equals_semver(&self, semver: &semver::Version) -> bool {
        self.git_rev.is_none() && &self.semver == semver
    }

    /// Get this VetVersion as a semver::Version, returning None if this version
    /// corresponds to a git revision.
    pub fn as_semver(&self) -> Option<&semver::Version> {
        if self.git_rev.is_none() {
            Some(&self.semver)
        } else {
            None
        }
    }
}
impl fmt::Display for VetVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.git_rev {
            Some(hash) => write!(f, "{}@git:{}", self.semver, hash),
            None => self.semver.fmt(f),
        }
    }
}
impl FromStr for VetVersion {
    type Err = VersionParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}
impl Serialize for VetVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for VetVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VersionVisitor;

        impl Visitor<'_> for VersionVisitor {
            type Value = VetVersion;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("semver version")
            }
            fn visit_str<E>(self, string: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                VetVersion::parse(string).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(VersionVisitor)
    }
}

////////////////////////////////////////////////////////////////////////////////////
//                                                                                //
//                                                                                //
//                                                                                //
//                 Metaconfigs (found in Cargo.tomls)                             //
//                                                                                //
//                                                                                //
//                                                                                //
////////////////////////////////////////////////////////////////////////////////////

/// A `[*.metadata.vet]` table in a Cargo.toml, configuring our behaviour
#[derive(serde::Deserialize)]
pub struct MetaConfigInstance {
    // Reserved for future use, if not present version=1 assumed.
    // (not sure whether this versions the format, or semantics, or...
    // for now assuming this species global semantics of some kind.
    pub version: Option<u64>,
    pub store: Option<StoreInfo>,
}
#[derive(serde::Deserialize)]
pub struct StoreInfo {
    pub path: Option<PathBuf>,
}

// FIXME: It's *possible* for someone to have a workspace but not have a
// global `vet` instance for the whole workspace. In this case they *could*
// have individual `vet` instances for each subcrate they care about.
// This is... Weird, and it's unclear what that *means*... but maybe it's valid?
// Either way, we definitely don't support it right now!

/// All available configuration files, overlaying each other.
/// Generally contains: `[Default, Workspace, Package]`
pub struct MetaConfig(pub Vec<MetaConfigInstance>);

impl MetaConfig {
    pub fn store_path(&self) -> Filesystem {
        // Last config gets priority to set this
        for config in self.0.iter().rev() {
            if let Some(store) = &config.store {
                if let Some(path) = &store.path {
                    return Filesystem::new(path.into());
                }
            }
        }
        unreachable!("Default config didn't define store.path???");
    }
    pub fn version(&self) -> u64 {
        // Last config gets priority to set this
        for config in self.0.iter().rev() {
            if let Some(ver) = config.version {
                return ver;
            }
        }
        unreachable!("Default config didn't define version???");
    }
}

////////////////////////////////////////////////////////////////////////////////////
//                                                                                //
//                                                                                //
//                                                                                //
//                                audits.toml                                     //
//                                                                                //
//                                                                                //
//                                                                                //
////////////////////////////////////////////////////////////////////////////////////

pub type WildcardAudits = SortedMap<PackageName, Vec<WildcardEntry>>;

pub type AuditedDependencies = SortedMap<PackageName, Vec<AuditEntry>>;

pub type TrustedPackages = SortedMap<PackageName, Vec<TrustEntry>>;

/// audits.toml
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct AuditsFile {
    /// A map of criteria_name to details on that criteria.
    #[serde(skip_serializing_if = "SortedMap::is_empty")]
    #[serde(default)]
    pub criteria: SortedMap<CriteriaName, CriteriaEntry>,
    /// Wildcard audits
    #[serde(rename = "wildcard-audits")]
    #[serde(skip_serializing_if = "SortedMap::is_empty")]
    #[serde(default)]
    pub wildcard_audits: WildcardAudits,
    /// Actual audits.
    pub audits: AuditedDependencies,
    /// Trusted packages
    #[serde(skip_serializing_if = "SortedMap::is_empty")]
    #[serde(default)]
    pub trusted: TrustedPackages,
}

impl Tidyable for AuditsFile {
    fn tidy(&mut self) {
        self.audits.tidy();
        self.wildcard_audits.tidy();
        self.trusted.tidy();
    }
}

/// Foreign audits.toml with unparsed entries and audits. Should have the same
/// structure as `AuditsFile`, but with individual audits and criteria unparsed.
#[derive(serde::Deserialize, Clone, Debug)]
pub struct ForeignAuditsFile {
    #[serde(default)]
    pub criteria: SortedMap<CriteriaName, toml::Table>,
    #[serde(default)]
    #[serde(rename = "wildcard-audits")]
    pub wildcard_audits: SortedMap<PackageName, Vec<toml::Table>>,
    #[serde(default)]
    pub audits: SortedMap<PackageName, Vec<toml::Table>>,
    #[serde(default)]
    pub trusted: SortedMap<PackageName, Vec<toml::Table>>,
}

/// Information on a Criteria
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CriteriaEntry {
    /// Summary of how you evaluate something by this criteria.
    pub description: Option<String>,
    /// An alternative to description which locates the criteria text at a publicly-accessible URL.
    /// This can be useful for sharing criteria descriptions across multiple repositories.
    #[serde(rename = "description-url")]
    pub description_url: Option<String>,
    /// Criteria that this one implies
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    #[serde(with = "serialization::string_or_vec")]
    pub implies: Vec<Spanned<CriteriaName>>,
    /// Chain of sources this criteria was aggregated from, most recent last.
    #[serde(rename = "aggregated-from")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    #[serde(with = "serialization::string_or_vec")]
    pub aggregated_from: Vec<Spanned<String>>,
}

/// This is conceptually an enum
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(try_from = "serialization::audit::AuditEntryAll")]
#[serde(into = "serialization::audit::AuditEntryAll")]
pub struct AuditEntry {
    pub who: Vec<Spanned<String>>,
    pub criteria: Vec<Spanned<CriteriaName>>,
    pub kind: AuditKind,
    pub importable: bool,
    pub notes: Option<String>,
    /// Chain of sources this audit was aggregated from, most recent last.
    pub aggregated_from: Vec<Spanned<String>>,
    /// A non-serialized member which indicates whether this audit is a "fresh"
    /// audit. This will be set for all audits imported found in the remote
    /// audits file which aren't also found in the local `imports.lock` cache.
    ///
    /// This should almost always be `false`, and only set to `true` by the
    /// import handling code.
    #[serde(skip)]
    pub is_fresh_import: bool,
}

impl AuditEntry {
    /// Should `self` be considered to be the same audit as `other`, e.g. for
    /// the purposes of `is_fresh_import` checks?
    pub fn same_audit_as(&self, other: &AuditEntry) -> bool {
        // Ignore `who` and `notes` for comparison, as they are not relevant
        // semantically and might have been updated uneventfully.
        self.kind == other.kind && self.criteria == other.criteria
    }

    /// Try to collapse this (delta) entry with the given entry, which must be just prior to it
    /// (whether a delta or a full audit).
    ///
    /// If the entry can be collapsed, the new entry is returned. The new entry will merge the
    /// `who`, `notes`, and `kind` fields appropriately, and will derive `importable` based on
    /// `kind`.
    pub fn try_collapse_with_prior(&self, other: &AuditEntry) -> Option<Self> {
        let AuditKind::Delta {
            from: self_from,
            to: self_to,
        } = &self.kind
        else {
            return None;
        };
        let (other_from, other_to) = match &other.kind {
            AuditKind::Full { version } => (None, version),
            AuditKind::Delta { from, to } => (Some(from), to),
            AuditKind::Violation { .. } => return None,
        };

        if other_to != self_from {
            return None;
        }

        // TODO should this use a criteria mapper to avoid different orderings?
        if other.criteria != self.criteria {
            return None;
        }

        // Consume the existing audit's `from`, `who`, and `notes`.
        let mut new_entry = self.clone();
        new_entry.kind = match other_from {
            Some(version) => AuditKind::Delta {
                from: version.clone(),
                to: self_to.clone(),
            },
            None => AuditKind::Full {
                version: self_to.clone(),
            },
        };

        let unique_who: Vec<_> = other
            .who
            .iter()
            .filter(|s| !new_entry.who.contains(s))
            .cloned()
            .collect();
        // Precede with the `who` from the audit which aren't in this
        // ceritification, to retain a temporal ordering of auditors.
        new_entry.who.splice(..0, unique_who);

        // Precede the certification notes with the notes from the audit.
        if let Some(prior_notes) = &other.notes {
            new_entry.notes = Some(match new_entry.notes {
                None => prior_notes.clone(),
                Some(new_notes) => format!("{prior_notes}\n{new_notes}"),
            });
        }

        // Rederive `importable` based on the versions.
        new_entry.importable = new_entry.kind.default_importable();

        Some(new_entry)
    }
}

/// Implement PartialOrd manually because the order we want for sorting is
/// different than the order we want for serialization.
///
/// Strictly speaking Ord and PartialOrd implementations are supposed to agree,
/// and clippy recently started complaining about this. We should consider whether
/// there's another solution to this problem.
#[allow(clippy::non_canonical_partial_ord_impl)]
impl cmp::PartialOrd for AuditEntry {
    fn partial_cmp<'a>(&'a self, other: &'a AuditEntry) -> Option<cmp::Ordering> {
        let tuple = |x: &'a AuditEntry| (&x.kind, &x.criteria, &x.who, &x.notes);
        tuple(self).partial_cmp(&tuple(other))
    }
}

impl cmp::Ord for AuditEntry {
    fn cmp(&self, other: &AuditEntry) -> cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub enum AuditKind {
    Full { version: VetVersion },
    Delta { from: VetVersion, to: VetVersion },
    Violation { violation: VersionReq },
}

impl AuditKind {
    pub fn default_importable(&self) -> bool {
        match self {
            Self::Full { version } => version.git_rev.is_none(),
            Self::Delta { from, to } => from.git_rev.is_none() && to.git_rev.is_none(),
            Self::Violation { .. } => false,
        }
    }
}

/// A "VERSION" or "VERSION -> VERSION"
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Delta {
    pub from: Option<VetVersion>,
    pub to: VetVersion,
}

impl<'de> Deserialize<'de> for Delta {
    fn deserialize<D>(deserializer: D) -> Result<Delta, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DeltaVisitor;

        impl Visitor<'_> for DeltaVisitor {
            type Value = Delta;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("version -> version delta")
            }

            fn visit_str<E>(self, string: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if let Some((from, to)) = string.split_once("->") {
                    Ok(Delta {
                        from: Some(VetVersion::parse(from.trim()).map_err(de::Error::custom)?),
                        to: VetVersion::parse(to.trim()).map_err(de::Error::custom)?,
                    })
                } else {
                    Ok(Delta {
                        from: None,
                        to: VetVersion::parse(string.trim()).map_err(de::Error::custom)?,
                    })
                }
            }
        }

        deserializer.deserialize_str(DeltaVisitor)
    }
}

impl Serialize for Delta {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.from {
            Some(from) => format!("{} -> {}", from, self.to).serialize(serializer),
            None => self.to.serialize(serializer),
        }
    }
}

impl fmt::Display for Delta {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.from {
            Some(from) => writeln!(f, "{} -> {}", from, self.to),
            None => self.to.fmt(f),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(untagged)]
pub enum CratesSourceId {
    User {
        #[serde(rename = "user-id")]
        user_id: CratesUserId,
    },
    TrustedPublisher {
        #[serde(rename = "trusted-publisher")]
        trusted_publisher: CratesTrustpubSignature,
    },
}

/// An entry specifying a wildcard audit for a specific crate based on crates.io
/// publication time and user-id.
///
/// These audits will be reified in the imports.lock file when unlocked.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WildcardEntry {
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(with = "serialization::string_or_vec")]
    pub who: Vec<Spanned<String>>,
    #[serde(with = "serialization::string_or_vec")]
    pub criteria: Vec<Spanned<CriteriaName>>,
    #[serde(flatten)]
    pub source: CratesSourceId,
    pub start: Spanned<chrono::NaiveDate>,
    pub end: Spanned<chrono::NaiveDate>,
    pub renew: Option<bool>,
    pub notes: Option<String>,
    #[serde(rename = "aggregated-from")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(with = "serialization::string_or_vec")]
    #[serde(default)]
    pub aggregated_from: Vec<Spanned<String>>,
    /// See `AuditEntry::is_fresh_import`.
    #[serde(skip)]
    pub is_fresh_import: bool,
}

impl WildcardEntry {
    /// Should `self` be considered to be the same audit as `other`, e.g. for
    /// the purposes of `is_fresh_import` checks?
    pub fn same_audit_as(&self, other: &WildcardEntry) -> bool {
        // Ignore `who` and `notes` for comparison, as they are not relevant
        // semantically and might have been updated uneventfully.
        self.source == other.source
            && self.start == other.start
            && self.end == other.end
            && self.criteria == other.criteria
    }

    /// Whether a renewal should be suggested for the entry.
    ///
    /// If the entry expires before `date` (and `renew` isn't `false`) a renewal will be
    /// suggested.
    pub fn should_renew(&self, date: chrono::NaiveDate) -> bool {
        self.renew.unwrap_or(true) && self.end < date
    }
}

/// An entry specifying a trusted publisher for a specific crate based on
/// crates.io publication time and user-id.
///
/// Trusted crates will be reified in the imports.lock file when unlocked.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TrustEntry {
    #[serde(with = "serialization::string_or_vec")]
    pub criteria: Vec<Spanned<CriteriaName>>,
    #[serde(flatten)]
    pub source: CratesSourceId,
    pub start: Spanned<chrono::NaiveDate>,
    pub end: Spanned<chrono::NaiveDate>,
    pub notes: Option<String>,
    #[serde(rename = "aggregated-from")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(with = "serialization::string_or_vec")]
    #[serde(default)]
    pub aggregated_from: Vec<Spanned<String>>,
}

////////////////////////////////////////////////////////////////////////////////////
//                                                                                //
//                                                                                //
//                                                                                //
//                                config.toml                                     //
//                                                                                //
//                                                                                //
//                                                                                //
////////////////////////////////////////////////////////////////////////////////////

/// config.toml
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct ConfigFile {
    #[serde(rename = "cargo-vet")]
    #[serde(default = "CargoVetConfig::missing")]
    pub cargo_vet: CargoVetConfig,

    /// This top-level key specifies the default criteria that cargo vet certify will use
    /// when recording audits. If unspecified, this defaults to "safe-to-deploy".
    #[serde(rename = "default-criteria")]
    #[serde(default = "get_default_criteria")]
    #[serde(skip_serializing_if = "is_default_criteria")]
    pub default_criteria: CriteriaName,

    /// Remote audits.toml's that we trust and want to import.
    #[serde(skip_serializing_if = "SortedMap::is_empty")]
    #[serde(default)]
    pub imports: SortedMap<ImportName, RemoteImport>,

    /// A table of policies for crates.
    #[serde(skip_serializing_if = "Policy::is_empty")]
    #[serde(default)]
    pub policy: Policy,

    /// All of the "foreign" dependencies that we rely on but haven't audited yet.
    /// Foreign dependencies are just "things on crates.io", everything else
    /// (paths, git, etc) is assumed to be "under your control" and therefore implicitly trusted.
    #[serde(skip_serializing_if = "SortedMap::is_empty")]
    #[serde(default)]
    #[serde(alias = "unaudited")]
    pub exemptions: SortedMap<PackageName, Vec<ExemptedDependency>>,
}

impl Tidyable for ConfigFile {
    fn tidy(&mut self) {
        self.exemptions.tidy();
    }
}

pub static SAFE_TO_DEPLOY: CriteriaStr = "safe-to-deploy";
pub static SAFE_TO_RUN: CriteriaStr = "safe-to-run";
pub static DEFAULT_CRITERIA: CriteriaStr = SAFE_TO_DEPLOY;

pub fn get_default_criteria() -> CriteriaName {
    CriteriaName::from(DEFAULT_CRITERIA)
}
fn is_default_criteria(val: &CriteriaName) -> bool {
    val == DEFAULT_CRITERIA
}

/// The table of crate policies.
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, Default)]
#[serde(try_from = "serialization::policy::AllPolicies")]
#[serde(into = "serialization::policy::AllPolicies")]
pub struct Policy {
    pub package: SortedMap<PackageName, PackagePolicyEntry>,
}

impl Policy {
    /// Get the policy entry for the given crate, if any.
    pub fn get(&self, name: PackageStr, version: &VetVersion) -> Option<&PolicyEntry> {
        self.package
            .get(name)
            .and_then(|pkg_policy| match pkg_policy {
                PackagePolicyEntry::Unversioned(e) => Some(e),
                PackagePolicyEntry::Versioned { version: v } => v.get(version),
            })
    }

    /// Get the mutable policy entry for the given crate, if any.
    pub fn get_mut(
        &mut self,
        name: PackageStr,
        version: Option<&VetVersion>,
    ) -> Option<&mut PolicyEntry> {
        self.package
            .get_mut(name)
            .and_then(|pkg_policy| match pkg_policy {
                PackagePolicyEntry::Unversioned(e) => Some(e),
                PackagePolicyEntry::Versioned { version: v } => {
                    version.and_then(|version| v.get_mut(version))
                }
            })
    }

    /// Get the mutable policy entry for the given crate, creating a default if none exists.
    ///
    /// Unlike `get_mut`, this guarantees that the policy is represented as versioned or
    /// unversioned based on the whether the `version` is provided. If the `version` passed is
    /// incompatible with the current policy, None is returned.
    ///
    /// `all_versions` is required to maintain proper structure of the policy map if the entry is
    /// missing: if one policy version is provided, they all must be.
    pub fn get_mut_or_default<F: FnOnce() -> Vec<VetVersion>>(
        &mut self,
        name: PackageName,
        version: Option<&VetVersion>,
        all_versions: F,
    ) -> Option<&mut PolicyEntry> {
        let pkg_policy = self.package.entry(name).or_insert_with(|| {
            if version.is_none() {
                PackagePolicyEntry::Unversioned(Default::default())
            } else {
                PackagePolicyEntry::Versioned {
                    version: all_versions()
                        .into_iter()
                        .map(|v| (v, Default::default()))
                        .collect(),
                }
            }
        });

        match (pkg_policy, version) {
            (PackagePolicyEntry::Unversioned(e), None) => Some(e),
            (PackagePolicyEntry::Versioned { version }, Some(v)) => version.get_mut(v),
            _ => None,
        }
    }

    /// Insert a new package policy entry.
    pub fn insert(
        &mut self,
        name: PackageName,
        entry: PackagePolicyEntry,
    ) -> Option<PackagePolicyEntry> {
        self.package.insert(name, entry)
    }

    /// Return whether there are no policies defined.
    pub fn is_empty(&self) -> bool {
        self.package.is_empty()
    }

    /// Return an iterator over defined policies.
    pub fn iter(&self) -> PolicyIter<'_> {
        PolicyIter {
            iter: self.package.iter(),
            versioned: None,
        }
    }
}

pub struct PolicyIter<'a> {
    iter: <&'a SortedMap<PackageName, PackagePolicyEntry> as IntoIterator>::IntoIter,
    versioned: Option<(
        &'a PackageName,
        <&'a SortedMap<VetVersion, PolicyEntry> as IntoIterator>::IntoIter,
    )>,
}

impl<'a> Iterator for PolicyIter<'a> {
    type Item = (&'a PackageName, Option<&'a VetVersion>, &'a PolicyEntry);

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.versioned {
            Some((name, versioned)) => match versioned.next() {
                Some((v, p)) => Some((name, Some(v), p)),
                None => {
                    self.versioned = None;
                    self.next()
                }
            },
            None => {
                let (name, ppe) = self.iter.next()?;
                match ppe {
                    PackagePolicyEntry::Versioned { version } => {
                        self.versioned = Some((name, version.iter()));
                        self.next()
                    }
                    PackagePolicyEntry::Unversioned(p) => Some((name, None, p)),
                }
            }
        }
    }
}

impl<'a> IntoIterator for &'a Policy {
    type IntoIter = PolicyIter<'a>;
    type Item = <PolicyIter<'a> as Iterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Policies for a particular package (crate).
///
/// If the crate exists as a third-party crate anywhere in the dependency tree, crate versions for
/// _all_ and _only_ the versions present in the dependency tree must be provided to set policies.
/// Otherwise, versions may be omitted.
#[derive(Debug, Clone)]
// We have to use a slightly different serialization than than `serde(untagged)`, because toml only
// parses `Spanned` elements (as contained in `PolicyEntry`) through their own Deseralizer, and
// `serde(untagged)` deserializes everything into a buffer first to try different deserialization
// branches (which will use an internal `serde` Deserializer rather than the `toml` Deserializer).
pub enum PackagePolicyEntry {
    Versioned {
        version: SortedMap<VetVersion, PolicyEntry>,
    },
    Unversioned(PolicyEntry),
}

/// Policies that crates must pass.
///
/// Policy settings here are basically the equivalent of audits.toml, which is separated out
/// because it's not supposed to be shared (or, doesn't really make sense to share, since
/// first-party crates are defined by "not on crates.io").
///
/// Because first-party crates are implicitly trusted, the only purpose of this table is to define
/// the boundary between first-party and third-party ones.  More specifically, the criteria of the
/// dependency edges between a first-party crate and its direct third-party dependencies.
///
/// If this sounds overwhelming, don't worry, everything defaults to "nothing special"
/// and an empty PolicyTable basically just means "everything should satisfy the
/// default criteria in audits.toml".
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, Default)]
pub struct PolicyEntry {
    /// Whether this nominally-first-party crate should actually be subject to audits
    /// as-if it was third-party, based on matches to crates.io packages with the same
    /// name and version. This field is optional for any package that *doesn't* have
    /// such a match, and mandatory for all others (None == Some(false)).
    ///
    /// If true, this package will be handled like a third-party package and require
    /// audits. If the package is not in the crates.io registry, it will be an error
    /// and you should either make sure the current version is published or flip
    /// this back to false.
    ///
    /// Setting this value to true is intended for actual externally developed projects
    /// that you are importing into your project in a weird way with minimal modifications.
    /// For instance, if you manually vendor the package in, or maintain a small patchset
    /// on top of the currently published version.
    ///
    /// It should not be used for packages that are directly developed in this project
    /// (a project shouldn't publish audits for its own code) or for non-trivial forks.
    ///
    /// Audits you *do* perform should be for the actual version published to crates.io,
    /// which are the versions `cargo vet diff` and `cargo vet inspect` will fetch.
    #[serde(rename = "audit-as-crates-io")]
    pub audit_as_crates_io: Option<bool>,

    /// Default criteria that must be satisfied by all *direct* third-party (foreign) dependencies
    /// of the crate. If satisfied, the crate is set to satisfying all criteria.
    ///
    /// If not present, this defaults to the default criteria in the audits table.
    #[serde(default)]
    #[serde(with = "serialization::string_or_vec_or_none")]
    pub criteria: Option<Vec<Spanned<CriteriaName>>>,

    /// Same as `criteria`, but for crates that are only used as dev-dependencies.
    #[serde(rename = "dev-criteria")]
    #[serde(default)]
    #[serde(with = "serialization::string_or_vec_or_none")]
    pub dev_criteria: Option<Vec<Spanned<CriteriaName>>>,

    /// Custom criteria for a specific crate's dependencies.
    ///
    /// Any dependency edge that isn't explicitly specified defaults to `criteria`.
    #[serde(rename = "dependency-criteria")]
    #[serde(skip_serializing_if = "CriteriaMap::is_empty")]
    #[serde(with = "serialization::criteria_map")]
    #[serde(default)]
    pub dependency_criteria: CriteriaMap,

    /// Freeform notes
    pub notes: Option<String>,
}

/// Helper type for managing a mapping from a string to a set of criteria. This
/// is used for dependency-criteria to specify the criteria that transitive
/// dependencies must satisfy, as well as for criteria-maps when specifying the
/// criteria implied by foreign criteria.
///
/// Example:
///
/// ```toml
/// dependency_criteria = { hmac = ['secure', 'crypto_reviewed'] }
/// ```
///
/// ```toml
/// criteria-map = { fuzzed = 'safe-to-deploy' }
/// ```
pub type CriteriaMap = SortedMap<Spanned<String>, Vec<Spanned<CriteriaName>>>;

pub static DEFAULT_POLICY_CRITERIA: CriteriaStr = SAFE_TO_DEPLOY;
pub static DEFAULT_POLICY_DEV_CRITERIA: CriteriaStr = SAFE_TO_RUN;

/// A remote audits.toml that we trust the contents of (by virtue of trusting the maintainer).
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, Default)]
pub struct RemoteImport {
    /// URL(s) of the foreign audits.toml
    #[serde(with = "serialization::string_or_vec")]
    pub url: Vec<String>,
    /// A list of crates for which no audits or violations should be imported.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub exclude: Vec<PackageName>,
    /// A list of criteria that are implied by foreign criteria
    #[serde(rename = "criteria-map")]
    #[serde(skip_serializing_if = "CriteriaMap::is_empty")]
    #[serde(with = "serialization::criteria_map")]
    #[serde(default)]
    pub criteria_map: CriteriaMap,
}

/// Translations of foreign criteria to local criteria.
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct CriteriaMapping {
    /// This local criteria is implied...
    pub ours: CriteriaName,
    /// If this foreign criteria applies
    pub theirs: Spanned<ForeignCriteriaName>,
}

/// Semantically identical to a 'full audit' entry, but private to our project
/// and tracked as less-good than a proper audit, so that you try to get rid of it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExemptedDependency {
    /// The version of the crate that we are currently "fine" with leaving unaudited.
    pub version: VetVersion,
    /// Criteria that we're willing to handwave for this version (assuming our dependencies
    /// satisfy this criteria). This isn't defaulted, 'vet init' and similar commands will
    /// pick a "good" initial value.
    #[serde(default)]
    #[serde(with = "serialization::string_or_vec")]
    pub criteria: Vec<Spanned<CriteriaName>>,
    /// Whether 'suggest' should bother mentioning this (defaults true).
    #[serde(default = "get_default_exemptions_suggest")]
    #[serde(skip_serializing_if = "is_default_exemptions_suggest")]
    pub suggest: bool,
    /// Freeform notes, put whatever you want here. Just more stable/reliable than comments.
    pub notes: Option<String>,
}

static DEFAULT_EXEMPTIONS_SUGGEST: bool = true;
pub fn get_default_exemptions_suggest() -> bool {
    DEFAULT_EXEMPTIONS_SUGGEST
}
fn is_default_exemptions_suggest(val: &bool) -> bool {
    val == &DEFAULT_EXEMPTIONS_SUGGEST
}

/// Special version type used for store versions. Only contains two components
/// (major/minor) to avoid patch version changes from causing changes to the
/// store.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StoreVersion {
    pub major: u64,
    pub minor: u64,
}

impl StoreVersion {
    #[cfg(not(test))]
    pub fn current() -> Self {
        StoreVersion {
            major: env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap(),
            minor: env!("CARGO_PKG_VERSION_MINOR").parse().unwrap(),
        }
    }

    // To keep output from tests stable, when running unit tests we always
    // pretend we're version 1.0
    #[cfg(test)]
    pub fn current() -> Self {
        StoreVersion { major: 1, minor: 0 }
    }
}

impl FromStr for StoreVersion {
    type Err = StoreVersionParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('.') {
            Some((major, minor)) => Ok(StoreVersion {
                major: major.parse()?,
                minor: minor.parse()?,
            }),
            None => Err(StoreVersionParseError::MissingSeparator),
        }
    }
}

impl fmt::Display for StoreVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl Serialize for StoreVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StoreVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VersionVisitor;

        impl Visitor<'_> for VersionVisitor {
            type Value = StoreVersion;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("store version")
            }
            fn visit_str<E>(self, string: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                StoreVersion::from_str(string).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(VersionVisitor)
    }
}

/// Cargo vet config metadata field for the store's config file.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CargoVetConfig {
    pub version: StoreVersion,
}

impl CargoVetConfig {
    /// Pretend that any store which was created without a version specified is
    /// from version 0.4.
    fn missing() -> Self {
        Self {
            version: StoreVersion { major: 0, minor: 4 },
        }
    }
}

impl Default for CargoVetConfig {
    fn default() -> Self {
        Self {
            version: StoreVersion::current(),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////
//                                                                                //
//                                                                                //
//                                                                                //
//                                imports.lock                                    //
//                                                                                //
//                                                                                //
//                                                                                //
////////////////////////////////////////////////////////////////////////////////////

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ImportsFile {
    #[serde(default)]
    #[serde(skip_serializing_if = "SortedMap::is_empty")]
    pub unpublished: SortedMap<PackageName, Vec<UnpublishedEntry>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "SortedMap::is_empty")]
    pub publisher: SortedMap<PackageName, Vec<CratesPublisher>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "SortedMap::is_empty")]
    pub audits: SortedMap<ImportName, AuditsFile>,
}

impl Tidyable for ImportsFile {
    fn tidy(&mut self) {
        self.unpublished.tidy();
        self.publisher.tidy();
        for audits_file in self.audits.values_mut() {
            audits_file.tidy();
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(untagged)]
pub enum CratesPublisherSource {
    User {
        #[serde(rename = "user-id")]
        user_id: CratesUserId,
        #[serde(rename = "user-login")]
        user_login: String,
        #[serde(rename = "user-name")]
        user_name: Option<String>,
    },
    TrustedPublisher {
        #[serde(rename = "trusted-publisher")]
        trusted_publisher: CratesTrustpubSignature,
    },
}

impl CratesPublisherSource {
    pub fn as_identifier(&self) -> &str {
        match self {
            CratesPublisherSource::User { user_login, .. } => &user_login[..],
            CratesPublisherSource::TrustedPublisher { trusted_publisher } => &trusted_publisher[..],
        }
    }

    pub fn as_wildcard_source(&self) -> CratesSourceId {
        match self {
            CratesPublisherSource::User { user_id, .. } => {
                CratesSourceId::User { user_id: *user_id }
            }
            CratesPublisherSource::TrustedPublisher { trusted_publisher } => {
                CratesSourceId::TrustedPublisher {
                    trusted_publisher: trusted_publisher.clone(),
                }
            }
        }
    }
}

impl fmt::Display for CratesPublisherSource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CratesPublisherSource::User {
                user_login,
                user_name: Some(user_name),
                ..
            } => write!(f, "{} ({})", user_name, user_login),
            CratesPublisherSource::User { user_login, .. } => write!(f, "{}", user_login),
            CratesPublisherSource::TrustedPublisher { trusted_publisher } => {
                write!(f, "{}", trusted_publisher)
            }
        }
    }
}

impl PartialEq<CratesSourceId> for CratesPublisherSource {
    fn eq(&self, other: &CratesSourceId) -> bool {
        match (self, other) {
            (
                CratesPublisherSource::User { user_id: us, .. },
                CratesSourceId::User { user_id: them },
            ) => us == them,
            (
                CratesPublisherSource::TrustedPublisher {
                    trusted_publisher: us,
                },
                CratesSourceId::TrustedPublisher {
                    trusted_publisher: them,
                },
            ) => us == them,
            _ => false,
        }
    }
}
impl PartialEq<CratesPublisherSource> for CratesSourceId {
    fn eq(&self, other: &CratesPublisherSource) -> bool {
        other == self
    }
}

/// Information about who published a specific version of a crate to be cached
/// in imports.lock.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CratesPublisher {
    // NOTE: This will only ever be a `semver::Version`, however the resolver
    // code works on borrowed `VetVersion` instances, so we use one here so it
    // is easier to use within the resolver.
    pub version: VetVersion,
    pub when: chrono::NaiveDate,
    #[serde(flatten)]
    pub source: CratesPublisherSource,
    /// See `AuditEntry::is_fresh_import`.
    #[serde(skip)]
    pub is_fresh_import: bool,
}

// Information about a specific crate being unpublished
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnpublishedEntry {
    // NOTE: This will only ever be a `semver::Version`, however the resolver
    // code works on borrowed `VetVersion` instances, so we use one here so it
    // is easier to use within the resolver.
    pub version: VetVersion,
    pub audited_as: VetVersion,
    /// Set to `true` if `version` was not published when acquiring the Store.
    /// Always set to `false` when locked.
    #[serde(skip)]
    pub still_unpublished: bool,
    /// See `AuditEntry::is_fresh_import`.
    #[serde(skip)]
    pub is_fresh_import: bool,
}

////////////////////////////////////////////////////////////////////////////////////
//                                                                                //
//                                                                                //
//                                                                                //
//                               diffcache.toml                                   //
//                                                                                //
//                                                                                //
//                                                                                //
////////////////////////////////////////////////////////////////////////////////////

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct DiffCache {
    pub version: CacheFileVersion<2>,
    pub diffs: SortedMap<PackageName, SortedMap<Delta, DiffStat>>,
}

impl Tidyable for DiffCache {
    fn tidy(&mut self) {}
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct DiffStat {
    pub insertions: u64,
    pub deletions: u64,
    pub files_changed: u64,
}

impl DiffStat {
    pub fn count(&self) -> u64 {
        self.insertions + self.deletions
    }
}

impl fmt::Display for DiffStat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} files changed", self.files_changed)?;
        if self.insertions > 0 {
            write!(f, ", {} insertions(+)", self.insertions)?;
        }
        if self.deletions > 0 {
            write!(f, ", {} deletions(-)", self.deletions)?;
        }
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////////
//                                                                                //
//                                                                                //
//                                                                                //
//                             command-history.json                               //
//                                                                                //
//                                                                                //
//                                                                                //
////////////////////////////////////////////////////////////////////////////////////

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum FetchCommand {
    Inspect {
        package: PackageName,
        version: VetVersion,
    },
    Diff {
        package: PackageName,
        version1: VetVersion,
        version2: VetVersion,
    },
}

impl FetchCommand {
    pub fn package(&self) -> PackageStr<'_> {
        match self {
            FetchCommand::Inspect { package, .. } => package,
            FetchCommand::Diff { package, .. } => package,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CommandHistory {
    pub version: CacheFileVersion<1>,
    #[serde(flatten)]
    pub last_fetch: Option<FetchCommand>,
    pub last_fetch_mode: Option<FetchMode>,
}

////////////////////////////////////////////////////////////////////////////////////
//                                                                                //
//                                                                                //
//                                                                                //
//                             crates-io-cache.json                               //
//                                                                                //
//                                                                                //
//                                                                                //
////////////////////////////////////////////////////////////////////////////////////

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CratesCacheUser {
    pub login: String,
    pub name: Option<String>,
}
impl fmt::Display for CratesCacheUser {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(name) = &self.name {
            write!(f, "{} ({})", name, &self.login)
        } else {
            write!(f, "{}", &self.login)
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CratesCacheVersionDetails {
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub source: Option<CratesSourceId>,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct CratesCacheEntry {
    pub versions: SortedMap<semver::Version, CratesCacheVersionDetails>,
    pub metadata: CratesAPICrateMetadata,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct CratesCache {
    pub version: CacheFileVersion<2>,
    pub users: SortedMap<CratesUserId, CratesCacheUser>,
    pub crates: SortedMap<PackageName, Arc<CratesCacheEntry>>,
}

////////////////////////////////////////////////////////////////////////////////////
//                                                                                //
//                                                                                //
//                                                                                //
//                                 crates.io API                                  //
//                                                                                //
//                                                                                //
//                                                                                //
////////////////////////////////////////////////////////////////////////////////////

// NOTE: This is a subset of the format returned from the crates.io v1 API.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CratesAPIUser {
    pub id: CratesUserId,
    pub login: String,
    pub name: Option<String>,
}

// NOTE: This is a subset of the format returned from the crates.io v1 API.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[serde(tag = "provider")]
pub enum CratesAPITrustpubData {
    #[serde(rename = "github")]
    GitHub { repository: String },
    #[serde(other)]
    Unknown,
}

impl CratesAPITrustpubData {
    pub fn as_signature(&self) -> Option<CratesTrustpubSignature> {
        match self {
            CratesAPITrustpubData::GitHub { repository } => Some(format!("github:{repository}")),
            CratesAPITrustpubData::Unknown => None,
        }
    }
}

// NOTE: This is a subset of the format returned from the crates.io v1 API.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CratesAPIVersion {
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub num: semver::Version,
    pub published_by: Option<CratesAPIUser>,
    pub trustpub_data: Option<CratesAPITrustpubData>,
}

// NOTE: This is a subset of the format returned from the crates.io v1 API.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct CratesAPICrateMetadata {
    pub description: Option<String>,
    pub repository: Option<String>,
}

// NOTE: This is a subset of the format returned from the crates.io v1 API.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CratesAPICrate {
    #[serde(rename = "crate")]
    pub crate_data: CratesAPICrateMetadata,
    pub versions: Vec<CratesAPIVersion>,
}

impl CratesAPICrateMetadata {
    /// Whether this metadata is similar enough to that of the given package to be considered the
    /// same.
    pub fn consider_as_same(&self, p: &Package) -> bool {
        (self.description.is_some() && p.description == self.description)
            || (self.repository.is_some() && p.repository == self.repository)
    }
}

////////////////////////////////////////////////////////////////////////////////////
//                                                                                //
//                                                                                //
//                                                                                //
//                               registry.toml                                    //
//                                                                                //
//                                                                                //
//                                                                                //
////////////////////////////////////////////////////////////////////////////////////

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct RegistryFile {
    pub registry: SortedMap<ImportName, RegistryEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegistryEntry {
    #[serde(with = "serialization::string_or_vec")]
    pub url: Vec<String>,
}

////////////////////////////////////////////////////////////////////////////////////
//                                                                                //
//                                                                                //
//                                                                                //
//                             <json report output>                               //
//                                                                                //
//                                                                                //
//                                                                                //
////////////////////////////////////////////////////////////////////////////////////

/// cargo-vet's `--output-format=json` for `check` and `suggest` on:
///
/// * success
/// * audit failure
/// * violation conflicts
///
/// Other errors like i/o or supply-chain integrity issues will show
/// up as miette-style json errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonReport {
    #[serde(flatten)]
    pub conclusion: JsonReportConclusion,
}

/// The conclusion of running `check` or `suggest`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "conclusion")]
pub enum JsonReportConclusion {
    /// Success! Everything's Good.
    #[serde(rename = "success")]
    Success(JsonReportSuccess),
    /// The violations and audits/exemptions are contradictory!
    #[serde(rename = "fail (violation)")]
    FailForViolationConflict(JsonReportFailForViolationConflict),
    /// The audit failed, here's why and what to do.
    #[serde(rename = "fail (vetting)")]
    FailForVet(JsonReportFailForVet),
}

/// Success! Everything is audited!
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonReportSuccess {
    /// These packages are fully vetted
    pub vetted_fully: Vec<JsonPackage>,
    /// These packages are partially vetted (some audits but relies on an `exemption`).
    pub vetted_partially: Vec<JsonPackage>,
    /// These packages are exempted
    pub vetted_with_exemptions: Vec<JsonPackage>,
}

/// Failure! The violations and audits/exemptions are contradictory!
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonReportFailForViolationConflict {
    /// These packages have the following conflicts
    // FIXME(SCHEMA): we probably shouldn't expose this internal type
    pub violations: SortedMap<PackageAndVersion, Vec<ViolationConflict>>,
}

/// Failure! You need more audits!
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonReportFailForVet {
    /// Here are the problems we found
    pub failures: Vec<JsonVetFailure>,
    /// And here are the fixes we recommend
    pub suggest: Option<JsonSuggest>,
}

/// Suggested fixes for a FailForVet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSuggest {
    /// Here are the suggestions sorted in the order of priority
    pub suggestions: Vec<JsonSuggestItem>,
    /// The same set of suggestions but grouped by the criteria (lists) needed to audit them
    // FIXME(SCHEMA): this is kinda redundant? do consumers want this?
    pub suggest_by_criteria: SortedMap<String, Vec<JsonSuggestItem>>,
    /// The total number of lines you would need to review to resolve this
    pub total_lines: u64,
}

/// This specific package needed the following criteria but doesn't have them!
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonVetFailure {
    /// The name of the package
    pub name: PackageName,
    /// The version of the package
    pub version: VetVersion,
    /// The missing criteria
    pub missing_criteria: Vec<CriteriaName>,
}

/// We recommend auditing the following package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSuggestItem {
    /// The name of the package
    pub name: PackageName,
    /// Any notable parents the package has (can be helpful in giving context to the user)
    // FIXME(SCHEMA): we probably shouldn't expose this as a String
    pub notable_parents: String,
    /// The criteria we recommend auditing the package for
    pub suggested_criteria: Vec<CriteriaName>,
    /// The diff (or full version) we recommend auditing
    // FIXME(SCHEMA): we probably shouldn't expose this internal type
    pub suggested_diff: DiffRecommendation,
}

/// A string of the form "package:version"
pub type PackageAndVersion = String;

/// A Package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonPackage {
    /// Name of the package
    pub name: PackageName,
    /// Version of the package
    pub version: VetVersion,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn vet_version_parsing() {
        assert_eq!(
            VetVersion::parse("1.0.0").unwrap(),
            VetVersion {
                semver: "1.0.0".parse().unwrap(),
                git_rev: None
            }
        );

        assert_eq!(
            VetVersion::parse("1.0.1@git:00112233445566778899aabbccddeeff00112233").unwrap(),
            VetVersion {
                semver: "1.0.1".parse().unwrap(),
                git_rev: Some("00112233445566778899aabbccddeeff00112233".into())
            }
        );

        match VetVersion::parse("1.0.1@git:00112233445566778899aabbccddeeff0011223g") {
            Err(VersionParseError::InvalidGitHash) => (),
            _ => panic!("expected invalid git hash"),
        }

        match VetVersion::parse("1.0.1@git:00112233") {
            Err(VersionParseError::InvalidGitHash) => (),
            _ => panic!("expected invalid git hash"),
        }

        match VetVersion::parse("1.0.1@pijul:00112233") {
            Err(VersionParseError::UnknownRevision) => (),
            _ => panic!("expected unknown revision"),
        }
    }
}
