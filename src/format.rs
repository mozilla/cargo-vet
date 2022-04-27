//! Details of the file formats used by cargo vet

use core::fmt;
use std::path::{Path, PathBuf};

use cargo_metadata::{Version, VersionReq};
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::VetError;

pub type StableMap<K, V> = linked_hash_map::LinkedHashMap<K, V>;

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
    pub store: Option<Store>,
}
#[derive(serde::Deserialize)]
pub struct Store {
    pub path: Option<PathBuf>,
}

// FIXME: It's *possible* for someone to have a workspace but not have a
// global `vet` instance for the whole workspace. In this case they *could*
// have individual `vet` instances for each subcrate they care about.
// This is... Weird, and it's unclear what that *means*... but maybe it's valid?
// Either way, we definitely don't support it right now!

/// All available configuration files, overlaying eachother.
/// Generally contains: `[Default, Workspace, Package]`
pub struct MetaConfig(pub Vec<MetaConfigInstance>);

impl MetaConfig {
    pub fn store_path(&self) -> &Path {
        // Last config gets priority to set this
        for config in self.0.iter().rev() {
            if let Some(store) = &config.store {
                if let Some(path) = &store.path {
                    return path;
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

pub type AuditedDependencies = StableMap<String, Vec<AuditEntry>>;

/// audits.toml
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AuditsFile {
    /// A map of criteria_name to details on that criteria.
    pub criteria: StableMap<String, CriteriaEntry>,
    /// Actual audits.
    pub audits: AuditedDependencies,
}

impl AuditsFile {
    pub fn validate(&self) -> Result<(), VetError> {
        // TODO
        // * check that each CriteriaEntry has 'description' or 'description_url'
        // * check that all criteria are valid in:
        //   * CriteriaEntry::implies
        //   * AuditEntry::criteria
        //   * DependencyCriteria
        // * check that all 'audits' entries are well-formed
        // * check that all package names are valid (with crates.io...?)
        // * check that all reviews have a 'who' (currently an Option to stub it out)
        // * catch no-op deltas?
        Ok(())
    }
}

/// Information on a Criteria
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
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
    pub implies: Vec<String>,
}

/// This is conceptually an enum
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct AuditEntry {
    pub who: Option<String>,
    pub notes: Option<String>,
    pub criteria: String,
    #[serde(flatten)]
    pub kind: AuditKind,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(untagged)]
pub enum AuditKind {
    Full {
        version: Version,
        #[serde(rename = "dependency-criteria")]
        #[serde(skip_serializing_if = "DependencyCriteria::is_empty")]
        #[serde(default)]
        dependency_criteria: DependencyCriteria,
    },
    Delta {
        delta: Delta,
        #[serde(rename = "dependency-criteria")]
        #[serde(skip_serializing_if = "DependencyCriteria::is_empty")]
        #[serde(default)]
        dependency_criteria: DependencyCriteria,
    },
    Violation {
        violation: VersionReq,
    },
}

/// A list of criteria that transitive dependencies must satisfy for this
/// audit to continue to be considered valid.
///
/// Example:
///
/// ```toml
/// dependency_criteria = { hmac: ['secure', 'crypto_reviewed'] }
/// ```
pub type DependencyCriteria = StableMap<String, Vec<String>>;

/// A "VERSION -> VERSION"
#[derive(Debug)]
pub struct Delta {
    pub from: Version,
    pub to: Version,
}

impl<'de> Deserialize<'de> for Delta {
    fn deserialize<D>(deserializer: D) -> Result<Delta, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DeltaVisitor;
        impl<'de> Visitor<'de> for DeltaVisitor {
            type Value = Delta;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a delta of the form 'VERSION -> VERSION'")
            }
            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if let Some((from, to)) = s.split_once("->") {
                    Ok(Delta {
                        from: Version::parse(from.trim()).map_err(de::Error::custom)?,
                        to: Version::parse(to.trim()).map_err(de::Error::custom)?,
                    })
                } else {
                    Err(de::Error::invalid_value(de::Unexpected::Str(s), &self))
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
        let output = format!("{} -> {}", self.from, self.to);
        serializer.serialize_str(&output)
    }
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
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ConfigFile {
    /// This top-level key specifies the default criteria that cargo vet certify will use
    /// when recording audits. If unspecified, this defaults to "safe-to-deploy".
    #[serde(rename = "default-criteria")]
    #[serde(default = "get_default_criteria")]
    #[serde(skip_serializing_if = "is_default_criteria")]
    pub default_criteria: String,
    /// Remote audits.toml's that we trust and want to import.
    pub imports: StableMap<String, RemoteImport>,
    /// All of the "foreign" dependencies that we rely on but haven't audited yet.
    /// Foreign dependencies are just "things on crates.io", everything else
    /// (paths, git, etc) is assumed to be "under your control" and therefore implicitly trusted.
    pub unaudited: StableMap<String, Vec<UnauditedDependency>>,
    /// A table of policies for first-party crates.
    pub policy: StableMap<String, PolicyEntry>,
}

impl ConfigFile {
    pub fn validate(&self) -> Result<(), VetError> {
        // TODO
        //
        // * check that policy entries are only first-party
        // * check that unaudited entries are for things that exist?
        // * check that lockfile and imports aren't desync'd (catch new/removed import urls)
        Ok(())
    }
}

pub static SAFE_TO_DEPLOY: &str = "safe-to-deploy";
pub static SAFE_TO_RUN: &str = "safe-to-run";
pub static DEFAULT_CRITERIA: &str = SAFE_TO_DEPLOY;

pub fn get_default_criteria() -> String {
    String::from(DEFAULT_CRITERIA)
}
fn is_default_criteria(val: &String) -> bool {
    val == DEFAULT_CRITERIA
}

/// Policies that first-party (non-foreign) crates must pass.
///
/// This is basically the first-party equivalent of audits.toml, which is separated out
/// because it's not supposed to be shared (or, doesn't really make sense to share,
/// since first-party crates are defined by "not on crates.io").
///
/// Because first-party crates are implicitly trusted, really the only purpose of this
/// table is to define the boundary between a first-party crates and third-party ones.
/// More specifically, the criteria of the dependency edges between a first-party crate
/// and its direct third-party dependencies.
///
/// If this sounds overwhelming, don't worry, everything defaults to "nothing special"
/// and an empty PolicyTable basically just means "everything should satisfy the
/// default criteria in audits.toml".
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PolicyEntry {
    /// Default criteria that must be satisfied by all *direct* third-party (foreign)
    /// dependencies of first-party crates. If satisfied, the first-party crate is
    /// set to satisfying all criteria.
    ///
    /// If not present, this defaults to the default criteria in the audits table.
    #[serde(default = "get_default_policy_criteria")]
    #[serde(skip_serializing_if = "is_default_policy_criteria")]
    pub criteria: Vec<String>,

    /// Same as `criteria`, but for first-party(?) crates/dependencies that are only
    /// used as build-dependencies or dev-dependencies.
    #[serde(rename = "build-and-dev-criteria")]
    #[serde(default = "get_default_policy_build_and_dev_criteria")]
    #[serde(skip_serializing_if = "is_default_policy_build_and_dev_criteria")]
    pub build_and_dev_criteria: Vec<String>,

    /// Custom criteria for a specific first-party crate's dependencies.
    ///
    /// Any dependency edge that isn't explicitly specified defaults to `criteria`.
    #[serde(rename = "dependency-criteria")]
    #[serde(default = "DependencyCriteria::new")]
    #[serde(skip_serializing_if = "DependencyCriteria::is_empty")]
    pub dependency_criteria: DependencyCriteria,

    /// TODO: figure this out
    pub targets: Option<Vec<String>>,

    /// `targets` but build/dev
    #[serde(rename = "build-and-dev-targets")]
    pub build_and_dev_targets: Option<Vec<String>>,
}

pub static DEFAULT_POLICY_CRITERIA: &str = SAFE_TO_DEPLOY;
pub static DEFAULT_POLICY_BUILD_AND_DEV_CRITERIA: &str = SAFE_TO_RUN;

pub fn get_default_policy_criteria() -> Vec<String> {
    vec![]
}
#[allow(clippy::ptr_arg)]
fn is_default_policy_criteria(val: &Vec<String>) -> bool {
    val.is_empty()
}
pub fn get_default_policy_build_and_dev_criteria() -> Vec<String> {
    vec![]
}
#[allow(clippy::ptr_arg)]
fn is_default_policy_build_and_dev_criteria(val: &Vec<String>) -> bool {
    val.is_empty()
}

/// A remote audits.toml that we trust the contents of (by virtue of trusting the maintainer).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RemoteImport {
    /// URL of the foreign audits.toml
    pub url: String,
    /// A list of criteria that are implied by foreign criteria
    #[serde(rename = "criteria-map")]
    pub criteria_map: Vec<CriteriaMapping>,
}

/// Translations of foreign criteria to local criteria.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CriteriaMapping {
    /// This local criteria is implied...
    pub ours: String,
    /// If all of these foreign criteria apply
    pub theirs: Vec<String>,
}

/// Semantically identical to a 'full audit' entry, but private to our project
/// and tracked as less-good than a proper audit, so that you try to get rid of it.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct UnauditedDependency {
    /// The version of the crate that we are currently "fine" with leaving unaudited.
    pub version: Version,
    /// Criteria that we're willing to handwave for this version (assuming our dependencies
    /// satisfy this criteria). This isn't defaulted, 'vet init' and similar commands will
    /// pick a "good" initial value.
    pub criteria: String,
    /// Freeform notes, put whatever you want here. Just more stable/reliable than comments.
    pub notes: Option<String>,
    /// Whether 'suggest' should bother mentioning this (defaults true).
    #[serde(default = "get_default_unaudited_suggest")]
    #[serde(skip_serializing_if = "is_default_unaudited_suggest")]
    pub suggest: bool,
}

static DEFAULT_UNAUDITED_SUGGEST: bool = true;
pub fn get_default_unaudited_suggest() -> bool {
    DEFAULT_UNAUDITED_SUGGEST
}
fn is_default_unaudited_suggest(val: &bool) -> bool {
    val == &DEFAULT_UNAUDITED_SUGGEST
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

/// imports.lock, not sure what I want to put in here yet.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ImportsFile {
    pub audits: StableMap<String, AuditsFile>,
}

impl ImportsFile {
    pub fn validate(&self) -> Result<(), VetError> {
        // TODO
        Ok(())
    }
}
