use std::{
    ffi::OsString,
    fmt::{Debug, Display},
    num::ParseIntError,
    path::{PathBuf, StripPrefixError},
    string::FromUtf8Error,
    sync::Arc,
};

use cargo_metadata::semver;
use miette::{Diagnostic, MietteSpanContents, SourceCode, SourceOffset, SourceSpan};
use thiserror::Error;

use crate::format::{
    CriteriaName, ForeignCriteriaName, ImportName, PackageName, StoreVersion, VetVersion,
};
use crate::network::PayloadEncoding;

#[derive(Eq, PartialEq)]
struct SourceFileInner {
    name: String,
    source: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SourceFile {
    inner: Arc<SourceFileInner>,
}

impl SourceFile {
    pub fn new_empty(name: &str) -> Self {
        Self::new(name, String::new())
    }
    pub fn new(name: &str, source: String) -> Self {
        SourceFile {
            inner: Arc::new(SourceFileInner {
                name: name.to_owned(),
                source,
            }),
        }
    }
    pub fn name(&self) -> &str {
        &self.inner.name
    }
    pub fn source(&self) -> &str {
        &self.inner.source
    }
}

impl SourceCode for SourceFile {
    fn read_span<'a>(
        &'a self,
        span: &SourceSpan,
        context_lines_before: usize,
        context_lines_after: usize,
    ) -> Result<Box<dyn miette::SpanContents<'a> + 'a>, miette::MietteError> {
        let contents = self
            .source()
            .read_span(span, context_lines_before, context_lines_after)?;
        Ok(Box::new(MietteSpanContents::new_named(
            self.name().to_owned(),
            contents.data(),
            *contents.span(),
            contents.line(),
            contents.column(),
            contents.line_count(),
        )))
    }
}

impl Debug for SourceFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceFile")
            .field("name", &self.name())
            .field("source", &self.source())
            .finish()
    }
}

//////////////////////////////////////////////////////////
// VersionParseError
//////////////////////////////////////////////////////////

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VersionParseError {
    #[error(transparent)]
    Semver(#[from] semver::Error),
    #[error("unrecognized revision type, expected 'git:' prefix")]
    UnknownRevision,
    #[error("unrecognized git hash, expected 40 hex digits")]
    InvalidGitHash,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StoreVersionParseError {
    #[error("error parsing version component: {0}")]
    ParseInt(#[from] ParseIntError),
    #[error("missing '.' separator")]
    MissingSeparator,
}

///////////////////////////////////////////////////////////
// AuditAsErrors
///////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[error("There are some issues with your policy.audit-as-crates-io entries")]
#[diagnostic()]
pub struct AuditAsErrors {
    #[related]
    pub errors: Vec<AuditAsError>,
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum AuditAsError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    NeedsAuditAs(NeedsAuditAsErrors),
    #[error(transparent)]
    #[diagnostic(transparent)]
    ShouldntBeAuditAs(ShouldntBeAuditAsErrors),
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnusedAuditAs(UnusedAuditAsErrors),
}

#[derive(Debug, Error, Diagnostic)]
#[diagnostic(help("Add a `policy.*.audit-as-crates-io` entry for them"))]
pub struct NeedsAuditAsErrors {
    pub errors: Vec<PackageError>,
}

impl Display for NeedsAuditAsErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Some non-crates.io-fetched packages match published crates.io versions")?;
        for e in &self.errors {
            f.write_fmt(format_args!("\n  {e}"))?
        }
        Ok(())
    }
}

#[derive(Debug, Error, Diagnostic)]
#[diagnostic(help("Remove the audit-as-crates-io entries or make them `false`"))]
pub struct ShouldntBeAuditAsErrors {
    pub errors: Vec<PackageError>,
}

impl Display for ShouldntBeAuditAsErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("some audit-as-crates-io packages don't match published crates.io versions")?;
        for e in &self.errors {
            f.write_fmt(format_args!("\n  {e}"))?
        }
        Ok(())
    }
}

#[derive(Debug, Error, Diagnostic)]
#[diagnostic(help("Remove the audit-as-crates-io entries"))]
pub struct UnusedAuditAsErrors {
    pub errors: Vec<PackageError>,
}

impl Display for UnusedAuditAsErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("some audit-as-crates-io policies don't match first-party crates")?;
        for e in &self.errors {
            f.write_fmt(format_args!("\n  {e}"))?
        }
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("{package}{}", .version.as_ref().map(|v| format!(":{v}")).unwrap_or_default())]
pub struct PackageError {
    pub package: PackageName,
    pub version: Option<VetVersion>,
}

///////////////////////////////////////////////////////////
// CratePolicyErrors
///////////////////////////////////////////////////////////
#[derive(Debug, Error, Diagnostic, PartialEq, Eq)]
#[error("There are some issues with your third-party policy entries")]
#[diagnostic()]
pub struct CratePolicyErrors {
    #[related]
    pub errors: Vec<CratePolicyError>,
}

#[derive(Debug, Error, Diagnostic, PartialEq, Eq)]
#[non_exhaustive]
pub enum CratePolicyError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    NeedsVersion(NeedsPolicyVersionErrors),
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnusedVersion(UnusedPolicyVersionErrors),
}

#[derive(Debug, Error, Diagnostic, PartialEq, Eq)]
#[diagnostic(help(
    "Specifing `dependency-criteria` requires explicit policies for each version of \
     a crate. Add a `policy.\"<crate>:<version>\"` entry for them."
))]
pub struct NeedsPolicyVersionErrors {
    pub errors: Vec<PackageError>,
}

impl Display for NeedsPolicyVersionErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("some crates have policies that are missing an associated version")?;
        for e in &self.errors {
            f.write_fmt(format_args!("\n  {e}"))?
        }
        Ok(())
    }
}

#[derive(Debug, Error, Diagnostic, PartialEq, Eq)]
#[diagnostic(help("Remove the `policy` entries"))]
pub struct UnusedPolicyVersionErrors {
    pub errors: Vec<PackageError>,
}

impl Display for UnusedPolicyVersionErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("some versioned policy entries don't correspond to crates being used")?;
        for e in &self.errors {
            f.write_fmt(format_args!("\n  {e}"))?
        }
        Ok(())
    }
}

///////////////////////////////////////////////////////////
// CertifyError
///////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum CertifyError {
    #[error("no criteria chosen, aborting")]
    NoCriteriaChosen,
    #[error("couldn't guess what version of {0} to certify, please specify")]
    CouldntGuessVersion(PackageName),
    #[error("couldn't guess what package to certify, please specify")]
    CouldntGuessPackage,
    #[error("couldn't find uncommented certify statement")]
    CouldntFindCertifyStatement,
    #[error("'{0}' isn't one of your foreign packages")]
    #[diagnostic(help("use --force to ignore this error"))]
    NotAPackage(PackageName),
    #[error("'{0}' has not published any relevant version of '{1}'")]
    #[diagnostic(help("please specify a user who has published a version of '{1}'"))]
    NotAPublisher(String, PackageName),
    #[error("end date of {0} is too far in the future")]
    #[diagnostic(help("wildcard audit end dates may be at most 1 year in the future"))]
    BadWildcardEndDate(chrono::NaiveDate),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    EditError(#[from] EditError),
    #[error(transparent)]
    UserInfoError(#[from] UserInfoError),
    #[error(transparent)]
    FetchAuditError(#[from] FetchAuditError),
    #[error(transparent)]
    CacheAcquire(#[from] CacheAcquireError),
}

///////////////////////////////////////////////////////////
// EditError
///////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum EditError {
    #[error("Failed to launch editor")]
    CouldntLaunch(#[source] std::io::Error),
    #[error("Failed to open result of editor")]
    CouldntOpen(#[source] std::io::Error),
    #[error("Failed to read result of editor")]
    CouldntRead(#[source] std::io::Error),
}

///////////////////////////////////////////////////////////
// InitErrors
///////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[error("Failed to initialize the cargo-vet store (supply-chain)")]
#[non_exhaustive]
pub enum InitError {
    StoreCreate(#[source] StoreCreateError),
    StoreCommit(#[source] StoreCommitError),
}

///////////////////////////////////////////////////////////
// StoreErrors
///////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
#[error("Couldn't create the store (supply-chain)")]
pub enum StoreCreateError {
    CouldntCreate(#[source] std::io::Error),
    CouldntAcquire(
        #[from]
        #[source]
        FlockError,
    ),
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum StoreAcquireError {
    #[error("Couldn't acquire the store's (supply-chain's) lock")]
    CouldntLock(
        #[from]
        #[source]
        FlockError,
    ),
    #[error("The supply-chain store was created with an incompatible version of cargo-vet ({0})")]
    #[help("Run cargo vet without --locked to update the store to this version")]
    OutdatedStore(StoreVersion),
    #[error("The supply-chain store was created with a newer version of cargo-vet ({0})")]
    #[help("Update to the latest version using `cargo install cargo-vet`")]
    NewerStore(StoreVersion),
    #[error(transparent)]
    #[diagnostic(transparent)]
    LoadToml(#[from] LoadTomlError),
    #[error("Couldn't acquire the store")]
    IoError(
        #[from]
        #[source]
        std::io::Error,
    ),
    #[error(transparent)]
    #[diagnostic(transparent)]
    Validate(#[from] StoreValidateErrors),
    #[error(transparent)]
    #[diagnostic(transparent)]
    FetchAuditError(#[from] Box<FetchAuditError>),
    #[diagnostic(transparent)]
    #[error(transparent)]
    CriteriaChange(#[from] CriteriaChangeErrors),
    #[diagnostic(transparent)]
    #[error(transparent)]
    CacheAcquire(#[from] Box<CacheAcquireError>),
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
#[error("Failed to commit store")]
pub enum StoreCommitError {
    IoError(
        #[from]
        #[source]
        std::io::Error,
    ),
    StoreToml(
        #[from]
        #[source]
        StoreTomlError,
    ),
}

#[derive(Debug, Error, Diagnostic)]
#[error("Some of your imported audits changed their criteria descriptions")]
#[diagnostic()]
pub struct CriteriaChangeErrors {
    #[related]
    pub errors: Vec<CriteriaChangeError>,
}
#[derive(Debug, Error, Diagnostic)]
#[error("{import_name}'s '{criteria_name}' criteria changed:\n\n{unified_diff}")]
#[diagnostic(help("Run `cargo vet regenerate imports` to accept this new definition"))]
pub struct CriteriaChangeError {
    pub import_name: ImportName,
    pub criteria_name: ForeignCriteriaName,
    pub unified_diff: String,
}

////////////////////////////////////////////////////////////
// StoreValidateErrors
////////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[error("Your cargo-vet store (supply-chain) has consistency errors")]
pub struct StoreValidateErrors {
    #[related]
    pub errors: Vec<StoreValidateError>,
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum StoreValidateError {
    #[diagnostic(transparent)]
    #[error(transparent)]
    InvalidCriteria(InvalidCriteriaError),
    #[diagnostic(transparent)]
    #[error(transparent)]
    BadFormat(BadFormatError),
    #[diagnostic(transparent)]
    #[error(transparent)]
    BadWildcardEndDate(BadWildcardEndDateError),
    #[error("imports.lock is out-of-date with respect to configuration")]
    #[diagnostic(help("run `cargo vet` without --locked to update imports"))]
    ImportsLockOutdated,
}

#[derive(Debug, Error, Diagnostic)]
#[error("'{invalid}' is not a valid criteria name")]
#[diagnostic(help("the possible criteria are {:?}", valid_names))]
pub struct InvalidCriteriaError {
    #[source_code]
    pub source_code: SourceFile,
    #[label]
    pub span: SourceSpan,
    pub invalid: String,
    pub valid_names: Arc<Vec<String>>,
}

#[derive(Debug, Error, Diagnostic)]
#[error("A file in the store is not correctly formatted:\n\n{unified_diff}")]
#[diagnostic(help("run `cargo vet` without --locked to reformat files in the store"))]
pub struct BadFormatError {
    pub unified_diff: String,
}

#[derive(Debug, Error, Diagnostic)]
#[error("'{date}' is more than a year in the future")]
#[diagnostic(help("wildcard audits must end at most a year in the future ({max})"))]
pub struct BadWildcardEndDateError {
    #[source_code]
    pub source_code: SourceFile,
    #[label]
    pub span: SourceSpan,
    pub date: chrono::NaiveDate,
    pub max: chrono::NaiveDate,
}

//////////////////////////////////////////////////////////
// CacheErrors
/////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum CacheAcquireError {
    #[error("Couldn't acquire cache")]
    IoError(
        #[from]
        #[source]
        std::io::Error,
    ),
    #[error("Failed to create cache root dir: {}", target.display())]
    Root {
        target: PathBuf,
        #[source]
        error: std::io::Error,
    },
    #[error("Failed to create cache src dir: {}", target.display())]
    Src {
        target: PathBuf,
        #[source]
        error: std::io::Error,
    },
    #[error("Failed to create cache empty dir: {}", target.display())]
    Empty {
        target: PathBuf,
        #[source]
        error: std::io::Error,
    },
    #[error("Failed to create cache package dir: {}", target.display())]
    Cache {
        target: PathBuf,
        #[source]
        error: std::io::Error,
    },
    #[error("Couldn't acquire the cache's lock")]
    CouldntLock(
        #[from]
        #[source]
        FlockError,
    ),
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
#[error("Failed to commit cache")]
pub enum CacheCommitError {
    IoError(
        #[from]
        #[source]
        std::io::Error,
    ),
    StoreToml(
        #[from]
        #[source]
        StoreTomlError,
    ),
    StoreJson(
        #[from]
        #[source]
        StoreJsonError,
    ),
}

//////////////////////////////////////////////////////////
/// CommandError
//////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum CommandError {
    #[error("Command failed")]
    CommandFailed(#[source] std::io::Error),
    #[error("Bad status {0}")]
    BadStatus(i32),
    #[error("Wasn't UTF-8")]
    BadOutput(#[source] FromUtf8Error),
}

//////////////////////////////////////////////////////////
// FetchAndDiffError
//////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum FetchAndDiffError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    Diff(#[from] DiffError),
    #[error(transparent)]
    #[diagnostic(transparent)]
    Fetch(#[from] FetchError),
}

//////////////////////////////////////////////////////////
// DiffError
//////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum DiffError {
    #[error("Failed to diff package")]
    CommandError(
        #[from]
        #[source]
        CommandError,
    ),
    #[error("Diff command produced an unexpected path")]
    UnexpectedPath(#[source] StripPrefixError),
    #[error("Diff command produced invalid output")]
    InvalidOutput,
}

//////////////////////////////////////////////////////////
// UserInfoError
//////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum UserInfoError {
    #[error("Failed to get user.name")]
    UserCommandFailed(#[source] CommandError),
    #[error("Failed to get user.email")]
    EmailCommandFailed(#[source] CommandError),
}

//////////////////////////////////////////////////////////
// FetchError
//////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum FetchError {
    #[error("Invalid URL for package: {url}")]
    InvalidUrl {
        url: String,
        #[source]
        error: url::ParseError,
    },
    #[error("Running as --frozen but needed to fetch {package}:{version}")]
    Frozen {
        package: PackageName,
        version: semver::Version,
    },
    #[error("Failed to unpack .crate at {}", src.display())]
    Unpack {
        src: PathBuf,
        #[source]
        error: UnpackError,
    },
    #[error("failed to open cached .crate at {}", target.display())]
    OpenCached {
        target: std::path::PathBuf,
        #[source]
        error: std::io::Error,
    },
    #[error("Failed to unpack checkout at {}", src.display())]
    UnpackCheckout {
        src: PathBuf,
        #[source]
        error: UnpackCheckoutError,
    },
    #[error("Cannot get source for unknown git commit {git_rev} of {package}")]
    #[help("Only revisions actively used in the dependency graph can be located")]
    UnknownGitRevision {
        package: PackageName,
        git_rev: String,
    },
    #[error(transparent)]
    #[diagnostic(transparent)]
    Download(#[from] DownloadError),
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum UnpackError {
    #[error("Failed to iterate archive")]
    ArchiveIterate(#[source] std::io::Error),
    #[error("Failed to read archive entry")]
    ArchiveEntry(#[source] std::io::Error),
    #[error("Invalid archive, {} wasn't under {}", entry_path.display(), prefix.to_string_lossy())]
    InvalidPaths {
        entry_path: PathBuf,
        prefix: OsString,
    },
    #[error("Failed to unpack archive entry {}", entry_path.display())]
    Unpack {
        entry_path: PathBuf,
        #[source]
        error: std::io::Error,
    },
    #[error("Failed to finalize unpack to {}", target.display())]
    LockCreate {
        target: std::path::PathBuf,
        #[source]
        error: std::io::Error,
    },
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum UnpackCheckoutError {
    #[error("Failed to run 'cargo package --list'")]
    CommandError(
        #[from]
        #[source]
        CommandError,
    ),
    #[error("Failed to create directory {path}")]
    CreateDirError {
        path: std::path::PathBuf,
        #[source]
        error: std::io::Error,
    },
    #[error("Failed to copy file contents for {target}")]
    CopyError {
        target: std::path::PathBuf,
        #[source]
        error: std::io::Error,
    },
    #[error("Failed to finalize checkout unpack")]
    LockCreate(#[source] std::io::Error),
}

//////////////////////////////////////////////////////////
// FetchAuditError
//////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum FetchAuditError {
    // FIXME: would have to explicitly import URL for this error
    #[error("invalid URL for foreign import {import_name} @ {import_url}")]
    InvalidUrl {
        import_name: ImportName,
        import_url: String,
        #[source]
        error: url::ParseError,
    },
    #[error("{import_name}'s '{criteria_name}' criteria is missing a description")]
    MissingCriteriaDescription {
        import_name: ImportName,
        criteria_name: ForeignCriteriaName,
    },
    #[error("{import_name}'s '{criteria_name}' criteria description URI is invalid: '{url}'")]
    InvalidCriteriaDescriptionUrl {
        import_name: ImportName,
        criteria_name: ForeignCriteriaName,
        url: String,
        #[source]
        error: url::ParseError,
    },
    #[diagnostic(transparent)]
    #[error(transparent)]
    Download(#[from] DownloadError),
    #[diagnostic(transparent)]
    #[error(transparent)]
    Toml(#[from] LoadTomlError),
    #[diagnostic(transparent)]
    #[error(transparent)]
    Json(#[from] LoadJsonError),
}

//////////////////////////////////////////////////////////
// DownloadError
//////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum DownloadError {
    #[error("failed to start download of {url}")]
    FailedToStartDownload {
        url: Box<reqwest::Url>,
        #[source]
        error: reqwest::Error,
    },
    #[error("failed to create file for download to {}", target.display())]
    FailedToCreateDownload {
        target: std::path::PathBuf,
        #[source]
        error: std::io::Error,
    },
    #[error("failed to read download from {url}")]
    FailedToReadDownload {
        url: Box<reqwest::Url>,
        #[source]
        error: reqwest::Error,
    },
    #[error("failed to write download to {}", target.display())]
    FailedToWriteDownload {
        target: std::path::PathBuf,
        #[source]
        error: std::io::Error,
    },
    #[error("failed to rename download to final location {}", target.display())]
    FailedToFinalizeDownload {
        target: std::path::PathBuf,
        #[source]
        error: std::io::Error,
    },
    #[error("download wasn't valid utf8: {url}")]
    InvalidText {
        url: Box<reqwest::Url>,
        #[source]
        error: FromUtf8Error,
    },
    #[error("download encoding ({encoding}) error")]
    InvalidEncoding {
        encoding: PayloadEncoding,
        #[source]
        error: std::io::Error,
    },
}

//////////////////////////////////////////////////////////
// SuggestError
//////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum SuggestError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    CacheAcquire(#[from] CacheAcquireError),
    #[error(transparent)]
    #[diagnostic(transparent)]
    FetchAudit(#[from] FetchAuditError),
}

//////////////////////////////////////////////////////////
// FlockError
//////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum FlockError {
    #[error("couldn't acquire file lock")]
    IoError(
        #[from]
        #[source]
        std::io::Error,
    ),
}

//////////////////////////////////////////////////////////
// AggregateErrors
//////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[error("there were errors aggregating source audit files")]
#[diagnostic()]
pub struct AggregateErrors {
    #[related]
    pub errors: Vec<AggregateError>,
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum AggregateError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    CriteriaDescriptionMismatch(AggregateCriteriaDescriptionMismatchError),
    #[error(transparent)]
    #[diagnostic(transparent)]
    ImpliesMismatch(AggregateImpliesMismatchError),
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
#[error("criteria description mismatch for {criteria_name}\n{first}\n{second}")]
pub struct AggregateCriteriaDescriptionMismatchError {
    pub criteria_name: CriteriaName,
    pub first: AggregateCriteriaDescription,
    pub second: AggregateCriteriaDescription,
}

#[derive(Debug)]
pub struct AggregateCriteriaDescription {
    pub source: String,
    pub description: Option<String>,
    pub description_url: Option<String>,
}

impl Display for AggregateCriteriaDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Some(description) = &self.description {
            write!(f, "{}:\n{}", self.source, description)
        } else if let Some(description_url) = &self.description_url {
            write!(f, "{}:\n(URL) {}", self.source, description_url)
        } else {
            write!(f, "{}:\n(no description)", self.source)
        }
    }
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
#[error("implied criteria mismatch for {criteria_name}\n{first}\n{second}")]
pub struct AggregateImpliesMismatchError {
    pub criteria_name: CriteriaName,
    pub first: AggregateCriteriaImplies,
    pub second: AggregateCriteriaImplies,
}

#[derive(Debug)]
pub struct AggregateCriteriaImplies {
    pub source: String,
    pub implies: Vec<CriteriaName>,
}

impl Display for AggregateCriteriaImplies {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:", self.source)?;
        for implied in &self.implies {
            write!(f, "\n - {implied}")?;
        }
        Ok(())
    }
}

//////////////////////////////////////////////////////////
// TomlError/JsonError
//////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[error("Failed to parse toml file")]
pub struct TomlParseError {
    #[source_code]
    pub source_code: SourceFile,
    #[label("here")]
    pub span: SourceOffset,
    #[source]
    pub error: toml::de::Error,
}

#[derive(Debug, Error, Diagnostic)]
#[error("Failed to parse json file")]
pub struct JsonParseError {
    // #[source_code]
    // input: SourceFile,
    // #[label("here")]
    // span: SourceOffset,
    #[source]
    pub error: serde_json::Error,
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum LoadTomlError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    TomlParse(#[from] TomlParseError),

    #[error("TOML wasn't valid utf8")]
    InvalidText {
        #[source]
        #[from]
        error: FromUtf8Error,
    },

    #[error("couldn't load toml")]
    IoError(
        #[from]
        #[source]
        std::io::Error,
    ),
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum LoadJsonError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    JsonParse(#[from] JsonParseError),
    #[error("couldn't load json")]
    IoError(
        #[from]
        #[source]
        std::io::Error,
    ),
}

pub type StoreJsonError = serde_json::Error;

pub type StoreTomlError = toml_edit::ser::Error;
