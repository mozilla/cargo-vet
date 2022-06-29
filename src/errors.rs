use std::{ffi::OsString, fmt::Display, path::PathBuf, string::FromUtf8Error, sync::Arc};

use cargo_metadata::Version;
use miette::{Diagnostic, NamedSource, SourceOffset, SourceSpan};
use thiserror::Error;

use crate::format::{ForeignCriteriaName, ImportName, PackageName};

pub type SourceFile = Arc<NamedSource>;

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
    // FIXME: we should probably just make the caller pass this in?
    #[error(transparent)]
    #[diagnostic(transparent)]
    CacheAcquire(CacheAcquireError),
}

#[derive(Debug, Error, Diagnostic)]
#[diagnostic(help("Add a `policy.*.audit-as-crates-io` entry for them"))]
pub struct NeedsAuditAsErrors {
    pub errors: Vec<NeedsAuditAsError>,
}

impl Display for NeedsAuditAsErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Some non-crates.io-fetched packages match published crates.io versions")?;
        for e in &self.errors {
            f.write_fmt(format_args!("\n  {}", e))?
        }
        Ok(())
    }
}

#[derive(Debug, Error, Diagnostic)]
#[diagnostic(help("Remove the audit-as-crates-io entries or make them `false`"))]
pub struct ShouldntBeAuditAsErrors {
    pub errors: Vec<ShouldntBeAuditAsError>,
}

impl Display for ShouldntBeAuditAsErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("some audit-as-crates-io packages don't match published crates.io versions")?;
        for e in &self.errors {
            f.write_fmt(format_args!("\n  {}", e))?
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
#[error("{package}:{version}")]
pub struct NeedsAuditAsError {
    pub package: PackageName,
    pub version: Version,
}

#[derive(Debug, Error)]
#[error("{package}:{version}")]
pub struct ShouldntBeAuditAsError {
    pub package: PackageName,
    pub version: Version,
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
    NotAPackage(PackageName),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    EditError(#[from] EditError),
    #[error(transparent)]
    UserInfoError(#[from] UserInfoError),
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

//////////////////////////////////////////////////////////
// MinimizeUnauditedError
//////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum MinimizeUnauditedError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    Suggest(#[from] SuggestError),
    #[error("An unknown error occured while trying to minimize exemptions entries")]
    Unknown,
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
        version: Version,
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
    #[diagnostic(transparent)]
    #[error(transparent)]
    Download(#[from] DownloadError),
    #[diagnostic(transparent)]
    #[error(transparent)]
    Toml(#[from] LoadTomlError),
    #[diagnostic(transparent)]
    #[error(transparent)]
    Validate(#[from] StoreValidateErrors),
    #[diagnostic(transparent)]
    #[error(transparent)]
    CriteriaChange(#[from] CriteriaChangeErrors),
}

#[derive(Debug, Error, Diagnostic)]
#[error("Some of your imported audits changed their criteria descriptions")]
#[diagnostic()]
pub struct CriteriaChangeErrors {
    #[related]
    pub errors: Vec<CriteriaChangeError>,
}
#[derive(Debug, Error, Diagnostic)]
// FIXME: it would be rad if this was a diff!
#[error(
    "{import_name}'s '{criteria_name}' criteria changed from\n\n{old_desc}\n\nto\n\n{new_desc}\n"
)]
#[diagnostic(help("Run `cargo vet regenerate imports` to accept this new definition"))]
pub struct CriteriaChangeError {
    pub import_name: ImportName,
    pub criteria_name: ForeignCriteriaName,
    pub old_desc: String,
    pub new_desc: String,
}

//////////////////////////////////////////////////////////
// DownloadError
//////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum DownloadError {
    #[error("failed to start download of {url}")]
    FailedToStartDownload {
        url: reqwest::Url,
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
        url: reqwest::Url,
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
    #[error("Download wasn't valid utf8: {url}")]
    InvalidText {
        url: reqwest::Url,
        #[source]
        error: FromUtf8Error,
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

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum StoreJsonError {
    #[error(transparent)]
    JsonSerialize(#[from] serde_json::Error),
    #[error("couldn't store json")]
    IoError(
        #[from]
        #[source]
        std::io::Error,
    ),
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum StoreTomlError {
    #[error(transparent)]
    TomlSerialize(#[from] toml_edit::ser::Error),
    #[error("couldn't store toml")]
    IoError(
        #[from]
        #[source]
        std::io::Error,
    ),
}
