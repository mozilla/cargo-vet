use std::{ffi::OsString, fmt::Display, path::PathBuf, string::FromUtf8Error, sync::Arc};

use cargo_metadata::Version;
use miette::{Diagnostic, NamedSource};
use thiserror::Error;

use crate::format::{ImportName, PackageName};

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
        f.write_str("Some first-party packages match published crates.io versions")?;
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
    CouldntLaunch(#[diagnostic(cause)] std::io::Error),
    #[error("Failed to open result of editor")]
    CouldntOpen(#[diagnostic(cause)] std::io::Error),
    #[error("Failed to read result of editor")]
    CouldntRead(#[diagnostic(cause)] std::io::Error),
}

///////////////////////////////////////////////////////////
// InitErrors
///////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[error("Failed to initialize the cargo-vet store (supply-chain)")]
#[non_exhaustive]
pub enum InitError {
    StoreCreate(#[diagnostic(cause)] StoreCreateError),
    StoreCommit(#[diagnostic(cause)] StoreCommitError),
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
    #[error("An unknown error occured while trying to minimize unaudited entries")]
    Unknown,
}

///////////////////////////////////////////////////////////
// StoreErrors
///////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
#[error("Couldn't create the store (supply-chain)")]
pub enum StoreCreateError {
    CouldntCreate(#[diagnostic(cause)] std::io::Error),
    CouldntAcquire(
        #[from]
        #[diagnostic(cause)]
        FlockError,
    ),
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum StoreAcquireError {
    #[error("Couldn't acquire the store's (supply-chain's) lock")]
    CouldntLock(
        #[from]
        #[diagnostic(cause)]
        FlockError,
    ),
    #[error(transparent)]
    LoadToml(
        #[from]
        #[diagnostic(cause)]
        LoadTomlError,
    ),
    #[error(transparent)]
    IoError(
        #[from]
        #[diagnostic(cause)]
        std::io::Error,
    ),
    #[error(transparent)]
    #[diagnostic(transparent)]
    Validate(#[from] StoreValidateErrors),
}

#[derive(Debug, Error, Diagnostic)]
#[error("Your cargo-vet store (supply-chain) has consistency errors")]
pub struct StoreValidateErrors {
    #[related]
    errors: Vec<StoreValidateError>,
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum StoreValidateError {}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
#[error("Failed to commit store")]
pub enum StoreCommitError {
    IoError(
        #[from]
        #[diagnostic(cause)]
        std::io::Error,
    ),
    StoreToml(
        #[from]
        #[diagnostic(cause)]
        StoreTomlError,
    ),
}

//////////////////////////////////////////////////////////
// CacheErrors
/////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum CacheAcquireError {
    #[error(transparent)]
    IoError(
        #[from]
        #[diagnostic(cause)]
        std::io::Error,
    ),
    #[error("Failed to create cache root dir: {}", target.display())]
    Root {
        target: PathBuf,
        #[diagnostic(cause)]
        error: std::io::Error,
    },
    #[error("Failed to create cache src dir: {}", target.display())]
    Src {
        target: PathBuf,
        #[diagnostic(cause)]
        error: std::io::Error,
    },
    #[error("Failed to create cache empty dir: {}", target.display())]
    Empty {
        target: PathBuf,
        #[diagnostic(cause)]
        error: std::io::Error,
    },
    #[error("Failed to create cache package dir: {}", target.display())]
    Cache {
        target: PathBuf,
        #[diagnostic(cause)]
        error: std::io::Error,
    },
    #[error("Couldn't acquire the cache's lock")]
    CouldntLock(
        #[from]
        #[diagnostic(cause)]
        FlockError,
    ),
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
#[error("Failed to commit cache")]
pub enum CacheCommitError {
    IoError(
        #[from]
        #[diagnostic(cause)]
        std::io::Error,
    ),
    StoreToml(
        #[from]
        #[diagnostic(cause)]
        StoreTomlError,
    ),
    StoreJson(
        #[from]
        #[diagnostic(cause)]
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
    CommandFailed(#[diagnostic(cause)] std::io::Error),
    #[error("Bad status {0}")]
    BadStatus(i32),
    #[error("Wasn't UTF-8")]
    BadOutput(#[diagnostic(cause)] FromUtf8Error),
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
        #[diagnostic(cause)]
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
    UserCommandFailed(#[diagnostic(cause)] CommandError),
    #[error("Failed to get user.email")]
    EmailCommandFailed(#[diagnostic(cause)] CommandError),
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
        #[diagnostic(cause)]
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
        #[diagnostic(cause)]
        error: UnpackError,
    },
    #[error("failed to open cached .crate at {}", target.display())]
    OpenCached {
        target: std::path::PathBuf,
        #[diagnostic(cause)]
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
    ArchiveIterate(#[diagnostic(cause)] std::io::Error),
    #[error("Failed to read archive entry")]
    ArchiveEntry(#[diagnostic(cause)] std::io::Error),
    #[error("Invalid archive, {} wasn't under {}", entry_path.display(), prefix.to_string_lossy())]
    InvalidPaths {
        entry_path: PathBuf,
        prefix: OsString,
    },
    #[error("Failed to unpack archive entry {}", entry_path.display())]
    Unpack {
        entry_path: PathBuf,
        #[diagnostic(cause)]
        error: std::io::Error,
    },
    #[error("Failed to finalize unpack to {}", target.display())]
    LockCreate {
        target: std::path::PathBuf,
        #[diagnostic(cause)]
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
        #[diagnostic(cause)]
        error: url::ParseError,
    },
    #[diagnostic(transparent)]
    #[error(transparent)]
    Download(#[from] DownloadError),
    #[diagnostic(transparent)]
    #[error(transparent)]
    Toml(#[from] TomlParseError),
    #[diagnostic(transparent)]
    #[error(transparent)]
    Validate(#[from] StoreValidateErrors),
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
        #[diagnostic(cause)]
        error: reqwest::Error,
    },
    #[error("failed to create file for download to {}", target.display())]
    FailedToCreateDownload {
        target: std::path::PathBuf,
        #[diagnostic(cause)]
        error: std::io::Error,
    },
    #[error("failed to read download from {url}")]
    FailedToReadDownload {
        url: reqwest::Url,
        #[diagnostic(cause)]
        error: reqwest::Error,
    },
    #[error("failed to write download to {}", target.display())]
    FailedToWriteDownload {
        target: std::path::PathBuf,
        #[diagnostic(cause)]
        error: std::io::Error,
    },
    #[error("failed to rename download to final location {}", target.display())]
    FailedToFinalizeDownload {
        target: std::path::PathBuf,
        #[diagnostic(cause)]
        error: std::io::Error,
    },
    #[error("Download wasn't valid utf8: {url}")]
    InvalidText {
        url: reqwest::Url,
        #[diagnostic(cause)]
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
    #[error(transparent)]
    IoError(
        #[from]
        #[diagnostic(cause)]
        std::io::Error,
    ),
}

//////////////////////////////////////////////////////////
// TomlError/JsonError
//////////////////////////////////////////////////////////

#[derive(Debug, Error, Diagnostic)]
#[error("Failed to parse toml file")]
pub struct TomlParseError {
    // #[source_code]
    // input: SourceFile,
    // #[label("here")]
    // span: SourceOffset,
    #[diagnostic(cause)]
    pub error: toml_edit::de::Error,
}

#[derive(Debug, Error, Diagnostic)]
#[error("Failed to parse json file")]
pub struct JsonParseError {
    // #[source_code]
    // input: SourceFile,
    // #[label("here")]
    // span: SourceOffset,
    #[diagnostic(cause)]
    pub error: serde_json::Error,
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum LoadTomlError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    TomlParse(#[from] TomlParseError),
    #[error(transparent)]
    IoError(
        #[from]
        #[diagnostic(cause)]
        std::io::Error,
    ),
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum LoadJsonError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    JsonParse(#[from] JsonParseError),
    #[error(transparent)]
    IoError(
        #[from]
        #[diagnostic(cause)]
        std::io::Error,
    ),
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum StoreJsonError {
    #[error(transparent)]
    JsonSerialize(#[from] serde_json::Error),
    #[error(transparent)]
    IoError(
        #[from]
        #[diagnostic(cause)]
        std::io::Error,
    ),
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum StoreTomlError {
    #[error(transparent)]
    TomlSerialize(#[from] toml_edit::ser::Error),
    #[error(transparent)]
    IoError(
        #[from]
        #[diagnostic(cause)]
        std::io::Error,
    ),
}
