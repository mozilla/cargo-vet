use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{BufReader, Read, Seek};
use std::ops::Deref;
use std::panic::panic_any;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::{fs, mem};
use std::{fs::File, io::Write, panic, path::PathBuf};

use cargo_metadata::{Metadata, Package, Version};
use clap::{ArgEnum, CommandFactory, Parser, Subcommand};
use console::{style, Term};
use eyre::Context;
use flate2::read::GzDecoder;
use format::{
    AuditEntry, AuditKind, CommandHistory, CriteriaName, CriteriaStr, Delta, DiffCache, DiffStat,
    FetchCommand, MetaConfig, PackageName, VersionReq,
};
use reqwest::blocking as req;
use resolver::{CriteriaMapper, DepGraph, DiffRecommendation};
use serde::{de::Deserialize, ser::Serialize};
use tar::Archive;
use tracing::level_filters::LevelFilter;
use tracing::{error, info, trace, trace_span, warn};

use crate::format::{
    AuditsFile, ConfigFile, CriteriaEntry, DependencyCriteria, ImportsFile, MetaConfigInstance,
    PackageStr, SortedMap, StoreInfo, UnauditedDependency,
};
use crate::resolver::{Conclusion, SuggestItem};

pub mod format;
mod resolver;
mod serialization;
#[cfg(test)]
mod tests;

type VetError = eyre::Report;

#[derive(Parser)]
#[clap(version, about, long_about = None)]
#[clap(propagate_version = true)]
#[clap(bin_name = "cargo")]
enum FakeCli {
    Vet(Cli),
}

#[derive(clap::Args)]
#[clap(version)]
#[clap(bin_name = "cargo vet")]
/// Supply-chain security for Rust
struct Cli {
    /// Subcommands ("no subcommand" is its own subcommand)
    #[clap(subcommand)]
    command: Option<Commands>,

    // Cargo flags we support and forward to e.g. 'cargo metadata'
    #[clap(flatten)]
    manifest: clap_cargo::Manifest,
    #[clap(flatten)]
    workspace: clap_cargo::Workspace,
    #[clap(flatten)]
    features: Features,

    // Top-level flags
    /// Do not pull in new "audits" and try to avoid the network
    #[clap(long)]
    locked: bool,

    /// Do not modify or lock the store (supply-chain) directory
    ///
    /// This is primarily intended for testing and should not be used without good reason.
    #[clap(long)]
    readonly_lockless: bool,

    /// How verbose logging should be (log level)
    #[clap(long)]
    #[clap(default_value_t = LevelFilter::WARN)]
    #[clap(possible_values = ["off", "error", "warn", "info", "debug", "trace"])]
    verbose: LevelFilter,

    /// Instead of stdout, write output to this file
    #[clap(long)]
    output_file: Option<PathBuf>,

    /// Instead of stderr, write logs to this file (only used after successful CLI parsing)
    #[clap(long)]
    log_file: Option<PathBuf>,

    /// The format of the output
    #[clap(long, arg_enum)]
    #[clap(default_value_t = OutputFormat::Human)]
    output_format: OutputFormat,

    /// Use the following path as the diff-cache
    ///
    /// The diff-cache stores the summary results used by vet's suggestion machinery.
    /// This is automatically managed in vet's tempdir, but if you want to manually store
    /// it somewhere more reliable, you can.
    ///
    /// This mostly exists for testing vet itself.
    #[clap(long)]
    diff_cache: Option<PathBuf>,

    /// Filter out different parts of the build graph and pretend that's the true graph
    ///
    /// Example: `--filter-graph="exclude(any(eq(is_dev_only(true)),eq(name(serde_derive))))"`
    ///
    /// This mostly exists to debug or reduce projects that cargo-vet is mishandling.
    /// Combining this with `cargo vet --output-format=json dump-graph` can produce an
    /// input that can be added to vet's test suite.
    ///
    ///
    /// The resulting graph is computed as follows:
    ///
    /// 1. First compute the original graph
    /// 2. Then apply the filters to find the new set of nodes
    /// 3. Create a new empty graph
    /// 4. For each workspace member that still exists, recursively add it and its dependencies
    ///
    /// This means that any non-workspace package that becomes "orphaned" by the filters will
    /// be implicitly discarded even if it passes the filters.
    ///
    /// Possible filters:
    ///
    /// * `include($query)`: only include packages that match this filter
    /// * `exclude($query)`: exclude packages that match this filter
    ///
    ///
    /// Possible queries:
    ///
    /// * `any($query1, $query2, ...)`: true if any of the listed queries are true
    /// * `all($query1, $query2, ...)`: true if all of the listed queries are true
    /// * `not($query)`: true if the query is false
    /// * `$property`: true if the package has this property
    ///
    ///
    /// Possible properties:
    ///
    /// * `name($string)`: the package's name (i.e. `serde`)
    /// * `version($version)`: the package's version (i.e. `1.2.0`)
    /// * `is_root($bool)`: whether it's a root in the original graph (ignoring dev-deps)
    /// * `is_workspace_member($bool)`: whether the package is a workspace-member (can be tested)
    /// * `is_third_party($bool)`: whether the package is considered third-party by vet
    /// * `is_dev_only($bool)`: whether it's only used by dev (test) builds in the original graph
    #[clap(long)]
    #[clap(verbatim_doc_comment)]
    filter_graph: Option<Vec<GraphFilter>>,
}

#[derive(Subcommand)]
enum Commands {
    /// initialize cargo-vet for your project
    #[clap(disable_version_flag = true)]
    Init(InitArgs),

    /// Accept changes that a foreign audits.toml made to their criteria
    #[clap(disable_version_flag = true)]
    AcceptCriteriaChange(AcceptCriteriaChangeArgs),

    /// Fetch the source of `$package $version`
    #[clap(disable_version_flag = true)]
    Inspect(InspectArgs),

    /// Yield a diff against the last reviewed version
    #[clap(disable_version_flag = true)]
    Diff(DiffArgs),

    /// Mark `$package $version` as reviewed
    #[clap(disable_version_flag = true)]
    Certify(CertifyArgs),

    /// Mark `$package $version` as unaudited
    #[clap(disable_version_flag = true)]
    AddUnaudited(AddUnauditedArgs),

    /// Mark `$package $version` as a violation of policy
    #[clap(disable_version_flag = true)]
    AddViolation(AddViolationArgs),

    /// Suggest some low-hanging fruit to review
    #[clap(disable_version_flag = true)]
    Suggest(SuggestArgs),

    /// Reformat all of vet's files (in case you hand-edited them)
    ///
    /// All commands that access the store (supply-chain) will implicitly do this.
    #[clap(disable_version_flag = true)]
    Fmt(FmtArgs),

    /// Explicitly fetch the imports (foreign audit files)
    ///
    /// Bare `cargo vet` will implicitly do this.
    #[clap(disable_version_flag = true)]
    FetchImports(FetchImportsArgs),

    /// Regenerate the 'unaudited' entries to try to minimize them and make the vet pass
    #[clap(disable_version_flag = true)]
    RegenerateUnaudited(RegenerateUnauditedArgs),

    /// Print a mermaid-js visualization of the cargo build graph as understood by cargo-vet
    #[clap(disable_version_flag = true)]
    DumpGraph(DumpGraphArgs),

    /// Print --help as markdown (for generating docs)
    #[clap(disable_version_flag = true)]
    #[clap(hide = true)]
    HelpMarkdown(HelpMarkdownArgs),
}

#[derive(clap::Args)]
struct InitArgs {}

/// Fetches the crate to a temp location and pushd's to it
#[derive(clap::Args)]
struct InspectArgs {
    /// The package to inspect
    package: PackageName,
    /// The version to inspect
    version: Version,
}

/// Emits a diff of the two versions
#[derive(clap::Args)]
struct DiffArgs {
    /// The package to diff
    package: PackageName,
    /// The base version to diff
    version1: Version,
    /// The target version to diff
    version2: Version,
}

/// Certifies a package as audited
#[derive(clap::Args)]
struct CertifyArgs {
    /// The package to certify as audited
    package: Option<PackageName>,
    /// The version to certify as audited
    version1: Option<Version>,
    /// If present, instead certify a diff from version1->version2
    version2: Option<Version>,
    /// The criteria to certify for this audit
    ///
    /// If not provided, we will prompt you for this information.
    #[clap(long)]
    criteria: Vec<CriteriaName>,
    /// The dependency-criteria to require for this audit to be valid
    ///
    /// If not provided, we will still implicitly require dependencies to satisfy `criteria`.
    #[clap(long)]
    dependency_criteria: Vec<DependencyCriteriaArg>,
    /// Who to name as the auditor
    ///
    /// If not provided, we will collect this information from the local git.
    #[clap(long)]
    who: Option<String>,
    /// A free-form string to include with the new audit entry
    ///
    /// If not provided, there will be no notes.
    #[clap(long)]
    notes: Option<String>,
    /// Accept all criteria without an interactive prompt
    #[clap(long)]
    accept_all: bool,
}

/// Forbids the given version
#[derive(clap::Args)]
struct AddViolationArgs {
    /// The package to forbid
    package: PackageName,
    /// The versions to forbid
    versions: VersionReq,
    /// (???) The criteria to be forbidden (???)
    ///
    /// If not provided, we will prompt you for this information(?)
    #[clap(long)]
    criteria: Vec<CriteriaName>,
    /// Who to name as the auditor
    ///
    /// If not provided, we will collect this information from the local git.
    #[clap(long)]
    who: Option<String>,
    /// A free-form string to include with the new forbid entry
    ///
    /// If not provided, there will be no notes.
    #[clap(long)]
    notes: Option<String>,
}

/// Cerifies the given version
#[derive(clap::Args)]
struct AddUnauditedArgs {
    /// The package to mark as unaudited (trusted)
    package: PackageName,
    /// The version to mark as unaudited
    version: Version,
    /// The criteria to assume (trust)
    ///
    /// If not provided, we will prompt you for this information.
    #[clap(long)]
    criteria: Vec<CriteriaName>,
    /// The dependency-criteria to require for this unaudited entry to be valid
    ///
    /// If not provided, we will still implicitly require dependencies to satisfy `criteria`.
    #[clap(long)]
    dependency_criteria: Vec<DependencyCriteriaArg>,
    /// A free-form string to include with the new forbid entry
    ///
    /// If not provided, there will be no notes.
    #[clap(long)]
    notes: Option<String>,
    /// Suppress suggesting this unaudited entry
    #[clap(long)]
    no_suggest: bool,
}

#[derive(clap::Args)]
struct SuggestArgs {
    /// Try to suggest even deeper down the dependency tree (approximate guessing).
    ///
    /// By default, if a dependency doesn't have sufficient audits for *itself* then we won't
    /// try to speculate on anything about its dependencies, because we lack sufficient
    /// information to say for certain what is required of those dependencies. This overrides
    /// that by making us assume the dependencies all need the same criteria as the parent.
    #[clap(long)]
    guess_deeper: bool,
}

#[derive(clap::Args)]
struct FmtArgs {}

#[derive(clap::Args)]
struct FetchImportsArgs {}

#[derive(clap::Args)]
struct RegenerateUnauditedArgs {}

#[derive(clap::Args)]
struct AcceptCriteriaChangeArgs {}

#[derive(clap::Args)]
struct HelpMarkdownArgs {}

/// Cargo feature flags, copied from clap_cargo to change defaults.
#[derive(Default, Clone, Debug, PartialEq, Eq, clap::Args)]
#[non_exhaustive]
pub struct Features {
    #[clap(long)]
    /// Don't use --all-features
    ///
    /// We default to passing --all-features to `cargo metadata`
    /// because we want to analyze your full dependency tree
    pub no_all_features: bool,
    #[clap(long)]
    /// Do not activate the `default` feature
    pub no_default_features: bool,
    #[clap(long, require_value_delimiter = true, value_delimiter = ' ')]
    /// Space-separated list of features to activate
    pub features: Vec<String>,
}

#[derive(clap::Args)]
pub struct DumpGraphArgs {
    /// The depth of the graph to print (for a large project, the full graph is a HUGE MESS).
    #[clap(long, arg_enum)]
    #[clap(default_value_t = DumpGraphDepth::FirstParty)]
    pub depth: DumpGraphDepth,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
pub enum DumpGraphDepth {
    Roots,
    Workspace,
    FirstParty,
    FirstPartyAndDirects,
    Full,
}

/// Logging verbosity levels
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
pub enum Verbose {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Clone, Debug)]
pub struct DependencyCriteriaArg {
    pub dependency: PackageName,
    pub criteria: CriteriaName,
}

impl FromStr for DependencyCriteriaArg {
    // the error must be owned as well
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use nom::{
            bytes::complete::{is_not, tag},
            combinator::all_consuming,
            error::{convert_error, VerboseError},
            sequence::tuple,
            Finish, IResult,
        };
        type ParseResult<I, O> = IResult<I, O, VerboseError<I>>;

        fn parse(input: &str) -> ParseResult<&str, DependencyCriteriaArg> {
            let (rest, (dependency, _, criteria)) =
                all_consuming(tuple((is_not(":"), tag(":"), is_not(":"))))(input)?;
            Ok((
                rest,
                DependencyCriteriaArg {
                    dependency: dependency.to_string(),
                    criteria: criteria.to_string(),
                },
            ))
        }

        match parse(s).finish() {
            Ok((_remaining, val)) => Ok(val),
            Err(e) => Err(convert_error(s, e)),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

impl Cli {
    #[cfg(test)]
    pub fn mock() -> Self {
        Self {
            command: None,
            manifest: clap_cargo::Manifest::default(),
            workspace: clap_cargo::Workspace::default(),
            features: Features::default(),
            locked: false,
            readonly_lockless: true,
            verbose: LevelFilter::OFF,
            output_file: None,
            output_format: OutputFormat::Human,
            log_file: None,
            diff_cache: None,
            filter_graph: None,
        }
    }
}

/// Absolutely All The Global Configurations
pub struct Config {
    /// Cargo.toml `metadata.vet`
    metacfg: MetaConfig,
    /// `cargo metadata`
    metadata: Metadata,
    /// Freestanding configuration values
    _rest: PartialConfig,
}

/// Configuration vars that are available in a free-standing situation
/// (no actual cargo-vet instance to load/query).
pub struct PartialConfig {
    /// Details of the CLI invocation (args)
    cli: Cli,
    /// Path to the `cargo` binary that invoked us
    cargo: OsString,
    /// Path to the cargo's home, whose registry/cache, we opportunistically use for inspect/diff
    cargo_home: Option<PathBuf>,
    /// Path to the global tmp we're using
    tmp: PathBuf,
}

// Makes it a bit easier to have both a "partial" and "full" config
impl Deref for Config {
    type Target = PartialConfig;
    fn deref(&self) -> &Self::Target {
        &self._rest
    }
}

#[derive(Clone, Debug)]
pub enum GraphFilter {
    Include(GraphFilterQuery),
    Exclude(GraphFilterQuery),
}

#[derive(Clone, Debug)]
pub enum GraphFilterQuery {
    Any(Vec<GraphFilterQuery>),
    All(Vec<GraphFilterQuery>),
    Not(Box<GraphFilterQuery>),
    Prop(GraphFilterProperty),
}

#[derive(Clone, Debug)]
pub enum GraphFilterProperty {
    Name(PackageName),
    Version(Version),
    IsRoot(bool),
    IsWorkspaceMember(bool),
    IsThirdParty(bool),
    IsDevOnly(bool),
}

impl FromStr for GraphFilter {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use nom::{
            branch::alt,
            bytes::complete::{is_not, tag},
            character::complete::multispace0,
            combinator::{all_consuming, cut},
            error::{convert_error, ParseError, VerboseError, VerboseErrorKind},
            multi::separated_list1,
            sequence::delimited,
            Finish, IResult,
        };
        type ParseResult<I, O> = IResult<I, O, VerboseError<I>>;

        fn parse(input: &str) -> ParseResult<&str, GraphFilter> {
            all_consuming(alt((include_filter, exclude_filter)))(input)
        }
        fn include_filter(input: &str) -> ParseResult<&str, GraphFilter> {
            let (rest, val) =
                delimited(ws(tag("include(")), cut(filter_query), ws(tag(")")))(input)?;
            Ok((rest, GraphFilter::Include(val)))
        }
        fn exclude_filter(input: &str) -> ParseResult<&str, GraphFilter> {
            let (rest, val) =
                delimited(ws(tag("exclude(")), cut(filter_query), ws(tag(")")))(input)?;
            Ok((rest, GraphFilter::Exclude(val)))
        }
        fn filter_query(input: &str) -> ParseResult<&str, GraphFilterQuery> {
            alt((any_query, all_query, not_query, prop_query))(input)
        }
        fn any_query(input: &str) -> ParseResult<&str, GraphFilterQuery> {
            let (rest, val) = delimited(
                ws(tag("any(")),
                cut(separated_list1(tag(","), cut(filter_query))),
                ws(tag(")")),
            )(input)?;
            Ok((rest, GraphFilterQuery::Any(val)))
        }
        fn all_query(input: &str) -> ParseResult<&str, GraphFilterQuery> {
            let (rest, val) = delimited(
                ws(tag("all(")),
                cut(separated_list1(tag(","), cut(filter_query))),
                ws(tag(")")),
            )(input)?;
            Ok((rest, GraphFilterQuery::All(val)))
        }
        fn not_query(input: &str) -> ParseResult<&str, GraphFilterQuery> {
            let (rest, val) = delimited(ws(tag("not(")), cut(filter_query), ws(tag(")")))(input)?;
            Ok((rest, GraphFilterQuery::Not(Box::new(val))))
        }
        fn prop_query(input: &str) -> ParseResult<&str, GraphFilterQuery> {
            let (rest, val) = filter_property(input)?;
            Ok((rest, GraphFilterQuery::Prop(val)))
        }
        fn filter_property(input: &str) -> ParseResult<&str, GraphFilterProperty> {
            alt((
                prop_name,
                prop_version,
                prop_is_root,
                prop_is_workspace_member,
                prop_is_third_party,
                prop_is_dev_only,
            ))(input)
        }
        fn prop_name(input: &str) -> ParseResult<&str, GraphFilterProperty> {
            let (rest, val) =
                delimited(ws(tag("name(")), cut(val_package_name), ws(tag(")")))(input)?;
            Ok((rest, GraphFilterProperty::Name(val.to_string())))
        }
        fn prop_version(input: &str) -> ParseResult<&str, GraphFilterProperty> {
            let (rest, val) =
                delimited(ws(tag("version(")), cut(val_version), ws(tag(")")))(input)?;
            Ok((rest, GraphFilterProperty::Version(val)))
        }
        fn prop_is_root(input: &str) -> ParseResult<&str, GraphFilterProperty> {
            let (rest, val) = delimited(ws(tag("is_root(")), cut(val_bool), ws(tag(")")))(input)?;
            Ok((rest, GraphFilterProperty::IsRoot(val)))
        }
        fn prop_is_workspace_member(input: &str) -> ParseResult<&str, GraphFilterProperty> {
            let (rest, val) =
                delimited(ws(tag("is_workspace_member(")), cut(val_bool), ws(tag(")")))(input)?;
            Ok((rest, GraphFilterProperty::IsWorkspaceMember(val)))
        }
        fn prop_is_third_party(input: &str) -> ParseResult<&str, GraphFilterProperty> {
            let (rest, val) =
                delimited(ws(tag("is_third_party(")), cut(val_bool), ws(tag(")")))(input)?;
            Ok((rest, GraphFilterProperty::IsThirdParty(val)))
        }
        fn prop_is_dev_only(input: &str) -> ParseResult<&str, GraphFilterProperty> {
            let (rest, val) =
                delimited(ws(tag("is_dev_only(")), cut(val_bool), ws(tag(")")))(input)?;
            Ok((rest, GraphFilterProperty::IsDevOnly(val)))
        }
        fn val_bool(input: &str) -> ParseResult<&str, bool> {
            alt((val_true, val_false))(input)
        }
        fn val_true(input: &str) -> ParseResult<&str, bool> {
            let (rest, _val) = ws(tag("true"))(input)?;
            Ok((rest, true))
        }
        fn val_false(input: &str) -> ParseResult<&str, bool> {
            let (rest, _val) = ws(tag("false"))(input)?;
            Ok((rest, false))
        }
        fn val_package_name(input: &str) -> ParseResult<&str, &str> {
            is_not(") ")(input)
        }
        fn val_version(input: &str) -> ParseResult<&str, Version> {
            let (rest, val) = is_not(") ")(input)?;
            let val = Version::from_str(val).map_err(|_e| {
                nom::Err::Failure(VerboseError {
                    errors: vec![(val, VerboseErrorKind::Context("version parse error"))],
                })
            })?;
            Ok((rest, val))
        }
        fn ws<'a, F: 'a, O, E: ParseError<&'a str>>(
            inner: F,
        ) -> impl FnMut(&'a str) -> IResult<&'a str, O, E>
        where
            F: Fn(&'a str) -> IResult<&'a str, O, E>,
        {
            delimited(multispace0, inner, multispace0)
        }

        match parse(s).finish() {
            Ok((_remaining, val)) => Ok(val),
            Err(e) => Err(convert_error(s, e)),
        }
    }
}

// tmp cache for various shenanigans
static TEMP_DIR_SUFFIX: &str = "cargo-vet-checkout";
static TEMP_DIFF_CACHE: &str = "diff-cache.toml";
static TEMP_COMMAND_HISTORY: &str = "command-history.json";
static TEMP_EMPTY_PACKAGE: &str = "empty";
static TEMP_REGISTRY_SRC: &str = "packages";
static TEMP_LOCKFILE: &str = "lockfile";

// Various cargo values
static CARGO_ENV: &str = "CARGO";
static CARGO_REGISTRY: &str = "registry";
static CARGO_REGISTRY_SRC: &str = "src";
static CARGO_REGISTRY_CACHE: &str = "cache";
static CARGO_OK_FILE: &str = ".cargo-ok";
static CARGO_OK_BODY: &str = "ok";

static DEFAULT_STORE: &str = "supply-chain";
// package.metadata.vet
static PACKAGE_VET_CONFIG: &str = "vet";
// workspace.metadata.vet
static WORKSPACE_VET_CONFIG: &str = "vet";

static AUDITS_TOML: &str = "audits.toml";
static CONFIG_TOML: &str = "config.toml";
static IMPORTS_LOCK: &str = "imports.lock";
static STORE_LOCKFILE: &str = "lockfile";

pub trait PackageExt {
    fn is_third_party(&self) -> bool;
}

impl PackageExt for Package {
    fn is_third_party(&self) -> bool {
        self.source
            .as_ref()
            .map(|s| s.is_crates_io())
            .unwrap_or(false)
    }
}

/// Trick to let us std::process::exit while still cleaning up
/// by panicking with this type instead of a string.
struct ExitPanic(i32);

fn main() -> Result<(), VetError> {
    // Wrap main up in a catch_panic so that we can use it to implement std::process::exit with
    // unwinding, allowing us to silently exit the program while still cleaning up.
    let result = std::panic::catch_unwind(real_main);
    match result {
        Ok(main_result) => main_result,
        Err(e) => {
            if let Some(ExitPanic(code)) = e.downcast_ref::<ExitPanic>() {
                // Exit panic, just silently exit with this status
                std::process::exit(*code);
            } else {
                // Normal panic, let it ride
                std::panic::resume_unwind(e);
            }
        }
    }
}

fn real_main() -> Result<(), VetError> {
    use Commands::*;

    let fake_cli = FakeCli::parse();
    let FakeCli::Vet(cli) = fake_cli;

    //////////////////////////////////////////////////////
    // Setup logging / output
    //////////////////////////////////////////////////////

    // Init the logger (and make trace logging less noisy)
    if let Some(log_path) = &cli.log_file {
        let log_file = File::create(log_path).unwrap();
        tracing_subscriber::fmt::fmt()
            .with_max_level(cli.verbose)
            .with_target(false)
            .without_time()
            .with_ansi(false)
            .with_writer(log_file)
            .init();
    } else {
        tracing_subscriber::fmt::fmt()
            .with_max_level(cli.verbose)
            .with_target(false)
            .without_time()
            .with_writer(std::io::stderr)
            .init();
    }

    // Set a panic hook to redirect to the logger
    panic::set_hook(Box::new(|panic_info| {
        if let Some(ExitPanic(_)) = panic_info.payload().downcast_ref::<ExitPanic>() {
            // Be silent, we're just trying to std::process::exit
            return;
        }
        let (filename, line) = panic_info
            .location()
            .map(|loc| (loc.file(), loc.line()))
            .unwrap_or(("<unknown>", 0));

        let cause = panic_info
            .payload()
            .downcast_ref::<String>()
            .map(String::deref)
            .unwrap_or_else(|| {
                panic_info
                    .payload()
                    .downcast_ref::<&str>()
                    .copied()
                    .unwrap_or("<cause unknown>")
            });
        error!(
            "Panic - A panic occurred at {}:{}: {}",
            filename, line, cause
        );
    }));

    // Setup our output stream
    let mut stdout;
    let mut output_f;
    let out: &mut dyn Write = if let Some(output_path) = &cli.output_file {
        output_f = File::create(output_path).unwrap();
        &mut output_f
    } else {
        stdout = std::io::stdout();
        &mut stdout
    };

    ////////////////////////////////////////////////////
    // Potentially handle freestanding commands
    ////////////////////////////////////////////////////

    // TODO: make this configurable
    let cargo = std::env::var_os(CARGO_ENV).expect("Cargo failed to set $CARGO, how?");
    let tmp = std::env::temp_dir().join(TEMP_DIR_SUFFIX);
    let cargo_home = home::cargo_home().ok();
    let partial_cfg = PartialConfig {
        cli,
        cargo,
        tmp,
        cargo_home,
    };

    match &partial_cfg.cli.command {
        Some(Inspect(sub_args)) => return cmd_inspect(out, &partial_cfg, sub_args),
        Some(Diff(sub_args)) => return cmd_diff(out, &partial_cfg, sub_args),
        Some(HelpMarkdown(sub_args)) => return cmd_help_md(out, &partial_cfg, sub_args),
        _ => {
            // Not a freestanding command, time to do full parsing and setup
        }
    }

    ///////////////////////////////////////////////////
    // Fetch cargo metadata
    ///////////////////////////////////////////////////

    let cli = &partial_cfg.cli;
    let mut cmd = cargo_metadata::MetadataCommand::new();
    cmd.cargo_path(&partial_cfg.cargo);
    if let Some(manifest_path) = &cli.manifest.manifest_path {
        cmd.manifest_path(manifest_path);
    }
    if !cli.features.no_all_features {
        cmd.features(cargo_metadata::CargoOpt::AllFeatures);
    }
    if cli.features.no_default_features {
        cmd.features(cargo_metadata::CargoOpt::NoDefaultFeatures);
    }
    if !cli.features.features.is_empty() {
        cmd.features(cargo_metadata::CargoOpt::SomeFeatures(
            cli.features.features.clone(),
        ));
    }
    let mut other_options = Vec::new();
    if cli.workspace.all || cli.workspace.workspace {
        other_options.push("--workspace".to_string());
    }
    for package in &cli.workspace.package {
        other_options.push("--package".to_string());
        other_options.push(package.to_string());
    }
    for package in &cli.workspace.exclude {
        other_options.push("--exclude".to_string());
        other_options.push(package.to_string());
    }
    // We never want cargo-vet to update the Cargo.lock.
    // For locked runs we don't want to touch the network so use --frozen
    // For unlocked runs we want to error out if the lock is out of date, so use --locked
    if cli.locked {
        other_options.push("--frozen".to_string());
    } else {
        other_options.push("--locked".to_string());
    }
    cmd.other_options(other_options);

    info!("Running: {:#?}", cmd.cargo_command());

    let metadata = match cmd.exec() {
        Ok(metadata) => metadata,
        Err(e) => {
            error!("'cargo metadata' failed: {}", e);
            panic_any(ExitPanic(-1));
        }
    };

    // trace!("Got Metadata! {:#?}", metadata);
    trace!("Got Metadata!");

    //////////////////////////////////////////////////////
    // Parse out our own configuration
    //////////////////////////////////////////////////////

    let default_config = MetaConfigInstance {
        version: Some(1),
        store: Some(StoreInfo {
            path: Some(
                metadata
                    .workspace_root
                    .join(DEFAULT_STORE)
                    .into_std_path_buf(),
            ),
        }),
    };

    let workspace_metacfg = || -> Option<MetaConfigInstance> {
        // FIXME: what is `store.path` relative to here?
        MetaConfigInstance::deserialize(metadata.workspace_metadata.get(WORKSPACE_VET_CONFIG)?)
            .map_err(|e| {
                error!(
                    "Workspace had [{WORKSPACE_VET_CONFIG}] but it was malformed: {}",
                    e
                );
                panic_any(ExitPanic(-1));
            })
            .ok()
    }();

    let package_metacfg = || -> Option<MetaConfigInstance> {
        // FIXME: what is `store.path` relative to here?
        MetaConfigInstance::deserialize(metadata.root_package()?.metadata.get(PACKAGE_VET_CONFIG)?)
            .map_err(|e| {
                error!(
                    "Root package had [{PACKAGE_VET_CONFIG}] but it was malformed: {}",
                    e
                );
                panic_any(ExitPanic(-1));
            })
            .ok()
    }();

    if workspace_metacfg.is_some() && package_metacfg.is_some() {
        error!("Both a workspace and a package defined [metadata.vet]! We don't know what that means, if you do, let us know!");
        panic_any(ExitPanic(-1));
    }

    let mut metacfgs = vec![default_config];
    if let Some(metacfg) = workspace_metacfg {
        metacfgs.push(metacfg);
    }
    if let Some(metacfg) = package_metacfg {
        metacfgs.push(metacfg);
    }
    let metacfg = MetaConfig(metacfgs);

    info!("Final Metadata Config: ");
    info!("  - version: {}", metacfg.version());
    info!("  - store.path: {:#?}", metacfg.store_path());

    //////////////////////////////////////////////////////
    // Run the actual command
    //////////////////////////////////////////////////////

    let init = is_init(&metacfg);
    if matches!(cli.command, Some(Commands::Init { .. })) {
        if init {
            error!(
                "'cargo vet' already initialized (store found at {:#?})",
                metacfg.store_path()
            );
            panic_any(ExitPanic(-1));
        }
    } else if !init {
        error!(
            "You must run 'cargo vet init' (store not found at {:#?})",
            metacfg.store_path()
        );
        panic_any(ExitPanic(-1));
    }

    let cfg = Config {
        metacfg,
        metadata,
        _rest: partial_cfg,
    };

    match &cfg.cli.command {
        None => cmd_vet(out, &cfg),
        Some(Init(sub_args)) => cmd_init(out, &cfg, sub_args),
        Some(AcceptCriteriaChange(sub_args)) => cmd_accept_criteria_change(out, &cfg, sub_args),
        Some(Certify(sub_args)) => cmd_certify(out, &cfg, sub_args),
        Some(AddUnaudited(sub_args)) => cmd_add_unaudited(out, &cfg, sub_args),
        Some(AddViolation(sub_args)) => cmd_add_violation(out, &cfg, sub_args),
        Some(Suggest(sub_args)) => cmd_suggest(out, &cfg, sub_args),
        Some(Fmt(sub_args)) => cmd_fmt(out, &cfg, sub_args),
        Some(FetchImports(sub_args)) => cmd_fetch_imports(out, &cfg, sub_args),
        Some(RegenerateUnaudited(sub_args)) => cmd_regenerate_unaudited(out, &cfg, sub_args),
        Some(DumpGraph(sub_args)) => cmd_dump_graph(out, &cfg, sub_args),
        // Need to be non-exhaustive because freestanding commands were handled earlier
        _ => unreachable!("did you add a new command and forget to implement it?"),
    }
}

fn cmd_init(_out: &mut dyn Write, cfg: &Config, _sub_args: &InitArgs) -> Result<(), VetError> {
    // Initialize vet

    // TODO: use Store::create or something else to make this transactional?

    // Create store_path
    // - audits.toml (empty, sample criteria)
    // - imports.lock (empty)
    // - config.toml (populated with defaults and full list of third-party crates)
    trace!("initializing...");

    let store_path = cfg.metacfg.store_path();

    let (config, audits, imports) = init_files(&cfg.metadata, cfg.cli.filter_graph.as_ref())?;

    // In theory we don't need `all` here, but this allows them to specify
    // the store as some arbitrarily nested subdir for whatever reason
    // (maybe multiple parallel instances?)
    std::fs::create_dir_all(store_path)?;
    store_audits(store_path, audits)?;
    store_imports(store_path, imports)?;
    store_config(store_path, config)?;

    Ok(())
}

pub fn init_files(
    metadata: &Metadata,
    filter_graph: Option<&Vec<GraphFilter>>,
) -> Result<(ConfigFile, AuditsFile, ImportsFile), VetError> {
    // Default audits file is empty
    let audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: SortedMap::new(),
    };

    // Default imports file is empty
    let imports = ImportsFile {
        audits: SortedMap::new(),
    };

    // TODO: pipe in cfg and filter_graph
    // This is the hard one
    let config = {
        let mut dependencies = SortedMap::new();
        let graph = DepGraph::new(metadata, filter_graph);
        for package in &graph.nodes {
            if !package.is_third_party {
                // Only care about third-party packages
                continue;
            }
            let criteria = if package.is_dev_only {
                format::DEFAULT_POLICY_DEV_CRITERIA.to_string()
            } else {
                format::DEFAULT_POLICY_CRITERIA.to_string()
            };
            // NOTE: May have multiple copies of a package!
            let item = UnauditedDependency {
                version: package.version.clone(),
                criteria,
                dependency_criteria: DependencyCriteria::new(),
                notes: None,
                suggest: true,
            };
            dependencies
                .entry(package.name.to_string())
                .or_insert(vec![])
                .push(item);
        }
        ConfigFile {
            default_criteria: format::get_default_criteria(),
            imports: SortedMap::new(),
            unaudited: dependencies,
            policy: SortedMap::new(),
        }
    };

    Ok((config, audits, imports))
}

fn cmd_inspect(
    out: &mut dyn Write,
    cfg: &PartialConfig,
    sub_args: &InspectArgs,
) -> Result<(), VetError> {
    // Download a crate's source to a temp location for review
    let mut cache = Cache::acquire(cfg)?;
    // Record this command for magic in `vet certify`
    cache.command_history.last_fetch = Some(FetchCommand::Inspect {
        package: sub_args.package.clone(),
        version: sub_args.version.clone(),
    });

    let package = &*sub_args.package;

    let to_fetch = &[(package, &sub_args.version)];
    let fetched_paths = cache.fetch_packages(to_fetch)?;
    let fetched = &fetched_paths[package][&sub_args.version];

    #[cfg(target_family = "unix")]
    {
        // Loosely borrowed from cargo crev.
        use std::os::unix::process::CommandExt;
        let shell = std::env::var_os("SHELL").unwrap();
        writeln!(out, "Opening nested shell in: {:#?}", fetched)?;
        writeln!(out, "Use `exit` or Ctrl-D to finish.",)?;
        let mut command = std::process::Command::new(shell);
        command.current_dir(fetched.clone()).env("PWD", fetched);
        command.exec();
    }

    #[cfg(not(target_family = "unix"))]
    {
        writeln!(out, "  fetched to {:#?}", fetched)?;
    }

    Ok(())
}

fn cmd_certify(out: &mut dyn Write, cfg: &Config, sub_args: &CertifyArgs) -> Result<(), VetError> {
    // Certify that you have reviewed a crate's source for some version / delta
    let mut store = Store::acquire(cfg)?;
    // Grab the command history and immediately drop the cache
    let command_history = Cache::acquire(cfg)?.command_history.clone();

    let term = Term::stdout();
    let dependency_criteria = if sub_args.dependency_criteria.is_empty() {
        // TODO: look at the current audits to infer this? prompt?
        DependencyCriteria::new()
    } else {
        let mut dep_criteria = DependencyCriteria::new();
        for arg in &sub_args.dependency_criteria {
            dep_criteria
                .entry(arg.dependency.clone())
                .or_insert_with(Vec::new)
                .push(arg.criteria.clone());
        }
        dep_criteria
    };

    let package = if let Some(package) = &sub_args.package {
        package.clone()
    } else if let Some(FetchCommand::Inspect { package, .. } | FetchCommand::Diff { package, .. }) =
        &command_history.last_fetch
    {
        package.clone()
    } else {
        writeln!(
            out,
            "error: couldn't guess what package to certify, please specify"
        )?;
        panic_any(ExitPanic(-1));
    };

    let kind = if let Some(v1) = &sub_args.version1 {
        if let Some(v2) = &sub_args.version2 {
            // This is a delta audit
            AuditKind::Delta {
                delta: Delta {
                    from: v1.clone(),
                    to: v2.clone(),
                },
                dependency_criteria,
            }
        } else {
            // This is a full audit
            AuditKind::Full {
                version: v1.clone(),
                dependency_criteria,
            }
        }
    } else if let Some(fetch) = &command_history.last_fetch {
        match fetch {
            FetchCommand::Inspect {
                package: package_name,
                version,
            } if package_name == &package => AuditKind::Full {
                version: version.clone(),
                dependency_criteria: DependencyCriteria::new(),
            },
            FetchCommand::Diff {
                package: package_name,
                version1,
                version2,
            } if package_name == &package => AuditKind::Delta {
                delta: Delta {
                    from: version1.clone(),
                    to: version2.clone(),
                },
                dependency_criteria: DependencyCriteria::new(),
            },
            _ => {
                writeln!(
                    out,
                    "error: couldn't guess what version to certify, please specify"
                )?;
                panic_any(ExitPanic(-1));
            }
        }
    } else {
        writeln!(
            out,
            "error: couldn't guess what version to certify, please specify"
        )?;
        panic_any(ExitPanic(-1));
    };

    let (username, who) = if let Some(who) = &sub_args.who {
        (who.clone(), Some(who.clone()))
    } else {
        let user_info = get_user_info()?;
        let who = format!("{} <{}>", user_info.username, user_info.email);
        (user_info.username, Some(who))
    };

    let criteria_mapper = CriteriaMapper::new(&store.audits.criteria);

    let criteria_names = if sub_args.criteria.is_empty() {
        // Try to guess the criteria based on any previous suggest
        let mut chosen_criteria = command_history
            .last_suggest
            .into_iter()
            .find(|s| s.command.package() == package)
            .map(|s| s.criteria)
            .unwrap_or_default();

        // Prompt for criteria
        loop {
            term.clear_screen()?;
            write!(out, "choose criteria to certify for {}", package)?;
            match &kind {
                AuditKind::Full { version, .. } => write!(out, ":{}", version)?,
                AuditKind::Delta { delta, .. } => write!(out, ":{} -> {}", delta.from, delta.to)?,
                AuditKind::Violation { .. } => unreachable!(),
            }
            writeln!(out)?;
            writeln!(out, "  0. <clear selections>")?;
            let implied_criteria = criteria_mapper.criteria_from_list(&chosen_criteria);
            for (criteria_idx, (criteria_name, _criteria_entry)) in
                criteria_mapper.list.iter().enumerate()
            {
                if chosen_criteria.contains(criteria_name) {
                    writeln!(
                        out,
                        "  {}. {}",
                        criteria_idx + 1,
                        style(criteria_name).green()
                    )?;
                } else if implied_criteria.has_criteria(criteria_idx) {
                    writeln!(
                        out,
                        "  {}. {}",
                        criteria_idx + 1,
                        style(criteria_name).yellow()
                    )?;
                } else {
                    writeln!(out, "  {}. {}", criteria_idx + 1, criteria_name)?;
                }
            }

            writeln!(out)?;
            writeln!(
                out,
                "current selection: {:?}",
                criteria_mapper
                    .criteria_names(&implied_criteria)
                    .collect::<Vec<_>>()
            )?;
            writeln!(out, "(press ENTER to accept the current criteria)")?;
            let input = term.read_line()?;
            let input = input.trim();
            if input.is_empty() {
                if chosen_criteria.is_empty() {
                    writeln!(out, "no criteria chosen, aborting")?;
                    panic_any(ExitPanic(-1));
                }
                // User done selecting criteria
                break;
            }

            // FIXME: these errors get cleared away right away
            let answer = if let Ok(val) = input.parse::<usize>() {
                val
            } else {
                writeln!(out, "error: not a valid integer")?;
                continue;
            };
            if answer == 0 {
                chosen_criteria.clear();
                continue;
            }
            if answer > criteria_mapper.list.len() {
                writeln!(out, "error: not a valid criteria")?;
                continue;
            }
            chosen_criteria.push(criteria_mapper.list[answer - 1].0.clone());
        }
        chosen_criteria
    } else {
        sub_args.criteria.clone()
    };

    let notes = if let Some(notes) = sub_args.notes.clone() {
        Some(notes)
    } else {
        term.clear_screen()?;
        writeln!(out, "do you have any notes? (press ENTER to continue)")?;
        writeln!(out)?;
        let input = term.read_line()?;
        let input = input.trim();
        if input.is_empty() {
            None
        } else {
            Some(input.to_string())
        }
    };

    // Round-trip this through the criteria_mapper to clean up `implies` relationships
    let criteria_set = criteria_mapper.criteria_from_list(&criteria_names);
    for criteria in criteria_mapper.criteria_names(&criteria_set) {
        let eula = if let Some(eula) = eula_for_criteria(&store.audits, criteria) {
            eula
        } else {
            writeln!(out, "error: couldn't get description of criteria")?;
            panic_any(ExitPanic(-1));
        };

        // FIXME: can we check if the version makes sense..?
        if !foreign_packages(&cfg.metadata).any(|pkg| pkg.name == *package) {
            writeln!(
                out,
                "error: '{}' isn't one of your foreign packages",
                package
            )?;
            panic_any(ExitPanic(-1));
        }

        if !sub_args.accept_all {
            term.clear_screen()?;
            // Print out the EULA and prompt
            let what_version = match &kind {
                AuditKind::Full { version, .. } => {
                    format!("version {}", version)
                }
                AuditKind::Delta { delta, .. } => {
                    format!("the changes from version {} to {}", delta.from, delta.to)
                }
                AuditKind::Violation { .. } => unreachable!(),
            };
            let statement = format!(
                "I, {}, certify that I have audited {} of {} in accordance with the following criteria:",
                username, what_version, package,
            );

            write!(
                out,
                "\n{}\n\n",
                style(textwrap::fill(&statement, 80)).yellow().bold()
            )?;
            writeln!(out, "{}\n", style(eula).cyan())?;
            write!(out, r#"(type "yes" to certify): "#)?;
            out.flush()?;

            let answer = term.read_line()?.trim().to_lowercase();
            if answer != "yes" {
                writeln!(out, "rejected certification")?;
                panic_any(ExitPanic(-1));
            }
        }

        // Ok! Ready to commit the audit!
        let new_entry = AuditEntry {
            kind: kind.clone(),
            criteria: criteria.to_string(),
            who: who.clone(),
            notes: notes.clone(),
        };

        store
            .audits
            .audits
            .entry(package.clone())
            .or_insert(vec![])
            .push(new_entry);
    }

    store.commit()?;

    Ok(())
}

fn cmd_add_violation(
    _out: &mut dyn Write,
    cfg: &Config,
    sub_args: &AddViolationArgs,
) -> Result<(), VetError> {
    // Mark a package as a violation
    let mut store = Store::acquire(cfg)?;

    let kind = AuditKind::Violation {
        violation: sub_args.versions.clone(),
    };

    let (_username, who) = if let Some(who) = &sub_args.who {
        (who.clone(), Some(who.clone()))
    } else {
        let user_info = get_user_info()?;
        let who = format!("{} <{}>", user_info.username, user_info.email);
        (user_info.username, Some(who))
    };

    let notes = sub_args.notes.clone();

    let mut criteria = if sub_args.criteria.is_empty() {
        // TODO: provide an interactive prompt for this
        vec![store.config.default_criteria.clone()]
    } else {
        sub_args.criteria.clone()
    };

    // TODO: implement multi-criteria
    if criteria.len() != 1 {
        unimplemented!("multiple criteria not yet implemented");
    }
    let criteria = criteria.swap_remove(0);

    // FIXME: can we check if the version makes sense..?
    if !foreign_packages(&cfg.metadata).any(|pkg| pkg.name == sub_args.package) {
        error!("'{}' isn't one of your foreign packages", sub_args.package);
        panic_any(ExitPanic(-1));
    }

    // Ok! Ready to commit the audit!
    let new_entry = AuditEntry {
        kind,
        criteria,
        who,
        notes,
    };

    store
        .audits
        .audits
        .entry(sub_args.package.clone())
        .or_insert(vec![])
        .push(new_entry);

    store.commit()?;

    Ok(())
}

fn cmd_add_unaudited(
    _out: &mut dyn Write,
    cfg: &Config,
    sub_args: &AddUnauditedArgs,
) -> Result<(), VetError> {
    // Add an unaudited entry
    let mut store = Store::acquire(cfg)?;

    let dependency_criteria = if sub_args.dependency_criteria.is_empty() {
        // TODO: look at the current audits to infer this? prompt?
        DependencyCriteria::new()
    } else {
        let mut dep_criteria = DependencyCriteria::new();
        for arg in &sub_args.dependency_criteria {
            dep_criteria
                .entry(arg.dependency.clone())
                .or_insert_with(Vec::new)
                .push(arg.criteria.clone());
        }
        dep_criteria
    };

    let notes = sub_args.notes.clone();

    let mut criteria = if sub_args.criteria.is_empty() {
        // TODO: provide an interactive prompt for this
        vec![store.config.default_criteria.clone()]
    } else {
        sub_args.criteria.clone()
    };

    let suggest = !sub_args.no_suggest;

    // TODO: implement multi-criteria
    if criteria.len() != 1 {
        unimplemented!("multiple criteria not yet implemented");
    }
    let criteria = criteria.swap_remove(0);

    // FIXME: can we check if the version makes sense..?
    if !foreign_packages(&cfg.metadata).any(|pkg| pkg.name == sub_args.package) {
        error!("'{}' isn't one of your foreign packages", sub_args.package);
        panic_any(ExitPanic(-1));
    }

    // Ok! Ready to commit the audit!
    let new_entry = UnauditedDependency {
        criteria,
        notes,
        version: sub_args.version.clone(),
        dependency_criteria,
        suggest,
    };

    store
        .config
        .unaudited
        .entry(sub_args.package.clone())
        .or_insert(vec![])
        .push(new_entry);

    store.commit()?;

    Ok(())
}

fn cmd_suggest(out: &mut dyn Write, cfg: &Config, sub_args: &SuggestArgs) -> Result<(), VetError> {
    // Run the checker to validate that the current set of deps is covered by the current cargo vet store
    trace!("suggesting...");
    let mut store = Store::acquire(cfg)?;

    // Delete all unaudited entries except those that are suggest=false
    for versions in &mut store.config.unaudited.values_mut() {
        versions.retain(|e| !e.suggest);
    }

    // DO THE THING!!!!
    let report = resolver::resolve(
        &cfg.metadata,
        cfg.cli.filter_graph.as_ref(),
        &store,
        sub_args.guess_deeper,
    );
    match cfg.cli.output_format {
        OutputFormat::Human => report.print_suggest_human(out, cfg)?,
        OutputFormat::Json => report.print_json(out, cfg)?,
    }

    // Don't commit the store, because we purged the unaudited table above.

    Ok(())
}

fn cmd_regenerate_unaudited(
    _out: &mut dyn Write,
    cfg: &Config,
    _sub_args: &RegenerateUnauditedArgs,
) -> Result<(), VetError> {
    // Run the checker to validate that the current set of deps is covered by the current cargo vet store
    trace!("regenerating unaudited...");
    let mut store = Store::acquire(cfg)?;

    minimize_unaudited(cfg, &mut store)?;

    // We were successful, commit the store
    store.commit()?;

    Ok(())
}

pub fn minimize_unaudited(cfg: &Config, store: &mut Store) -> Result<(), VetError> {
    // Set the unaudited entries to nothing
    let old_unaudited = mem::take(&mut store.config.unaudited);

    // Try to vet
    let report = resolver::resolve(&cfg.metadata, cfg.cli.filter_graph.as_ref(), store, true);

    trace!("minimizing unaudited...");
    let new_unaudited = if let Some(suggest) = report.compute_suggest(cfg, false)? {
        let mut new_unaudited = SortedMap::new();
        let mut suggest_by_package_name = SortedMap::<PackageStr, Vec<SuggestItem>>::new();
        for item in suggest.suggestions {
            let package = &report.graph.nodes[item.package];
            suggest_by_package_name
                .entry(package.name)
                .or_default()
                .push(item);
        }

        // First try to preserve as many old entries as possible
        for (package_name, old_entries) in &old_unaudited {
            let mut no_suggestions = Vec::new();
            let suggestions = suggest_by_package_name
                .get_mut(&**package_name)
                .unwrap_or(&mut no_suggestions);
            for old_entry in old_entries {
                for item_idx in (0..suggestions.len()).rev() {
                    // If there's an existing entry for these criteria, preserve it
                    let new_item = &mut suggestions[item_idx];
                    {
                        let mut new_criteria = report
                            .criteria_mapper
                            .criteria_names(&new_item.suggested_criteria);
                        if new_item.suggested_diff.to == old_entry.version
                            && new_criteria.any(|s| s == &*old_entry.criteria)
                        {
                            std::mem::drop(new_criteria);
                            report.criteria_mapper.clear_criteria(
                                &mut new_item.suggested_criteria,
                                &old_entry.criteria,
                            );
                            new_unaudited
                                .entry(package_name.clone())
                                .or_insert(Vec::new())
                                .push(old_entry.clone());
                        }
                    }
                    // If we've exhausted all the criteria for this suggestion, remove it
                    if new_item.suggested_criteria.is_empty() {
                        suggestions.swap_remove(item_idx);
                    }
                }
                // If we haven't cleared out all the suggestions for this package, make sure its entry is inserted
                // to try to preserve the original order of it.
                if !suggestions.is_empty() {
                    new_unaudited
                        .entry(package_name.clone())
                        .or_insert(Vec::new());
                }
            }
        }

        // Now insert any remaining suggestions
        for (package_name, new_items) in suggest_by_package_name {
            for item in new_items {
                for criteria in report
                    .criteria_mapper
                    .criteria_names(&item.suggested_criteria)
                {
                    new_unaudited
                        .entry(package_name.to_string())
                        .or_insert(Vec::new())
                        .push(UnauditedDependency {
                            version: item.suggested_diff.to.clone(),
                            criteria: criteria.to_string(),
                            dependency_criteria: DependencyCriteria::new(),
                            notes: None,
                            suggest: true,
                        })
                }
            }
        }

        new_unaudited
    } else if let Conclusion::Success(_) = report.conclusion {
        SortedMap::new()
    } else {
        return Err(eyre::eyre!(
            "error: regenerate-unaudited failed for unknown reason"
        ));
    };

    // Alright there's the new unaudited
    store.config.unaudited = new_unaudited;

    Ok(())
}

fn cmd_diff(out: &mut dyn Write, cfg: &PartialConfig, sub_args: &DiffArgs) -> Result<(), VetError> {
    let mut cache = Cache::acquire(cfg)?;
    cache.command_history.last_fetch = Some(FetchCommand::Diff {
        package: sub_args.package.clone(),
        version1: sub_args.version1.clone(),
        version2: sub_args.version2.clone(),
    });

    let package = &*sub_args.package;

    writeln!(
        out,
        "fetching {} {} and {} ...",
        sub_args.package, sub_args.version1, sub_args.version2,
    )?;

    let to_fetch = &[(package, &sub_args.version1), (package, &sub_args.version2)];
    let fetched_paths = cache.fetch_packages(to_fetch)?;
    let fetched1 = &fetched_paths[package][&sub_args.version1];
    let fetched2 = &fetched_paths[package][&sub_args.version2];

    writeln!(out)?;

    diff_crate(out, cfg, fetched1, fetched2)?;

    Ok(())
}

fn cmd_vet(out: &mut dyn Write, cfg: &Config) -> Result<(), VetError> {
    // Run the checker to validate that the current set of deps is covered by the current cargo vet store
    trace!("vetting...");

    let mut store = Store::acquire(cfg)?;
    if !cfg.cli.locked {
        store.fetch_foreign_audits()?;
    }

    // DO THE THING!!!!
    let report = resolver::resolve(&cfg.metadata, cfg.cli.filter_graph.as_ref(), &store, false);
    match cfg.cli.output_format {
        OutputFormat::Human => report.print_human(out, cfg)?,
        OutputFormat::Json => report.print_json(out, cfg)?,
    }

    // Only save imports if we succeeded, to avoid any modifications on error.
    if report.has_errors() {
        panic_any(ExitPanic(-1));
    } else {
        store.commit()?;
    }

    Ok(())
}

fn cmd_fetch_imports(
    out: &mut dyn Write,
    cfg: &Config,
    _sub_args: &FetchImportsArgs,
) -> Result<(), VetError> {
    trace!("fetching imports...");

    let mut store = Store::acquire(cfg)?;
    if !cfg.cli.locked {
        store.fetch_foreign_audits()?;
    } else {
        writeln!(
            out,
            "warning: ran fetch-imports with --locked, this won't fetch!"
        )?;
    }
    store.commit()?;

    Ok(())
}

fn cmd_dump_graph(
    out: &mut dyn Write,
    cfg: &Config,
    sub_args: &DumpGraphArgs,
) -> Result<(), VetError> {
    // Dump a mermaid-js graph
    trace!("dumping...");

    let graph = resolver::DepGraph::new(&cfg.metadata, cfg.cli.filter_graph.as_ref());
    match cfg.cli.output_format {
        OutputFormat::Human => graph.print_mermaid(out, sub_args)?,
        OutputFormat::Json => serde_json::to_writer_pretty(out, &graph.nodes)?,
    }

    Ok(())
}

fn cmd_fmt(_out: &mut dyn Write, cfg: &Config, _sub_args: &FmtArgs) -> Result<(), VetError> {
    // Reformat all the files (just load and store them, formatting is implict).
    trace!("formatting...");
    let store = Store::acquire(cfg)?;
    store.commit()?;
    Ok(())
}

fn cmd_accept_criteria_change(
    _out: &mut dyn Write,
    _cfg: &Config,
    _sub_args: &AcceptCriteriaChangeArgs,
) -> Result<(), VetError> {
    // Accept changes that a foreign audits.toml made to their criteria.
    trace!("accepting...");

    error!("TODO(#68): unimplemented feature!");

    Ok(())
}

/// Perform crimes on clap long_help to generate markdown docs
fn cmd_help_md(
    out: &mut dyn Write,
    _cfg: &PartialConfig,
    _sub_args: &HelpMarkdownArgs,
) -> Result<(), VetError> {
    let app_name = "cargo-vet";
    let pretty_app_name = "cargo vet";
    // Make a new App to get the help message this time.

    writeln!(out, "# {pretty_app_name} CLI manual")?;
    writeln!(out)?;
    writeln!(
        out,
        "> This manual can be regenerated with `{pretty_app_name} help-markdown`"
    )?;
    writeln!(out)?;

    let mut fake_cli = FakeCli::command();
    let full_command = fake_cli.get_subcommands_mut().next().unwrap();
    full_command.build();
    let mut todo = vec![full_command];
    let mut is_full_command = true;

    while let Some(command) = todo.pop() {
        let mut help_buf = Vec::new();
        command.write_long_help(&mut help_buf).unwrap();
        let help = String::from_utf8(help_buf).unwrap();

        // First line is --version
        let mut lines = help.lines();
        let version_line = lines.next().unwrap();
        let subcommand_name = command.get_name();
        let pretty_subcommand_name;

        if is_full_command {
            pretty_subcommand_name = String::new();
            writeln!(out, "Version: `{version_line}`")?;
            writeln!(out)?;
        } else {
            pretty_subcommand_name = format!("{pretty_app_name} {subcommand_name} ");
            // Give subcommands some breathing room
            writeln!(out, "<br><br><br>")?;
            writeln!(out, "## {pretty_subcommand_name}")?;
        }

        let mut in_subcommands_listing = false;
        let mut in_usage = false;
        for line in lines {
            // Use a trailing colon to indicate a heading
            if let Some(heading) = line.strip_suffix(':') {
                if !line.starts_with(' ') {
                    // SCREAMING headers are Main headings
                    if heading.to_ascii_uppercase() == heading {
                        in_subcommands_listing = heading == "SUBCOMMANDS";
                        in_usage = heading == "USAGE";

                        writeln!(out, "### {pretty_subcommand_name}{heading}")?;
                    } else {
                        writeln!(out, "### {heading}")?;
                    }
                    continue;
                }
            }

            if in_subcommands_listing && !line.starts_with("     ") {
                // subcommand names are list items
                let own_subcommand_name = line.trim();
                write!(
                    out,
                    "* [{own_subcommand_name}](#{app_name}-{own_subcommand_name}): "
                )?;
                continue;
            }
            // The rest is indented, get rid of that
            let line = line.trim();

            // Usage strings get wrapped in full code blocks
            if in_usage && line.starts_with(pretty_app_name) {
                writeln!(out, "```")?;
                writeln!(out, "{line}")?;
                writeln!(out, "```")?;
                continue;
            }

            // argument names are subheadings
            if line.starts_with('-') || line.starts_with('<') {
                writeln!(out, "#### `{line}`")?;
                continue;
            }

            // escape default/value strings
            if line.starts_with('[') {
                writeln!(out, "\\{line}  ")?;
                continue;
            }

            // Normal paragraph text
            writeln!(out, "{line}")?;
        }
        writeln!(out)?;

        todo.extend(command.get_subcommands_mut());
        is_full_command = false;
    }

    Ok(())
}

// Utils

fn is_init(metacfg: &MetaConfig) -> bool {
    // Probably want to do more here later...
    metacfg.store_path().exists()
}

fn foreign_packages(metadata: &Metadata) -> impl Iterator<Item = &Package> {
    // Only analyze things from crates.io (no source = path-dep / workspace-member)
    metadata
        .packages
        .iter()
        .filter(|package| package.is_third_party())
}

fn load_toml<T>(path: &Path) -> Result<T, VetError>
where
    T: for<'a> Deserialize<'a>,
{
    let mut reader = BufReader::new(File::open(path)?);
    let mut string = String::new();
    reader.read_to_string(&mut string)?;
    let toml = toml::from_str(&string)?;
    Ok(toml)
}
fn store_toml<T>(path: &Path, heading: &str, val: T) -> Result<(), VetError>
where
    T: Serialize,
{
    // FIXME: do this in a temp file and swap it into place to avoid corruption?
    let toml_string = toml::to_string(&val)?;
    let mut output = File::create(path)?;
    writeln!(&mut output, "{}\n{}", heading, toml_string)?;
    Ok(())
}
fn load_json<T>(path: &Path) -> Result<T, VetError>
where
    T: for<'a> Deserialize<'a>,
{
    let mut reader = BufReader::new(File::open(path)?);
    let mut string = String::new();
    reader.read_to_string(&mut string)?;
    let json = serde_json::from_str(&string)?;
    Ok(json)
}
fn store_json<T>(path: &Path, val: T) -> Result<(), VetError>
where
    T: Serialize,
{
    // FIXME: do this in a temp file and swap it into place to avoid corruption?
    let json_string = serde_json::to_string(&val)?;
    let mut output = File::create(path)?;
    writeln!(&mut output, "{}", json_string)?;
    Ok(())
}

fn load_audits(store_path: &Path) -> Result<AuditsFile, VetError> {
    // TODO: do integrity checks? (for things like criteria keys being valid)
    let path = store_path.join(AUDITS_TOML);
    let file: AuditsFile = load_toml(&path)?;
    Ok(file)
}

fn load_config(store_path: &Path) -> Result<ConfigFile, VetError> {
    // TODO: do integrity checks?
    let path = store_path.join(CONFIG_TOML);
    let file: ConfigFile = load_toml(&path)?;
    Ok(file)
}

fn load_imports(store_path: &Path) -> Result<ImportsFile, VetError> {
    // TODO: do integrity checks?
    let path = store_path.join(IMPORTS_LOCK);
    let file: ImportsFile = load_toml(&path)?;
    Ok(file)
}

fn load_diff_cache(diff_cache_path: &Path) -> Result<DiffCache, VetError> {
    let file: DiffCache = load_toml(diff_cache_path)?;
    Ok(file)
}
fn load_command_history(command_history_path: &Path) -> Result<CommandHistory, VetError> {
    let file: CommandHistory = load_json(command_history_path)?;
    Ok(file)
}

fn store_audits(store_path: &Path, mut audits: AuditsFile) -> Result<(), VetError> {
    let heading = r###"
# cargo-vet audits file
"###;
    audits
        .audits
        .values_mut()
        .for_each(|entries| entries.sort());

    let path = store_path.join(AUDITS_TOML);
    store_toml(&path, heading, audits)?;
    Ok(())
}
fn store_config(store_path: &Path, mut config: ConfigFile) -> Result<(), VetError> {
    config
        .unaudited
        .values_mut()
        .for_each(|entries| entries.sort());

    let heading = r###"
# cargo-vet config file
"###;

    let path = store_path.join(CONFIG_TOML);
    store_toml(&path, heading, config)?;
    Ok(())
}
fn store_imports(store_path: &Path, imports: ImportsFile) -> Result<(), VetError> {
    let heading = r###"
# cargo-vet imports lock
"###;

    let path = store_path.join(IMPORTS_LOCK);
    store_toml(&path, heading, imports)?;
    Ok(())
}
fn store_diff_cache(diff_cache_path: &Path, diff_cache: DiffCache) -> Result<(), VetError> {
    let heading = "";

    store_toml(diff_cache_path, heading, diff_cache)?;
    Ok(())
}
fn store_command_history(
    command_history_path: &Path,
    command_history: CommandHistory,
) -> Result<(), VetError> {
    store_json(command_history_path, command_history)?;
    Ok(())
}

pub struct FileLock {
    path: PathBuf,
}

impl FileLock {
    pub fn acquire(path: impl Into<PathBuf>) -> Result<Self, VetError> {
        // TODO: learn how to do this more robustly
        // TODO: should we hold onto the file to avoid anyone deleting it?
        // Or drop it right away to make it easier to cleanup if something goes wrong?
        let path = path.into();
        let _lock = File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("Could not acquire lockfile at {}", path.display()))?;

        Ok(Self { path })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // Try to clean up the lock
        std::fs::remove_file(&self.path)
            .unwrap_or_else(|_| panic!("Couldn't delete file lock!? {}", self.path.display()));
    }
}

/// The store (typically `supply-chain/`)
///
/// All access to this directory should be managed by this type to avoid races.
/// By default, modifications to this type will not be written back to the store
/// because we don't generally want to write back any results unless everything
/// goes perfectly.
///
/// To write back this value, use [`Store::commit`][].
pub struct Store {
    /// Repo-global lock over the store, will be None if we're mocking.
    _lock: Option<FileLock>,
    /// Path to the root of the store
    root: Option<PathBuf>,

    // Contents of the store, eagerly loaded and already validated.
    pub config: ConfigFile,
    pub imports: ImportsFile,
    pub audits: AuditsFile,
}

impl Store {
    /// Create a brand-new store
    pub fn create(cfg: &Config) -> Result<Self, VetError> {
        let root = cfg.metacfg.store_path();
        std::fs::create_dir(&root).with_context(|| {
            format!(
                "Couldn't create cargo-vet Store because it already exists at {}",
                root.display()
            )
        })?;

        // TODO: cargo vet init?
        unimplemented!()
    }

    /// Acquire an existing store
    pub fn acquire(cfg: &Config) -> Result<Self, VetError> {
        let root = cfg.metacfg.store_path().to_owned();
        // Before we do anything, acquire the lockfile to get exclusive access
        let lock = if cfg.cli.readonly_lockless {
            None
        } else {
            Some(FileLock::acquire(root.join(STORE_LOCKFILE))?)
        };

        let config = load_config(&root)?;
        let audits = load_audits(&root)?;
        let imports = load_imports(&root)?;

        let root = if cfg.cli.readonly_lockless {
            None
        } else {
            Some(root)
        };

        let store = Self {
            _lock: lock,
            root,

            config,
            audits,
            imports,
        };

        // Check that the store isn't corrupt
        store.validate()?;

        Ok(store)
    }

    /// Create a mock store
    #[cfg(test)]
    pub fn mock(config: ConfigFile, audits: AuditsFile, imports: ImportsFile) -> Self {
        Self {
            _lock: None,
            root: None,

            config,
            imports,
            audits,
        }
    }

    /// Commit the store's contents back to disk
    pub fn commit(self) -> Result<(), VetError> {
        // TODO: make this truly transactional?
        // (With a dir rename? Does that work with the _lock? Fine because it's already closed?)
        if let Some(root) = self.root {
            store_audits(&root, self.audits)?;
            store_config(&root, self.config)?;
            store_imports(&root, self.imports)?;
        }
        Ok(())
    }

    /// Validate the store's integrity
    pub fn validate(&self) -> Result<(), VetError> {
        // TODO(#66): implement validation
        //
        // * check that policy entries are only first-party
        // * check that unaudited entries are for things that exist?
        // * check that lockfile and imports aren't desync'd (catch new/removed import urls)
        //
        // * check that each CriteriaEntry has 'description' or 'description_url'
        // * check that no one is trying to shadow builtin criteria (safe-to-run, safe-to-deploy)
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

    /// Fetch foreign audits, only call this is we're not --locked
    pub fn fetch_foreign_audits(&mut self) -> Result<(), VetError> {
        let mut audits = SortedMap::new();
        for (name, import) in &self.config.imports {
            let url = &import.url;
            // FIXME: this should probably be async but that's a Whole Thing and these files are small.
            let audit_txt = req::get(url).and_then(|r| r.text());
            if let Err(e) = audit_txt {
                return Err(eyre::eyre!("Could not load {name} @ {url} - {e}"));
            }
            let audit_file: Result<AuditsFile, _> = toml::from_str(&audit_txt.unwrap());
            if let Err(e) = audit_file {
                return Err(eyre::eyre!("Could not parse {name} @ {url} - {e}"));
            }
            audits.insert(name.clone(), audit_file.unwrap());
        }

        let new_imports = ImportsFile { audits };
        // TODO(#68): error out if the criteria changed

        // Accept the new imports. These will only be committed if the current command succeeds.
        self.imports = new_imports;

        // Now do one last validation to catch corrupt imports
        self.validate()?;
        Ok(())
    }
}

/// The cache where we store globally shared artifacts like fetched packages and diffstats
///
/// All access to this directory should be managed by this type to avoid races.
pub struct Cache {
    /// System-global lock over the cache, will be None if we're mocking.
    _lock: Option<FileLock>,
    /// Path to the root of the cache
    root: Option<PathBuf>,
    /// Cargo's crates.io package registry (in CARGO_HOME) for us to query opportunistically
    cargo_registry: Option<CargoRegistry>,
    /// Path to the DiffCache (for when we want to save it back)
    diff_cache_path: Option<PathBuf>,
    /// The loaded DiffCache, will be written back on Drop
    diff_cache: DiffCache,
    /// Path to the CommandHistory (for when we want to save it back)
    command_history_path: Option<PathBuf>,
    /// Command history to provide some persistent magic smarts
    command_history: CommandHistory,
}

/// A Registry in CARGO_HOME (usually the crates.io one)
pub struct CargoRegistry {
    /// The base path all registries share
    base_dir: PathBuf,
    /// The name of the registry
    registry: OsString,
}

impl CargoRegistry {
    /// Get the src dir of this registry (unpacked fetches)
    pub fn src(&self) -> PathBuf {
        self.base_dir.join(CARGO_REGISTRY_SRC).join(&self.registry)
    }
    /// Get the cache dir of the registry (.crate packed fetches)
    pub fn cache(&self) -> PathBuf {
        self.base_dir
            .join(CARGO_REGISTRY_CACHE)
            .join(&self.registry)
    }
    // Could also include the index, not reason to do that yet
}

impl Drop for Cache {
    fn drop(&mut self) {
        if let Some(diff_cache_path) = &self.diff_cache_path {
            // Write back the diff_cache
            store_diff_cache(diff_cache_path, mem::take(&mut self.diff_cache)).unwrap();
        }
        if let Some(command_history_path) = &self.command_history_path {
            // Write back the command_history
            store_command_history(command_history_path, mem::take(&mut self.command_history))
                .unwrap();
        }
        // `_lock: FileLock` implicitly released here
    }
}

impl Cache {
    /// Acquire the cache
    pub fn acquire(cfg: &PartialConfig) -> Result<Self, VetError> {
        if cfg.cargo_home.is_none() {
            // If the registry_src isn't set, then assume we're running in tests and mocked.
            // In that case, don't read/write disk for the DiffCache
            return Ok(Cache {
                _lock: None,
                root: None,
                cargo_registry: None,
                diff_cache_path: None,
                diff_cache: DiffCache::new(),
                command_history_path: None,
                command_history: CommandHistory::default(),
            });
        }

        let root = cfg.tmp.clone();
        let empty = root.join(TEMP_EMPTY_PACKAGE);
        let packages: PathBuf = root.join(TEMP_REGISTRY_SRC);

        // Make sure our cache exists
        if !root.exists() {
            fs::create_dir_all(&root)?;
        }
        // Now acquire the lockfile
        let lock = if cfg.cli.readonly_lockless {
            None
        } else {
            Some(FileLock::acquire(root.join(TEMP_LOCKFILE))?)
        };

        // Make sure everything else exists
        if !empty.exists() {
            fs::create_dir_all(&empty)?;
        }
        if !packages.exists() {
            fs::create_dir_all(&packages)?;
        }

        // Setup the diff_cache.
        let diff_cache_path = cfg
            .cli
            .diff_cache
            .clone()
            .unwrap_or_else(|| root.join(TEMP_DIFF_CACHE));
        let diff_cache = if let Ok(cache) = load_diff_cache(&diff_cache_path) {
            cache
        } else {
            // Might be our first run, create a fresh diff-cache that we'll write back at the end
            DiffCache::new()
        };

        // Setup the command_history.
        let command_history_path = root.join(TEMP_COMMAND_HISTORY);
        let command_history =
            if let Ok(command_history) = load_command_history(&command_history_path) {
                command_history
            } else {
                // Might be our first run, create a fresh command_history that we'll write back at the end
                CommandHistory::default()
            };

        // Try to get the cargo registry
        let cargo_registry = find_cargo_registry(cfg);
        if let Err(e) = &cargo_registry {
            warn!("Couldn't find cargo registry: {e}");
        }

        Ok(Self {
            _lock: lock,
            root: Some(root),
            diff_cache_path: Some(diff_cache_path),
            diff_cache,
            command_history_path: Some(command_history_path),
            command_history,
            cargo_registry: cargo_registry.ok(),
        })
    }

    pub fn fetch_packages<'a>(
        &mut self,
        packages: &[(PackageStr<'a>, &'a Version)],
    ) -> Result<BTreeMap<PackageStr<'a>, BTreeMap<&'a Version, PathBuf>>, VetError> {
        let _span = trace_span!("fetch-packages").entered();
        // Don't do anything if we're mocked, or there is no work to do
        if self.root.is_none() || packages.is_empty() {
            return Ok(BTreeMap::new());
        }

        let root = self.root.as_ref().unwrap();
        let fetch_dir = root.join(TEMP_REGISTRY_SRC);
        let cargo_registry = self.cargo_registry.as_ref();

        let mut paths = BTreeMap::<PackageStr, BTreeMap<&Version, PathBuf>>::new();
        let mut to_download = Vec::new();

        // Get all the cached things / find out what needs to be downloaded.
        for (name, version) in packages {
            let path = if **version == resolver::ROOT_VERSION {
                // Empty package
                root.join(TEMP_EMPTY_PACKAGE)
            } else {
                // First try to get a cached copy from cargo's register or our own
                let dir_name = format!("{}-{}", name, version);

                let cached = cargo_registry
                    .map(|reg| reg.src().join(&dir_name))
                    .filter(|path| fetch_is_ok(path))
                    .unwrap_or_else(|| fetch_dir.join(&dir_name));

                if !fetch_is_ok(&cached) {
                    // If we don't have a cached copy, push this to the download queue
                    to_download.push((name, version, cached.clone()));
                }

                // Either this path exists or we'll download it, either way, it's right
                cached
            };

            paths.entry(name).or_default().insert(version, path);
        }

        if !to_download.is_empty() {
            trace!("downloading {} packages", to_download.len());
        }
        // If there is anything to download, do it
        for (name, version, to_dir) in to_download {
            trace!("  downloading {}:{} to {}", name, version, to_dir.display());
            // FIXME: make this all async instead of blocking
            self.download_package(name, version, &to_dir)?;
        }

        trace!("all fetched!");

        Ok(paths)
    }

    pub fn fetch_and_diffstat_all(
        &mut self,
        package: PackageStr,
        diffs: &BTreeSet<Delta>,
    ) -> Result<DiffRecommendation, VetError> {
        let _span = trace_span!("diffstat-all").entered();
        // If there's no registry path setup, assume we're in tests and mocking.
        let mut all_versions = BTreeSet::new();

        for delta in diffs {
            let is_cached = self
                .diff_cache
                .get(package)
                .and_then(|cache| cache.get(delta))
                .is_some();
            if !is_cached {
                all_versions.insert(&delta.from);
                all_versions.insert(&delta.to);
            }
        }

        let mut best_rec: Option<DiffRecommendation> = None;
        let to_fetch = all_versions
            .iter()
            .map(|v| (package, *v))
            .collect::<Vec<_>>();
        let fetches = self.fetch_packages(&to_fetch)?;

        for delta in diffs {
            let cached = self
                .diff_cache
                .get(package)
                .and_then(|cache| cache.get(delta))
                .cloned();

            let diffstat = if let Some(cached) = cached {
                // Hooray, we have the cached result!
                cached
            } else {
                let from = fetches.get(package).and_then(|m| m.get(&delta.from));
                let to = fetches.get(package).and_then(|m| m.get(&delta.to));

                if let (Some(from), Some(to)) = (from, to) {
                    // Have fetches, do a real diffstat
                    let diffstat = diffstat_crate(from, to)?;
                    self.diff_cache
                        .entry(package.to_string())
                        .or_insert(SortedMap::new())
                        .insert(delta.clone(), diffstat.clone());
                    diffstat
                } else {
                    // If we don't have fetches, assume we want mocked results
                    warn!("Missing fetches, assuming we're in tests and mocking");

                    let from_len = delta.from.major * delta.from.major;
                    let to_len: u64 = delta.to.major * delta.to.major;
                    let diff = to_len as i64 - from_len as i64;
                    let count = diff.unsigned_abs();
                    let raw = if diff < 0 {
                        format!("-{}", count)
                    } else {
                        format!("+{}", count)
                    };
                    DiffStat { raw, count }
                }
            };

            let rec = DiffRecommendation {
                from: delta.from.clone(),
                to: delta.to.clone(),
                diffstat,
            };

            if let Some(best) = best_rec.as_ref() {
                if best.diffstat.count > rec.diffstat.count {
                    best_rec = Some(rec);
                }
            } else {
                best_rec = Some(rec);
            }
        }

        Ok(best_rec.unwrap())
    }

    fn download_package(
        &mut self,
        package: PackageStr,
        version: &Version,
        to_dir: &Path,
    ) -> Result<(), VetError> {
        // Download to an anonymous temp file
        let url = format!("https://crates.io/api/v1/crates/{package}/{version}/download");
        let mut tempfile = tempfile::tempfile()?;
        let bytes = req::get(url).and_then(|r| r.bytes())?;
        tempfile.write_all(&bytes[..])?;
        tempfile.rewind()?;

        // Now unpack it
        self.unpack_package(&tempfile, to_dir)?;

        Ok(())
    }

    fn unpack_package(&mut self, tarball: &File, unpack_dir: &Path) -> Result<(), VetError> {
        // If we get here and the unpack_dir exists, this implies we had a previously failed fetch,
        // blast it away so we can have a clean slate!
        if unpack_dir.exists() {
            fs::remove_dir_all(unpack_dir)?;
        }
        fs::create_dir(unpack_dir)?;
        let lockfile = unpack_dir.join(CARGO_OK_FILE);
        let gz = GzDecoder::new(tarball);
        let mut tar = Archive::new(gz);
        let prefix = unpack_dir.file_name().unwrap();
        let parent = unpack_dir.parent().unwrap();
        for entry in tar.entries()? {
            let mut entry = entry.wrap_err("failed to iterate over archive")?;
            let entry_path = entry
                .path()
                .wrap_err("failed to read entry path")?
                .into_owned();

            // We're going to unpack this tarball into the global source
            // directory, but we want to make sure that it doesn't accidentally
            // (or maliciously) overwrite source code from other crates. Cargo
            // itself should never generate a tarball that hits this error, and
            // crates.io should also block uploads with these sorts of tarballs,
            // but be extra sure by adding a check here as well.
            if !entry_path.starts_with(prefix) {
                return Err(eyre::eyre!(
                    "invalid tarball downloaded, contains \
                        a file at {} which isn't under {}",
                    entry_path.display(),
                    prefix.to_string_lossy()
                ));
            }
            // Unpacking failed
            let result = entry.unpack_in(parent).map_err(VetError::from);
            result.wrap_err_with(|| {
                format!("failed to unpack entry at `{}`", entry_path.display())
            })?;
        }

        // The lock file is created after unpacking so we overwrite a lock file
        // which may have been extracted from the package.
        let mut ok = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lockfile)
            .wrap_err_with(|| format!("failed to open `{}`", lockfile.display()))?;

        // Write to the lock file to indicate that unpacking was successful.
        write!(ok, "ok")?;

        Ok(())
    }
}

fn fetch_is_ok(fetch: &Path) -> bool {
    if !fetch.exists() || !fetch.is_dir() {
        return false;
    }

    let ok_contents = || -> Result<String, std::io::Error> {
        let mut ok_file = File::open(fetch.join(CARGO_OK_FILE))?;
        let mut contents = String::new();
        ok_file.read_to_string(&mut contents)?;
        Ok(contents)
    };

    if let Ok(ok) = ok_contents() {
        ok == CARGO_OK_BODY
    } else {
        false
    }
}

fn find_cargo_registry(cfg: &PartialConfig) -> Result<CargoRegistry, VetError> {
    // Find the cargo registry
    //
    // This is all unstable nonsense so being a bit paranoid here so that we can notice
    // when things get weird and understand corner cases better...
    if cfg.cargo_home.is_none() {
        return Err(eyre::eyre!("Could not resolve CARGO_HOME!?"));
    }

    let base_dir = cfg.cargo_home.as_ref().unwrap().join(CARGO_REGISTRY);
    let registry_src = base_dir.join(CARGO_REGISTRY_SRC);
    if !registry_src.exists() {
        return Err(eyre::eyre!("Cargo registry src cache doesn't exist!?"));
    }

    // There's some weird opaque directory name here, so no hardcoding of the path
    let mut registry = None;
    for entry in std::fs::read_dir(registry_src)? {
        let entry = entry?;
        let path = entry.path();
        let dir_name = path.file_name().unwrap().to_owned();
        if path.is_dir() {
            if registry.is_some() {
                warn!("Found multiple subdirectories in CARGO_HOME/registry/src");
                warn!("  Preferring any named github.com-*");
                if dir_name.to_string_lossy().starts_with("github.com-") {
                    registry = Some(dir_name);
                }
            } else {
                registry = Some(dir_name);
            }
        }
    }

    if let Some(registry) = registry {
        Ok(CargoRegistry { base_dir, registry })
    } else {
        Err(eyre::eyre!("failed to find cargo package sources"))
    }
}

fn diff_crate(
    _out: &mut dyn Write,
    _cfg: &PartialConfig,
    version1: &Path,
    version2: &Path,
) -> Result<(), VetError> {
    // FIXME: mask out .cargo_vcs_info.json
    // FIXME: look into libgit2 vs just calling git

    let status = Command::new("git")
        .arg("diff")
        .arg("--no-index")
        .arg(version1)
        .arg(version2)
        .status()?;

    let status = status.code().unwrap();

    // 0 = empty
    // 1 = some diff
    if status != 0 && status != 1 {
        return Err(eyre::eyre!("git diff failed!\n {}", status,));
    }

    Ok(())
}

fn diffstat_crate(version1: &Path, version2: &Path) -> Result<DiffStat, VetError> {
    trace!("diffstating {version1:#?} {version2:#?}");
    // FIXME: mask out .cargo_vcs_info.json
    // FIXME: look into libgit2 vs just calling git

    let out = Command::new("git")
        .arg("diff")
        .arg("--no-index")
        .arg("--shortstat")
        .arg(version1)
        .arg(version2)
        .output()?;

    // TODO: don't unwrap this
    let status = out.status.code().unwrap();
    // 0 = empty
    // 1 = some diff
    if status != 0 && status != 1 {
        return Err(eyre::eyre!(
            "command failed!\nout:\n{}\nstderr:\n{}",
            String::from_utf8(out.stdout).unwrap(),
            String::from_utf8(out.stderr).unwrap()
        ));
    }

    let diffstat = String::from_utf8(out.stdout)?;

    let count = if diffstat.is_empty() {
        0
    } else {
        // 3 files changed, 9 insertions(+), 3 deletions(-)
        let mut parts = diffstat.split(',');
        parts.next().unwrap(); // Discard files

        fn parse_diffnum(part: Option<&str>) -> Option<u64> {
            part?.trim().split_once(' ')?.0.parse().ok()
        }

        let added: u64 = parse_diffnum(parts.next()).unwrap_or(0);
        let removed: u64 = parse_diffnum(parts.next()).unwrap_or(0);

        assert_eq!(
            parts.next(),
            None,
            "diffstat had more parts than expected? {}",
            diffstat
        );

        added + removed
    };

    Ok(DiffStat {
        raw: diffstat,
        count,
    })
}

struct UserInfo {
    username: String,
    email: String,
}

fn get_user_info() -> Result<UserInfo, VetError> {
    let username = {
        let out = Command::new("git")
            .arg("config")
            .arg("--get")
            .arg("user.name")
            .output()?;

        if !out.status.success() {
            return Err(eyre::eyre!(
                "could not get user.name from git!\nout:\n{}\nstderr:\n{}",
                String::from_utf8(out.stdout).unwrap(),
                String::from_utf8(out.stderr).unwrap()
            ));
        }
        String::from_utf8(out.stdout)?
    };

    let email = {
        let out = Command::new("git")
            .arg("config")
            .arg("--get")
            .arg("user.email")
            .output()?;

        if !out.status.success() {
            return Err(eyre::eyre!(
                "could not get user.email from git!\nout:\n{}\nstderr:\n{}",
                String::from_utf8(out.stdout).unwrap(),
                String::from_utf8(out.stderr).unwrap()
            ));
        }

        String::from_utf8(out.stdout)?
    };

    Ok(UserInfo {
        username: username.trim().to_string(),
        email: email.trim().to_string(),
    })
}

fn eula_for_criteria(audits: &AuditsFile, criteria: CriteriaStr) -> Option<String> {
    let builtin_eulas = [
        (
            format::SAFE_TO_DEPLOY,
            include_str!("criteria/safe-to-deploy.txt"),
        ),
        (
            format::SAFE_TO_RUN,
            include_str!("criteria/safe-to-run.txt"),
        ),
    ]
    .into_iter()
    .collect::<HashMap<_, _>>();

    // Several fallbacks
    // * Try to get the builtin criteria
    // * Try to get the criteria's description
    // * Try to fetch the criteria's url
    // * Just display the url
    builtin_eulas
        .get(criteria)
        .map(|s| s.to_string())
        .or_else(|| {
            audits.criteria.get(criteria).and_then(|c| {
                c.description.clone().or_else(|| {
                    c.description_url.as_ref().map(|url| {
                        req::get(url)
                            .and_then(|r| r.text())
                            .map_err(|e| {
                                warn!("Could not fetch criteria description: {e}");
                            })
                            .ok()
                            .unwrap_or_else(|| format!("See criteria description at {url}"))
                    })
                })
            })
        })
}
