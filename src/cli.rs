use std::{path::PathBuf, str::FromStr};

use cargo_metadata::Version;
use clap::{Parser, Subcommand, ValueEnum};
use tracing::level_filters::LevelFilter;

use crate::format::{CriteriaName, PackageName, VersionReq};

#[derive(Parser)]
#[clap(version, about, long_about = None)]
#[clap(propagate_version = true)]
#[clap(bin_name = "cargo")]
pub enum FakeCli {
    Vet(Cli),
}

#[derive(clap::Args)]
#[clap(version)]
#[clap(bin_name = "cargo vet")]
#[clap(global_setting(clap::AppSettings::DeriveDisplayOrder))]
/// Supply-chain security for Rust
pub struct Cli {
    /// Subcommands ("no subcommand" is its own subcommand)
    #[clap(subcommand)]
    pub command: Option<Commands>,

    // Top-level flags
    /// Path to Cargo.toml
    #[clap(long, name = "PATH", parse(from_os_str))]
    #[clap(help_heading = "GLOBAL OPTIONS", global = true)]
    pub manifest_path: Option<PathBuf>,

    /// Don't use --all-features
    ///
    /// We default to passing --all-features to `cargo metadata`
    /// because we want to analyze your full dependency tree
    #[clap(long, action)]
    #[clap(help_heading = "GLOBAL OPTIONS", global = true)]
    pub no_all_features: bool,

    /// Do not activate the `default` feature
    #[clap(long, action)]
    #[clap(help_heading = "GLOBAL OPTIONS", global = true)]
    pub no_default_features: bool,

    /// Space-separated list of features to activate
    #[clap(long, action, require_value_delimiter = true, value_delimiter = ' ')]
    #[clap(help_heading = "GLOBAL OPTIONS", global = true)]
    pub features: Vec<String>,

    /// Do not fetch new imported audits.
    #[clap(long, action)]
    #[clap(help_heading = "GLOBAL OPTIONS", global = true)]
    pub locked: bool,

    /// Avoid the network entirely, requiring either that the cargo cache is
    /// populated or the dependencies are vendored. Requires --locked.
    #[clap(long, action)]
    #[clap(requires = "locked")]
    #[clap(help_heading = "GLOBAL OPTIONS", global = true)]
    pub frozen: bool,

    /// How verbose logging should be (log level)
    #[clap(long, action)]
    #[clap(default_value_t = LevelFilter::WARN)]
    #[clap(possible_values = ["off", "error", "warn", "info", "debug", "trace"])]
    #[clap(help_heading = "GLOBAL OPTIONS", global = true)]
    pub verbose: LevelFilter,

    /// Avoid suggesting audits for dependencies of unaudited dependencies.
    ///
    /// By default, if a dependency doesn't have sufficient audits for *itself*
    /// then we try to speculate that its dependencies require the criteria.
    /// This flag disables that behaviour, causing only suggestions which we're
    /// certain of the requirements for to be emitted.
    #[clap(long, action)]
    #[clap(help_heading = "GLOBAL OPTIONS", global = true)]
    pub shallow: bool,

    /// Instead of stdout, write output to this file
    #[clap(long, action)]
    #[clap(help_heading = "GLOBAL OPTIONS", global = true)]
    pub output_file: Option<PathBuf>,

    /// Instead of stderr, write logs to this file (only used after successful CLI parsing)
    #[clap(long, action)]
    #[clap(help_heading = "GLOBAL OPTIONS", global = true)]
    pub log_file: Option<PathBuf>,

    /// The format of the output
    #[clap(long, value_enum, action)]
    #[clap(default_value_t = OutputFormat::Human)]
    #[clap(help_heading = "GLOBAL OPTIONS", global = true)]
    pub output_format: OutputFormat,

    /// Use the following path as the diff-cache
    ///
    /// The diff-cache stores the summary results used by vet's suggestion machinery.
    /// This is automatically managed in vet's tempdir, but if you want to manually store
    /// it somewhere more reliable, you can.
    ///
    /// This mostly exists for testing vet itself.
    #[clap(long, action)]
    #[clap(help_heading = "GLOBAL OPTIONS", global = true)]
    pub diff_cache: Option<PathBuf>,

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
    #[clap(long, action)]
    #[clap(verbatim_doc_comment)]
    #[clap(help_heading = "GLOBAL OPTIONS", global = true)]
    pub filter_graph: Option<Vec<GraphFilter>>,
}

#[derive(Subcommand)]
pub enum Commands {
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
    RecordViolation(RecordViolationArgs),

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

    /// Clean up old packages from the vet cache
    ///
    /// Removes  packages which haven't been accessed in a while, and deletes
    /// any extra files which aren't recognized by cargo-vet.
    ///
    /// In the future, many cargo-vet subcommands will implicitly do this.
    #[clap(disable_version_flag = true)]
    Gc(GcArgs),
}

#[derive(clap::Args)]
pub struct InitArgs {}

/// Fetches the crate to a temp location and pushd's to it
#[derive(clap::Args)]
pub struct InspectArgs {
    /// The package to inspect
    #[clap(action)]
    pub package: PackageName,
    /// The version to inspect
    #[clap(action)]
    pub version: Version,
}

/// Emits a diff of the two versions
#[derive(clap::Args)]
pub struct DiffArgs {
    /// The package to diff
    #[clap(action)]
    pub package: PackageName,
    /// The base version to diff
    #[clap(action)]
    pub version1: Version,
    /// The target version to diff
    #[clap(action)]
    pub version2: Version,
}

/// Certifies a package as audited
#[derive(clap::Args)]
pub struct CertifyArgs {
    /// The package to certify as audited
    #[clap(action)]
    pub package: Option<PackageName>,
    /// The version to certify as audited
    #[clap(action)]
    pub version1: Option<Version>,
    /// If present, instead certify a diff from version1->version2
    #[clap(action)]
    pub version2: Option<Version>,
    /// The criteria to certify for this audit
    ///
    /// If not provided, we will prompt you for this information.
    #[clap(long, action)]
    pub criteria: Vec<CriteriaName>,
    /// The dependency-criteria to require for this audit to be valid
    ///
    /// If not provided, we will still implicitly require dependencies to satisfy `criteria`.
    #[clap(long, action)]
    pub dependency_criteria: Vec<DependencyCriteriaArg>,
    /// Who to name as the auditor
    ///
    /// If not provided, we will collect this information from the local git.
    #[clap(long, action)]
    pub who: Option<String>,
    /// A free-form string to include with the new audit entry
    ///
    /// If not provided, there will be no notes.
    #[clap(long, action)]
    pub notes: Option<String>,
    /// Accept all criteria without an interactive prompt
    #[clap(long, action)]
    pub accept_all: bool,
}

/// Forbids the given version
#[derive(clap::Args)]
pub struct RecordViolationArgs {
    /// The package to forbid
    #[clap(action)]
    pub package: PackageName,
    /// The versions to forbid
    #[clap(action)]
    pub versions: VersionReq,
    /// The criteria that have failed to be satisfied.
    ///
    /// If not provided, we will prompt you for this information(?)
    #[clap(long, action)]
    pub criteria: Vec<CriteriaName>,
    /// Who to name as the auditor
    ///
    /// If not provided, we will collect this information from the local git.
    #[clap(long, action)]
    pub who: Option<String>,
    /// A free-form string to include with the new forbid entry
    ///
    /// If not provided, there will be no notes.
    #[clap(long, action)]
    pub notes: Option<String>,
}

/// Certifies the given version
#[derive(clap::Args)]
pub struct AddUnauditedArgs {
    /// The package to mark as unaudited (trusted)
    #[clap(action)]
    pub package: PackageName,
    /// The version to mark as unaudited
    #[clap(action)]
    pub version: Version,
    /// The criteria to assume (trust)
    ///
    /// If not provided, we will prompt you for this information.
    #[clap(long, action)]
    pub criteria: Vec<CriteriaName>,
    /// The dependency-criteria to require for this unaudited entry to be valid
    ///
    /// If not provided, we will still implicitly require dependencies to satisfy `criteria`.
    #[clap(long, action)]
    pub dependency_criteria: Vec<DependencyCriteriaArg>,
    /// A free-form string to include with the new forbid entry
    ///
    /// If not provided, there will be no notes.
    #[clap(long, action)]
    pub notes: Option<String>,
    /// Suppress suggesting this unaudited entry
    #[clap(long, action)]
    pub no_suggest: bool,
}

#[derive(clap::Args)]
pub struct SuggestArgs {}

#[derive(clap::Args)]
pub struct FmtArgs {}

#[derive(clap::Args)]
pub struct FetchImportsArgs {}

#[derive(clap::Args)]
pub struct RegenerateUnauditedArgs {}

#[derive(clap::Args)]
pub struct AcceptCriteriaChangeArgs {}

#[derive(clap::Args)]
pub struct HelpMarkdownArgs {}

#[derive(clap::Args)]
pub struct GcArgs {
    /// Packages in the vet cache which haven't been used for this many days
    /// will be removed.
    #[clap(long, action)]
    #[clap(default_value_t = 30.0)]
    pub max_package_age_days: f64,

    /// Remove the entire cache directory, forcing it to be regenerated next
    /// time you use cargo vet.
    #[clap(long, action)]
    pub clean: bool,
}

#[derive(clap::Args)]
pub struct DumpGraphArgs {
    /// The depth of the graph to print (for a large project, the full graph is a HUGE MESS).
    #[clap(long, value_enum, action)]
    #[clap(default_value_t = DumpGraphDepth::FirstParty)]
    pub depth: DumpGraphDepth,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum DumpGraphDepth {
    Roots,
    Workspace,
    FirstParty,
    FirstPartyAndDirects,
    Full,
}

/// Logging verbosity levels
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
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

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
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
