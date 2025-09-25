use std::{path::PathBuf, str::FromStr};

use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use tracing::level_filters::LevelFilter;

use crate::format::{CriteriaName, ImportName, PackageName, VersionReq, VetVersion};

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
#[clap(display_name = "cargo-vet")]
#[clap(args_conflicts_with_subcommands = true)]
/// Supply-chain security for Rust
///
/// When run without a subcommand, `cargo vet` will invoke the `check`
/// subcommand. See `cargo vet help check` for more details.
pub struct Cli {
    /// Subcommands ("no subcommand" defaults to `check`)
    #[clap(subcommand)]
    pub command: Option<Commands>,

    // Top-level flags
    /// Path to Cargo.toml
    #[clap(long, name = "PATH")]
    #[clap(help_heading = "Global Options", global = true)]
    pub manifest_path: Option<PathBuf>,

    /// Path to the supply-chain directory
    #[clap(long, name = "STORE_PATH")]
    #[clap(help_heading = "Global Options", global = true)]
    pub store_path: Option<PathBuf>,

    /// Don't use --all-features
    ///
    /// We default to passing --all-features to `cargo metadata`
    /// because we want to analyze your full dependency tree
    #[clap(long, action)]
    #[clap(help_heading = "Global Options", global = true)]
    pub no_all_features: bool,

    /// Do not activate the `default` feature
    #[clap(long, action)]
    #[clap(help_heading = "Global Options", global = true)]
    pub no_default_features: bool,

    /// Space-separated list of features to activate
    #[clap(long, action, value_delimiter = ' ')]
    #[clap(help_heading = "Global Options", global = true)]
    pub features: Vec<String>,

    /// Do not fetch new imported audits.
    #[clap(long, action)]
    #[clap(help_heading = "Global Options", global = true)]
    pub locked: bool,

    /// Avoid the network entirely, requiring either that the cargo cache is
    /// populated or the dependencies are vendored. Requires --locked.
    #[clap(long, action)]
    #[clap(requires = "locked")]
    #[clap(help_heading = "Global Options", global = true)]
    pub frozen: bool,

    /// Prevent commands such as `check` and `certify` from automatically
    /// cleaning up unused exemptions.
    #[clap(long, action)]
    #[clap(help_heading = "Global Options", global = true)]
    pub no_minimize_exemptions: bool,

    /// Prevent commands such as `check` and `suggest` from suggesting registry
    /// imports.
    #[clap(long, action)]
    #[clap(help_heading = "Global Options", global = true)]
    pub no_registry_suggestions: bool,

    /// How verbose logging should be (log level)
    #[clap(long, action)]
    #[clap(default_value = "warn")]
    #[clap(help_heading = "Global Options", global = true)]
    pub verbose: VetLevelFilter,

    /// Instead of stdout, write output to this file
    #[clap(long, action)]
    #[clap(help_heading = "Global Options", global = true)]
    pub output_file: Option<PathBuf>,

    /// Instead of stderr, write logs to this file (only used after successful CLI parsing)
    #[clap(long, action)]
    #[clap(help_heading = "Global Options", global = true)]
    pub log_file: Option<PathBuf>,

    /// The format of the output
    #[clap(long, value_enum, action)]
    #[clap(default_value_t = OutputFormat::Human)]
    #[clap(help_heading = "Global Options", global = true)]
    pub output_format: OutputFormat,

    /// Use the following path instead of the global cache directory
    ///
    /// The cache stores information such as the summary results used by vet's
    /// suggestion machinery, cached results from crates.io APIs, and checkouts
    /// of crates from crates.io in some cases. This is generally automatically
    /// managed in the system cache directory.
    ///
    /// This mostly exists for testing vet itself.
    #[clap(long, action)]
    #[clap(help_heading = "Global Options", global = true)]
    pub cache_dir: Option<PathBuf>,

    /// The date and time to use as now.
    #[clap(long, action, hide = true)]
    #[clap(help_heading = "Global Options", global = true)]
    pub current_time: Option<chrono::DateTime<chrono::Utc>>,

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
    #[clap(help_heading = "Global Options", global = true)]
    pub filter_graph: Option<Vec<GraphFilter>>,

    /// Arguments to pass through to cargo. It can be specified multiple times for
    /// multiple arguments.
    ///
    /// Example: `--cargo-arg=-Zbindeps`
    ///
    /// This allows using unstable options in Cargo if a project's Cargo.toml requires them.
    #[clap(long, action)]
    #[clap(help_heading = "Global Options", global = true)]
    pub cargo_arg: Vec<String>,

    // Args for `Check` when the subcommand is not explicitly specified.
    //
    // These are exclusive with specifying a subcommand due to
    // `args_conflicts_with_subcommand`.
    #[clap(flatten)]
    pub check_args: CheckArgs,
}

#[derive(Subcommand)]
pub enum Commands {
    // Main commands:
    /// \[default\] Check that the current project has been vetted
    ///
    /// This is the default behaviour if no subcommand is specified.
    ///
    /// If the check fails due to lack of audits, we will do our best to explain why
    /// vetting failed, and what should be done to fix it. This can involve a certain
    /// amount of guesswork, as there are many possible solutions and we only want to recommend
    /// the "best" one to keep things simple.
    ///
    /// Failures and suggestions can either be "Certain" or "Speculative". Speculative items
    /// are greyed out and sorted lower to indicate that the Certain entries should be looked
    /// at first. Speculative items are for packages that probably need audits too, but
    /// only appear as transitive dependencies of Certain items.
    ///
    /// During review of Certain issues you may take various actions that change what's needed
    /// for the Speculative ones. For instance you may discover you're enabling a feature you
    /// don't need, and that's the only reason the Speculative package is in your tree. Or you
    /// may determine that the Certain package only needs to be safe-to-run, which may make
    /// the Speculative requirements weaker or completely resolved. For these reasons we
    /// recommend fixing problems "top down", and Certain items are The Top.
    ///
    /// Suggested fixes are grouped by the criteria they should be reviewed for and sorted by
    /// how easy the review should be (in terms of lines of code). We only ever suggest audits
    /// (and provide the command you need to run to do it), but there are other possible fixes
    /// like an `exemption` or `policy` change.
    ///
    /// The most aggressive solution is to run `cargo vet regenerate exemptions` which will
    /// add whatever exemptions necessary to make `check` pass (and remove uneeded ones).
    /// Ideally you should avoid doing this and prefer adding audits, but if you've done all
    /// the audits you plan on doing, that's the way to finish the job.
    #[clap(disable_version_flag = true)]
    Check(CheckArgs),

    /// Suggest some low-hanging fruit to review
    ///
    /// This is essentially the same as `check` but with all your `exemptions` temporarily
    /// removed as a way to inspect your "review backlog". As such, we recommend against
    /// running this command while `check` is failing, because this will just give you worse
    /// information.
    ///
    /// If you don't consider an exemption to be "backlog", add `suggest = false` to its
    /// entry and we won't remove it while suggesting.
    ///
    /// See also `regenerate exemptions`, which can be used to "garbage collect"
    /// your backlog (if you run it while `check` is passing).
    #[clap(disable_version_flag = true)]
    Suggest(SuggestArgs),

    /// Initialize cargo-vet for your project
    ///
    /// This will add `exemptions` and `audit-as-crates-io = false` for all packages that
    /// need it to make `check` pass immediately and make it easy to start using vet with
    /// your project.
    ///
    /// At this point you can either configure your project further or start working on your
    /// review backlog with `suggest`.
    #[clap(disable_version_flag = true)]
    Init(InitArgs),

    // Fetch Commands
    /// Fetch the source of a package
    ///
    /// We will attempt to guess what criteria you want to audit the package for
    /// based on the current check/suggest status, and show you the meaning of
    /// those criteria ahead of time.
    #[clap(disable_version_flag = true)]
    Inspect(InspectArgs),

    /// Yield a diff against the last reviewed version
    ///
    /// We will attempt to guess what criteria you want to audit the package for
    /// based on the current check/suggest status, and show you the meaning of
    /// those criteria ahead of time.
    #[clap(disable_version_flag = true)]
    Diff(DiffArgs),

    // Update State Commands
    /// Mark a package as audited
    ///
    /// This command will do its best to guess what you want to be certifying.
    ///
    /// If invoked with no args, it will try to certify the last thing you looked at
    /// with `inspect` or `diff`. Otherwise you must either supply the package name
    /// and one version (for a full audit) or two versions (for a delta audit).
    ///
    /// Once the package+version(s) have been selected, we will try to guess what
    /// criteria to certify it for. First we will `check`, and if the check fails
    /// and your audit would seemingly fix this package, we will use the criteria
    /// recommended for that fix. If `check` passes, we will assume you are working
    /// on your backlog and instead use the recommendations of `suggest`.
    ///
    /// If this removes the need for an `exemption` will we automatically remove it.
    #[clap(disable_version_flag = true)]
    Certify(CertifyArgs),

    /// Import a new peer's imports
    ///
    /// If invoked without a URL parameter, it will look up the named peer in
    /// the cargo-vet registry, and import that peer.
    #[clap(disable_version_flag = true)]
    Import(ImportArgs),

    /// Trust a given crate and publisher
    #[clap(disable_version_flag = true)]
    Trust(TrustArgs),

    /// Explicitly regenerate various pieces of information
    ///
    /// There are several things that `cargo vet` *can* do for you automatically
    /// but we choose to make manual just to keep a human in the loop of those
    /// decisions. Some of these might one day become automatic if we agree they're
    /// boring/reliable enough.
    ///
    /// See the subcommands for specifics.
    #[clap(disable_version_flag = true)]
    #[clap(subcommand)]
    Regenerate(RegenerateSubcommands),

    /// Mark a package as exempted from review
    ///
    /// Exemptions are *usually* just "backlog" and the expectation is that you will review
    /// them "eventually". You should usually only be trying to remove them, but sometimes
    /// additions are necessary to make progress.
    ///
    /// `regenerate exemptions` will do this for your automatically to make `check` pass
    /// (and remove any unnecessary ones), so we recommend using that over `add-exemption`.
    /// This command mostly exists as "plumbing" for building tools on top of `cargo vet`.
    #[clap(disable_version_flag = true)]
    AddExemption(AddExemptionArgs),

    /// Declare that some versions of a package violate certain audit criteria
    ///
    /// **IMPORTANT**: violations take *VersionReqs* not *Versions*. This is the same
    /// syntax used by Cargo.toml when specifying dependencies. A bare `1.0.0` actually
    /// means `^1.0.0`. If you want to forbid a *specific* version, use `=1.0.0`.
    /// This command can be a bit awkward because syntax like `*` has special meaning
    /// in scripts and terminals. It's probably easier to just manually add the entry
    /// to your audits.toml, but the command's here in case you want it.
    ///
    /// Violations are essentially treated as integrity constraints on your supply-chain,
    /// and will only result in errors if you have `exemptions` or `audits` (including
    /// imported ones) that claim criteria that are contradicted by the `violation`.
    /// It is not inherently an error to depend on a package with a `violation`.
    ///
    /// For instance, someone may review a package and determine that it's horribly
    /// unsound in the face of untrusted inputs, and therefore *un*safe-to-deploy. They
    /// would then add a "safe-to-deploy" violation for whatever versions of that
    /// package seem to have that problem. But if the package basically works fine
    /// on trusted inputs, it might still be safe-to-run. So if you use it in your
    /// tests and have an audit that only claims safe-to-run, we won't mention it.
    ///
    /// When a violation *does* cause an integrity error, it's up to you and your
    /// peers to figure out what to do about it. There isn't yet a mechanism for
    /// dealing with disagreements with a peer's published violations.
    #[clap(disable_version_flag = true)]
    RecordViolation(RecordViolationArgs),

    // Plumbing/Debug Commands
    /// Reformat all of vet's files (in case you hand-edited them)
    ///
    /// Most commands will implicitly do this, so this mostly exists as "plumbing"
    /// for building tools on top of vet, or in case you don't want to run another command.
    #[clap(disable_version_flag = true)]
    Fmt(FmtArgs),

    /// Prune unnecessary imports and exemptions
    ///
    /// This will fetch the updated state of imports, and attempt to remove any
    /// now-unnecessary imports or exemptions from the supply-chain.
    #[clap(disable_version_flag = true)]
    Prune(PruneArgs),

    /// Fetch and merge audits from multiple sources into a single `audits.toml`
    /// file.
    ///
    /// Will fetch the audits from each URL in the provided file, combining them
    /// into a single file. Custom criteria will be merged by-name, and must
    /// have identical descriptions in each source audit file.
    #[clap(disable_version_flag = true)]
    Aggregate(AggregateArgs),

    /// Print the computed audit path used by cargo-vet to certify a package for
    /// a given critera.
    ///
    /// This is a debugging command, and the output's format is not guaranteed.
    #[clap(disable_version_flag = true)]
    ExplainAudit(ExplainAuditArgs),

    /// Print the cargo build graph as understood by `cargo vet`
    ///
    /// This is a debugging command, the output's format is not guaranteed.
    /// Use `cargo metadata` to get a stable version of what *cargo* thinks the
    /// build graph is. Our graph is based on that result.
    ///
    /// With `--output-format=human` (the default) this will print out mermaid-js
    /// diagrams, which things like github natively support rendering of.
    ///
    /// With `--output-format=json` we will print out more raw statistics for you
    /// to search/analyze.
    ///
    /// Most projects will have unreadably complex build graphs, so you may want to
    /// use the global `--filter-graph` argument to narrow your focus on an interesting
    /// subgraph. `--filter-graph` is applied *before* doing any semantic analysis,
    /// so if you filter out a package and it was the problem, the problem will disappear.
    /// This can be used to bisect a problem if you get ambitious enough with your filters.
    #[clap(disable_version_flag = true)]
    DumpGraph(DumpGraphArgs),

    /// Print --help as markdown (for generating docs)
    ///
    /// The output of this is not stable or guaranteed.
    #[clap(disable_version_flag = true)]
    #[clap(hide = true)]
    HelpMarkdown(HelpMarkdownArgs),

    /// Clean up old packages from the vet cache
    ///
    /// Removes packages which haven't been accessed in a while, and deletes
    /// any extra files which aren't recognized by cargo-vet.
    ///
    /// In the future, many cargo-vet subcommands will implicitly do this.
    #[clap(disable_version_flag = true)]
    Gc(GcArgs),

    /// Renew wildcard audit expirations
    ///
    /// This will set a wildcard audit expiration to be one year in the future from when it is run.
    /// It can optionally do this for all audits which are expiring soon.
    #[clap(disable_version_flag = true)]
    Renew(RenewArgs),
}

#[derive(Subcommand)]
pub enum RegenerateSubcommands {
    /// Regenerate your exemptions to make `check` pass minimally
    ///
    /// This command can be used for two purposes: to force your supply-chain to pass `check`
    /// when it's currently failing, or to minimize/garbage-collect your exemptions when it's
    /// already passing. These are ultimately the same operation.
    ///
    /// We will try our best to preserve existing exemptions, removing only those that
    /// aren't needed, and adding only those that are needed. Exemptions that are overbroad
    /// may also be weakened (i.e. safe-to-deploy may be reduced to safe-to-run).
    #[clap(disable_version_flag = true)]
    Exemptions(RegenerateExemptionsArgs),

    /// Regenerate your imports and accept changes to criteria
    ///
    /// This is equivalent to `cargo vet fetch-imports` but it won't produce an error if
    /// the descriptions of foreign criteria change.
    #[clap(disable_version_flag = true)]
    Imports(RegenerateImportsArgs),

    /// Add `audit-as-crates-io` to the policy entry for all crates which require one.
    ///
    /// Crates which have a matching `description` and `repository` entry to a
    /// published crate on crates.io will be marked as `audit-as-crates-io = true`.
    #[clap(disable_version_flag = true)]
    AuditAsCratesIo(RegenerateAuditAsCratesIoArgs),

    /// Remove all outdated `unpublished` entries for crates which have since
    /// been published, or should now be audited as a more-recent version.
    ///
    /// Unlike `cargo vet prune`, this will remove outdated `unpublished`
    /// entries even if it will cause `check` to start failing.
    #[clap(disable_version_flag = true)]
    Unpublished(RegenerateUnpublishedArgs),
}

#[derive(clap::Args)]
pub struct CheckArgs {}

#[derive(clap::Args)]
pub struct InitArgs {}

/// Inspect a crate at a specific version
#[derive(clap::Args)]
pub struct InspectArgs {
    /// The package to inspect
    #[clap(action)]
    pub package: PackageName,
    /// The version to inspect
    #[clap(action)]
    pub version: VetVersion,
    /// How to inspect the source
    ///
    /// Defaults to the most recently used --mode argument, or diff.rs if no
    /// mode argument has been used.
    ///
    /// This option is ignored if a git version is passed.
    #[clap(long, action)]
    pub mode: Option<FetchMode>,
}

/// View a diff between two versions of the given crate
#[derive(clap::Args)]
pub struct DiffArgs {
    /// The package to diff
    #[clap(action)]
    pub package: PackageName,
    /// The base version to diff
    #[clap(action)]
    pub version1: VetVersion,
    /// The target version to diff
    #[clap(action)]
    pub version2: VetVersion,
    /// How to inspect the diff
    ///
    /// Defaults to the most recently used --mode argument, or diff.rs if no
    /// mode argument has been used.
    ///
    /// This option is ignored if a git version is passed.
    #[clap(long, action)]
    pub mode: Option<FetchMode>,
}

/// Certifies a package as audited
#[derive(clap::Args)]
pub struct CertifyArgs {
    /// The package to certify as audited
    #[clap(action)]
    pub package: Option<PackageName>,
    /// The version to certify as audited
    #[clap(action)]
    pub version1: Option<VetVersion>,
    /// If present, instead certify a diff from version1->version2
    #[clap(action)]
    pub version2: Option<VetVersion>,
    /// If present, certify a wildcard audit for the user with the given
    /// username, or trusted publisher with the given signature.
    ///
    /// Use the --start-date and --end-date options to specify the date range to
    /// certify for.
    ///
    /// NOTE: Trusted publisher signatures have a provider-specific format:
    ///
    ///  * GitHub Actions: `github:organization/repository`
    #[clap(long, action, conflicts_with("version1"), requires("package"))]
    pub wildcard: Option<String>,
    /// The criteria to certify for this audit
    ///
    /// If not provided, we will prompt you for this information.
    #[clap(long, action)]
    pub criteria: Vec<CriteriaName>,
    /// Who to name as the auditor
    ///
    /// If not provided, we will collect this information from the local git.
    #[clap(long, action)]
    pub who: Vec<String>,
    /// A free-form string to include with the new audit entry
    ///
    /// If not provided, there will be no notes.
    #[clap(long, action)]
    pub notes: Option<String>,
    /// Start date to create a wildcard audit from.
    ///
    /// Only valid with `--wildcard`.
    ///
    /// If not provided, will be the publication date of the first version
    /// published by the given user.
    #[clap(long, action, requires("wildcard"))]
    pub start_date: Option<chrono::NaiveDate>,
    /// End date to create a wildcard audit from. May be at most 1 year in the future.
    ///
    /// Only valid with `--wildcard`.
    ///
    /// If not provided, will be 1 year from the current date.
    #[clap(long, action, requires("wildcard"))]
    pub end_date: Option<chrono::NaiveDate>,
    /// Accept all criteria without an interactive prompt
    #[clap(long, action)]
    pub accept_all: bool,
    /// Force the command to ignore whether the package/version makes sense
    ///
    /// To catch typos/mistakes, we check if the thing you're trying to
    /// talk about is part of your current build, but this flag disables that.
    #[clap(long, action)]
    pub force: bool,
    /// Prevent combination of the audit with a prior adjacent non-importable git audit, if any.
    ///
    /// This will only have an effect if the supplied `from` version is a git version.
    ///
    /// For example, normally an existing audit from `1.0.0->1.0.0@git:1111111` and a new certified
    /// audit from `1.0.0@git:1111111->1.0.0@git:2222222` would result in a single audit from
    /// `1.0.0->1.0.0@git:2222222`. Passing this flag would prevent this.
    #[clap(long, action, requires("version2"))]
    pub no_collapse: bool,
}

/// Import a new peer
#[derive(clap::Args)]
pub struct ImportArgs {
    /// The name of the peer to import
    #[clap(action)]
    pub name: ImportName,
    /// The URL(s) of the peer's audits.toml file(s).
    ///
    /// If a URL is not provided, a peer with the given name will be looked up
    /// in the cargo-vet registry to determine the import URL(s).
    #[clap(action)]
    pub url: Vec<String>,
}

/// Trust a crate's publisher
#[derive(clap::Args)]
pub struct TrustArgs {
    /// The package to trust
    ///
    /// Must be specified unless --all has been specified.
    #[clap(action, required_unless_present("all"))]
    pub package: Option<PackageName>,
    /// The username or trusted publisher signature of the publisher to trust
    ///
    /// If not provided, will be inferred to be the sole known publisher of the
    /// given crate. If there is more than one publisher for the given crate,
    /// the login must be provided explicitly.
    #[clap(action)]
    pub publisher_identifier: Option<String>,
    /// The criteria to certify for this trust entry
    ///
    /// If not provided, we will prompt you for this information.
    #[clap(long, action)]
    pub criteria: Vec<CriteriaName>,
    /// Start date to create the trust entry from.
    ///
    /// If not provided, will be the publication date of the first version
    /// published by the given user.
    #[clap(long, action)]
    pub start_date: Option<chrono::NaiveDate>,
    /// End date to create the trust entry from. May be at most 1 year in the future.
    ///
    /// If not provided, will be 1 year from the current date.
    #[clap(long, action)]
    pub end_date: Option<chrono::NaiveDate>,
    /// A free-form string to include with the new audit entry
    ///
    /// If not provided, there will be no notes.
    #[clap(long, action)]
    pub notes: Option<String>,
    /// If specified, trusts all packages with exemptions or failures which are
    /// solely published by the given user or trusted publisher signature.
    #[clap(long, action, conflicts_with("package"))]
    pub all: Option<String>,
    /// If specified along with --all, also trusts packages with multiple
    /// publishers, so long as at least one version was published by the given
    /// user.
    #[clap(long, action, requires("all"))]
    pub allow_multiple_publishers: bool,
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
    pub who: Vec<String>,
    /// A free-form string to include with the new forbid entry
    ///
    /// If not provided, there will be no notes.
    #[clap(long, action)]
    pub notes: Option<String>,
    /// Force the command to ignore whether the package/version makes sense
    ///
    /// To catch typos/mistakes, we check if the thing you're trying to
    /// talk about is part of your current build, but this flag disables that.
    #[clap(long, action)]
    pub force: bool,
}

/// Certifies the given version
#[derive(clap::Args)]
pub struct AddExemptionArgs {
    /// The package to mark as exempted
    #[clap(action)]
    pub package: PackageName,
    /// The version to mark as exempted
    #[clap(action)]
    pub version: VetVersion,
    /// The criteria to assume (trust)
    ///
    /// If not provided, we will prompt you for this information.
    #[clap(long, action)]
    pub criteria: Vec<CriteriaName>,
    /// A free-form string to include with the new forbid entry
    ///
    /// If not provided, there will be no notes.
    #[clap(long, action)]
    pub notes: Option<String>,
    /// Suppress suggesting this exemption for review
    #[clap(long, action)]
    pub no_suggest: bool,
    /// Force the command to ignore whether the package/version makes sense
    ///
    /// To catch typos/mistakes, we check if the thing you're trying to
    /// talk about is part of your current build, but this flag disables that.
    #[clap(long, action)]
    pub force: bool,
}

#[derive(clap::Args)]
pub struct SuggestArgs {}

#[derive(clap::Args)]
pub struct FmtArgs {}

#[derive(clap::Args)]
pub struct PruneArgs {
    /// Don't prune unused imports
    #[clap(long, action)]
    pub no_imports: bool,
    /// Don't prune unused exemptions
    #[clap(long, action)]
    pub no_exemptions: bool,
    /// Don't prune unused non-importable audits.
    #[clap(long, action)]
    pub no_audits: bool,
}

#[derive(clap::Args)]
pub struct RegenerateExemptionsArgs {}

#[derive(clap::Args)]
pub struct RegenerateImportsArgs {}

#[derive(clap::Args)]
pub struct RegenerateAuditAsCratesIoArgs {}

#[derive(clap::Args)]
pub struct RegenerateUnpublishedArgs {}

#[derive(clap::Args)]
pub struct AggregateArgs {
    /// Path to a file containing a list of URLs to aggregate the audits from.
    #[clap(action)]
    pub sources: PathBuf,
}

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
pub struct RenewArgs {
    // Change this doc string if the WILDCARD_AUDIT_EXPIRATION_STRING changes.
    /// Renew all wildcard audits which will have expired six weeks from now.
    #[clap(long, action, conflicts_with("crate_name"))]
    pub expiring: bool,

    /// Renew wildcard audits for inactive crates which have not been updated
    /// in 4 months.
    #[clap(long, action, requires("expiring"))]
    pub include_inactive: bool,

    /// The name of a crate to renew.
    #[clap(value_name("CRATE"), action, required_unless_present("expiring"))]
    pub crate_name: Option<String>,
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

#[derive(clap::Args)]
pub struct ExplainAuditArgs {
    /// The package to display the audit path for
    #[clap(action)]
    pub package: PackageName,
    /// The version to display the audit path for
    #[clap(action)]
    pub version: Option<VetVersion>,
    /// The criteria to display the audit path for
    #[clap(action)]
    #[clap(default_value = "safe-to-deploy")]
    pub criteria: CriteriaName,
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

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, ValueEnum, Serialize, Deserialize)]
pub enum FetchMode {
    Local,
    Sourcegraph,
    #[clap(name = "diff.rs")]
    DiffRs,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum OutputFormat {
    /// Print output in a human-readable form.
    Human,
    /// Print output in a machine-readable form with minimal extra context.
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
    Version(VetVersion),
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
        fn val_version(input: &str) -> ParseResult<&str, VetVersion> {
            let (rest, val) = is_not(") ")(input)?;
            let val = VetVersion::from_str(val).map_err(|_e| {
                nom::Err::Failure(VerboseError {
                    errors: vec![(val, VerboseErrorKind::Context("version parse error"))],
                })
            })?;
            Ok((rest, val))
        }
        fn ws<'a, F, O, E: ParseError<&'a str>>(
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

/// Crate-local definition of the LevelFilter type to support
/// #[derive(ValueEnum)].
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, ValueEnum)]
pub enum VetLevelFilter {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<VetLevelFilter> for LevelFilter {
    fn from(value: VetLevelFilter) -> Self {
        match value {
            VetLevelFilter::Off => LevelFilter::OFF,
            VetLevelFilter::Error => LevelFilter::ERROR,
            VetLevelFilter::Warn => LevelFilter::WARN,
            VetLevelFilter::Info => LevelFilter::INFO,
            VetLevelFilter::Debug => LevelFilter::DEBUG,
            VetLevelFilter::Trace => LevelFilter::TRACE,
        }
    }
}
