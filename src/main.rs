use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::ops::Deref;
use std::panic::panic_any;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use std::{fs::File, io, panic, path::PathBuf};

use cargo_metadata::{Metadata, Package};
use clap::{CommandFactory, Parser};
use console::Term;
use errors::{
    AggregateCriteriaDescription, AggregateCriteriaDescriptionMismatchError,
    AggregateCriteriaImplies, AggregateError, AggregateErrors, AggregateImpliesMismatchError,
    AuditAsError, AuditAsErrors, CacheAcquireError, CertifyError, CratePolicyError,
    CratePolicyErrors, FetchAuditError, LoadTomlError, NeedsAuditAsErrors,
    NeedsPolicyVersionErrors, PackageError, ShouldntBeAuditAsErrors, UnusedAuditAsErrors,
    UnusedPolicyVersionErrors, UserInfoError,
};
use format::{CriteriaName, CriteriaStr, PackageName, Policy, PolicyEntry, SortedSet, VetVersion};
use futures_util::future::{join_all, try_join_all};
use indicatif::ProgressDrawTarget;
use lazy_static::lazy_static;
use miette::{miette, Context, Diagnostic, IntoDiagnostic};
use network::Network;
use out::{progress_bar, IncProgressOnDrop};
use reqwest::Url;
use serde::de::Deserialize;
use serialization::spanned::Spanned;
use serialization::Tidyable;
use storage::fetch_registry;
use thiserror::Error;
use tracing::{error, info, trace, warn};

use crate::cli::*;
use crate::criteria::CriteriaMapper;
use crate::errors::{
    CommandError, DownloadError, FetchAndDiffError, FetchError, MetadataAcquireError, SourceFile,
};
use crate::format::{
    AuditEntry, AuditKind, AuditsFile, ConfigFile, CratesUserId, CriteriaEntry, ExemptedDependency,
    FetchCommand, MetaConfig, MetaConfigInstance, PackageStr, SortedMap, StoreInfo, TrustEntry,
    WildcardEntry,
};
use crate::git_tool::Pager;
use crate::out::{indeterminate_spinner, Out, StderrLogWriter, MULTIPROGRESS};
use crate::storage::{Cache, Store};

mod cli;
mod criteria;
pub mod errors;
mod flock;
pub mod format;
mod git_tool;
pub mod network;
mod out;
pub mod resolver;
mod serialization;
pub mod storage;
mod string_format;
#[cfg(test)]
mod tests;

/// Absolutely All The Global Configurations
pub struct Config {
    /// Cargo.toml `metadata.vet`
    pub metacfg: MetaConfig,
    /// `cargo metadata`
    pub metadata: Metadata,
    /// Freestanding configuration values
    _rest: PartialConfig,
}

/// Configuration vars that are available in a free-standing situation
/// (no actual cargo-vet instance to load/query).
pub struct PartialConfig {
    /// Details of the CLI invocation (args)
    pub cli: Cli,
    /// The date and time to use as the current time.
    pub now: chrono::DateTime<chrono::Utc>,
    /// Path to the cache directory we're using
    pub cache_dir: PathBuf,
    /// Whether we should mock the global cache (for unit testing)
    pub mock_cache: bool,
}

impl PartialConfig {
    pub fn today(&self) -> chrono::NaiveDate {
        self.now.date_naive()
    }
}

// Makes it a bit easier to have both a "partial" and "full" config
impl Deref for Config {
    type Target = PartialConfig;
    fn deref(&self) -> &Self::Target {
        &self._rest
    }
}

pub trait PackageExt {
    fn is_third_party(&self, policy: &Policy) -> bool;
    fn is_crates_io(&self) -> bool;
    fn policy_entry<'a>(&self, policy: &'a Policy) -> Option<&'a PolicyEntry>;
    fn git_rev(&self) -> Option<String>;
    fn vet_version(&self) -> VetVersion;
}

impl PackageExt for Package {
    fn is_third_party(&self, policy: &Policy) -> bool {
        let forced_third_party = self
            .policy_entry(policy)
            .and_then(|policy| policy.audit_as_crates_io)
            .unwrap_or(false);

        forced_third_party || self.is_crates_io()
    }

    fn is_crates_io(&self) -> bool {
        self.source
            .as_ref()
            .map(|s| s.is_crates_io())
            .unwrap_or(false)
    }

    fn policy_entry<'a>(&self, policy: &'a Policy) -> Option<&'a PolicyEntry> {
        policy.get(&self.name, &self.vet_version())
    }

    fn git_rev(&self) -> Option<String> {
        self.source.as_ref().and_then(|s| {
            let git_source = s.repr.strip_prefix("git+")?;
            let source_url = Url::parse(git_source).ok()?;
            Some(source_url.fragment()?.to_owned())
        })
    }

    fn vet_version(&self) -> VetVersion {
        VetVersion {
            semver: self.version.clone(),
            git_rev: self.git_rev(),
        }
    }
}

const CACHE_DIR_SUFFIX: &str = "cargo-vet";
const CARGO_ENV: &str = "CARGO";
// package.metadata.vet
const PACKAGE_VET_CONFIG: &str = "vet";
// workspace.metadata.vet
const WORKSPACE_VET_CONFIG: &str = "vet";

const DURATION_DAY: Duration = Duration::from_secs(60 * 60 * 24);

lazy_static! {
    static ref WILDCARD_AUDIT_EXPIRATION_DURATION: chrono::Duration = chrono::Duration::weeks(6);
    static ref WILDCARD_AUDIT_INACTIVE_CRATE_DURATION: chrono::Duration =
        chrono::Duration::weeks(16);
}
/// This string is always used in a context such as "in the next {STR}".
const WILDCARD_AUDIT_EXPIRATION_STRING: &str = "six weeks";

/// Trick to let us std::process::exit while still cleaning up
/// by panicking with this type instead of a string.
struct ExitPanic(i32);

type ReportErrorFunc = dyn Fn(&miette::Report) + Send + Sync + 'static;

// XXX: We might be able to get rid of this `lazy_static` after 1.63 due to
// `const Mutex::new` being stabilized.
lazy_static! {
    static ref REPORT_ERROR: Mutex<Option<Box<ReportErrorFunc>>> = Mutex::new(None);
}

fn set_report_errors_as_json(out: Arc<dyn Out>) {
    *REPORT_ERROR.lock().unwrap() = Some(Box::new(move |error| {
        // Manually invoke JSONReportHandler to format the error as a report
        // to out_.
        let mut report = String::new();
        miette::JSONReportHandler::new()
            .render_report(&mut report, error.as_ref())
            .unwrap();
        writeln!(out, r#"{{"error": {report}}}"#);
    }));
}

fn report_error(error: &miette::Report) {
    {
        let guard = REPORT_ERROR.lock().unwrap();
        if let Some(do_report) = &*guard {
            do_report(error);
            return;
        }
    }
    error!("{:?}", error);
}

fn main() -> Result<(), ()> {
    // NOTE: Limit the maximum number of blocking threads to 128, rather than
    // the default of 512.
    // This may limit concurrency in some cases, but cargo-vet isn't running a
    // server, and should avoid consuming all available resources.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(128)
        .enable_all()
        .build()
        .unwrap();
    let _guard = runtime.enter();

    // Wrap main up in a catch_panic so that we can use it to implement std::process::exit with
    // unwinding, allowing us to silently exit the program while still cleaning up.
    let panic_result = std::panic::catch_unwind(real_main);
    let main_result = match panic_result {
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
    };
    main_result.map_err(|e| {
        report_error(&e);
        std::process::exit(-1);
    })
}

fn real_main() -> Result<(), miette::Report> {
    use cli::Commands::*;

    let fake_cli = cli::FakeCli::parse();
    let cli::FakeCli::Vet(cli) = fake_cli;

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
            .with_ansi(console::colors_enabled_stderr())
            .with_writer(StderrLogWriter::new)
            .init();
    }

    // Control how errors are formatted by setting the miette hook. This will
    // only be used for errors presented to humans, when formatting an error as
    // JSON, it will be handled by a custom `report_error` override, bypassing
    // the hook.
    let using_log_file = cli.log_file.is_some();
    miette::set_hook(Box::new(move |_| {
        let graphical_theme = if console::colors_enabled_stderr() && !using_log_file {
            miette::GraphicalTheme::unicode()
        } else {
            miette::GraphicalTheme::unicode_nocolor()
        };
        Box::new(
            miette::MietteHandlerOpts::new()
                .graphical_theme(graphical_theme)
                .build(),
        )
    }))
    .expect("failed to initialize error handler");

    // Now that miette is set up, use it to format panics.
    panic::set_hook(Box::new(move |panic_info| {
        if panic_info.payload().is::<ExitPanic>() {
            return;
        }

        let payload = panic_info.payload();
        let message = if let Some(msg) = payload.downcast_ref::<&str>() {
            msg
        } else if let Some(msg) = payload.downcast_ref::<String>() {
            &msg[..]
        } else {
            "something went wrong"
        };

        #[derive(Debug, Error, Diagnostic)]
        #[error("{message}")]
        pub struct PanicError {
            pub message: String,
            #[help]
            pub help: Option<String>,
        }

        report_error(
            &miette::Report::from(PanicError {
                message: message.to_owned(),
                help: panic_info
                    .location()
                    .map(|loc| format!("at {}:{}:{}", loc.file(), loc.line(), loc.column())),
            })
            .wrap_err("cargo vet panicked"),
        );
    }));

    // Initialize the MULTIPROGRESS's draw target, so that future progress
    // events are rendered to stderr.
    MULTIPROGRESS.set_draw_target(ProgressDrawTarget::stderr());

    // Setup our output stream
    let out: Arc<dyn Out> = if let Some(output_path) = &cli.output_file {
        Arc::new(File::create(output_path).unwrap())
    } else {
        Arc::new(Term::stdout())
    };

    // If we're outputting JSON, replace the error report method such that it
    // writes errors out to the normal output stream as JSON.
    if cli.output_format == OutputFormat::Json {
        set_report_errors_as_json(out.clone());
    }

    ////////////////////////////////////////////////////
    // Potentially handle freestanding commands
    ////////////////////////////////////////////////////

    let cache_dir = cli.cache_dir.clone().unwrap_or_else(|| {
        dirs::cache_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join(CACHE_DIR_SUFFIX)
    });
    let now = cli
        .current_time
        .unwrap_or_else(|| chrono::DateTime::from(SystemTime::now()));
    let partial_cfg = PartialConfig {
        cli,
        now,
        cache_dir,
        mock_cache: false,
    };

    match &partial_cfg.cli.command {
        Some(Aggregate(sub_args)) => return cmd_aggregate(&out, &partial_cfg, sub_args),
        Some(HelpMarkdown(sub_args)) => return cmd_help_md(&out, &partial_cfg, sub_args),
        Some(Gc(sub_args)) => return cmd_gc(&out, &partial_cfg, sub_args),
        _ => {
            // Not a freestanding command, time to do full parsing and setup
        }
    }

    ///////////////////////////////////////////////////
    // Fetch cargo metadata
    ///////////////////////////////////////////////////

    let cli = &partial_cfg.cli;
    let cargo_path = std::env::var_os(CARGO_ENV).expect("Cargo failed to set $CARGO, how?");

    let mut cmd = cargo_metadata::MetadataCommand::new();
    cmd.cargo_path(cargo_path);
    if let Some(manifest_path) = &cli.manifest_path {
        cmd.manifest_path(manifest_path);
    }
    if !cli.no_all_features {
        cmd.features(cargo_metadata::CargoOpt::AllFeatures);
    }
    if cli.no_default_features {
        cmd.features(cargo_metadata::CargoOpt::NoDefaultFeatures);
    }
    if !cli.features.is_empty() {
        cmd.features(cargo_metadata::CargoOpt::SomeFeatures(cli.features.clone()));
    }
    // We never want cargo-vet to update the Cargo.lock.
    // For frozen runs we also don't want to touch the network.
    let mut other_options = Vec::new();
    if cli.frozen {
        other_options.push("--frozen".to_string());
    } else {
        other_options.push("--locked".to_string());
    }
    if !using_log_file
        && cli.output_format == OutputFormat::Human
        && console::colors_enabled_stderr()
    {
        other_options.push("--color=always".to_string());
    }
    other_options.extend(cli.cargo_arg.iter().cloned());
    cmd.other_options(other_options);

    info!("Running: {:#?}", cmd.cargo_command());

    // ERRORS: immediate fatal diagnostic
    let metadata = {
        let _spinner = indeterminate_spinner("Running", "`cargo metadata`");
        cmd.exec().map_err(MetadataAcquireError::from)?
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
                    .join(storage::DEFAULT_STORE)
                    .into_std_path_buf(),
            ),
        }),
    };

    // FIXME: what is `store.path` relative to here?
    let workspace_metacfg = metadata
        .workspace_metadata
        .get(WORKSPACE_VET_CONFIG)
        .map(|cfg| {
            // ERRORS: immediate fatal diagnostic
            MetaConfigInstance::deserialize(cfg)
                .into_diagnostic()
                .wrap_err("Workspace had [{WORKSPACE_VET_CONFIG}] but it was malformed")
        })
        .transpose()?;

    // FIXME: what is `store.path` relative to here?
    let package_metacfg = metadata
        .root_package()
        .and_then(|r| r.metadata.get(PACKAGE_VET_CONFIG))
        .map(|cfg| {
            // ERRORS: immediate fatal diagnostic
            MetaConfigInstance::deserialize(cfg)
                .into_diagnostic()
                .wrap_err("Root package had [{PACKAGE_VET_CONFIG}] but it was malformed")
        })
        .transpose()?;

    let cli_metacfg = cli.store_path.as_ref().map(|path| MetaConfigInstance {
        version: Some(1),
        store: Some(StoreInfo {
            path: Some(path.clone()),
        }),
    });

    if workspace_metacfg.is_some() && package_metacfg.is_some() {
        // ERRORS: immediate fatal diagnostic
        return Err(miette!("Both a workspace and a package defined [metadata.vet]! We don't know what that means, if you do, let us know!"));
    }

    let mut metacfgs = vec![default_config];
    if let Some(metacfg) = workspace_metacfg {
        metacfgs.push(metacfg);
    }
    if let Some(metacfg) = package_metacfg {
        metacfgs.push(metacfg);
    }
    if let Some(metacfg) = cli_metacfg {
        metacfgs.push(metacfg);
    }
    let metacfg = MetaConfig(metacfgs);

    info!("Final Metadata Config: ");
    info!("  - version: {}", metacfg.version());
    info!("  - store.path: {:#?}", metacfg.store_path());

    //////////////////////////////////////////////////////
    // Run the actual command
    //////////////////////////////////////////////////////

    let init = Store::is_init(&metacfg);
    if matches!(cli.command, Some(Commands::Init { .. })) {
        if init {
            // ERRORS: immediate fatal diagnostic
            return Err(miette!(
                "'cargo vet' already initialized (store found at {})",
                metacfg.store_path().display()
            ));
        }
    } else if !init {
        // ERRORS: immediate fatal diagnostic
        return Err(miette!(
            "You must run 'cargo vet init' (store not found at {})",
            metacfg.store_path().display()
        ));
    }

    let cfg = Config {
        metacfg,
        metadata,
        _rest: partial_cfg,
    };

    use RegenerateSubcommands::*;
    match &cfg.cli.command {
        None => cmd_check(&out, &cfg, &cfg.cli.check_args),
        Some(Check(sub_args)) => cmd_check(&out, &cfg, sub_args),
        Some(Init(sub_args)) => cmd_init(&out, &cfg, sub_args),
        Some(Certify(sub_args)) => cmd_certify(&out, &cfg, sub_args),
        Some(Import(sub_args)) => cmd_import(&out, &cfg, sub_args),
        Some(Trust(sub_args)) => cmd_trust(&out, &cfg, sub_args),
        Some(AddExemption(sub_args)) => cmd_add_exemption(&out, &cfg, sub_args),
        Some(RecordViolation(sub_args)) => cmd_record_violation(&out, &cfg, sub_args),
        Some(Suggest(sub_args)) => cmd_suggest(&out, &cfg, sub_args),
        Some(Fmt(sub_args)) => cmd_fmt(&out, &cfg, sub_args),
        Some(Prune(sub_args)) => cmd_prune(&out, &cfg, sub_args),
        Some(DumpGraph(sub_args)) => cmd_dump_graph(&out, &cfg, sub_args),
        Some(Inspect(sub_args)) => cmd_inspect(&out, &cfg, sub_args),
        Some(Diff(sub_args)) => cmd_diff(&out, &cfg, sub_args),
        Some(Regenerate(Imports(sub_args))) => cmd_regenerate_imports(&out, &cfg, sub_args),
        Some(Regenerate(Exemptions(sub_args))) => cmd_regenerate_exemptions(&out, &cfg, sub_args),
        Some(Regenerate(AuditAsCratesIo(sub_args))) => {
            cmd_regenerate_audit_as(&out, &cfg, sub_args)
        }
        Some(Regenerate(Unpublished(sub_args))) => cmd_regenerate_unpublished(&out, &cfg, sub_args),
        Some(Renew(sub_args)) => cmd_renew(&out, &cfg, sub_args),
        Some(Aggregate(_)) | Some(HelpMarkdown(_)) | Some(Gc(_)) => unreachable!("handled earlier"),
    }
}

fn cmd_init(_out: &Arc<dyn Out>, cfg: &Config, _sub_args: &InitArgs) -> Result<(), miette::Report> {
    // Initialize vet
    trace!("initializing...");

    let network = Network::acquire(cfg);
    let mut store = Store::create(cfg)?;

    check_crate_policies(cfg, &store)?;
    tokio::runtime::Handle::current().block_on(fix_audit_as(cfg, network.as_ref(), &mut store))?;

    // Run the resolver to regenerate exemptions, this will fill in exemptions
    // such that the vet now passes.
    resolver::update_store(cfg, &mut store, |_| resolver::UpdateMode {
        search_mode: resolver::SearchMode::RegenerateExemptions,
        prune_exemptions: true,
        prune_non_importable_audits: true,
        prune_imports: true,
    });

    store.commit()?;

    Ok(())
}

fn cmd_inspect(
    out: &Arc<dyn Out>,
    cfg: &Config,
    sub_args: &InspectArgs,
) -> Result<(), miette::Report> {
    let version = &sub_args.version;
    let package = &*sub_args.package;

    let fetched = {
        let network = Network::acquire(cfg);
        let store = Store::acquire(cfg, network.as_ref(), false)?;
        let cache = Cache::acquire(cfg)?;

        // Record this command for magic in `vet certify`
        cache.set_last_fetch(FetchCommand::Inspect {
            package: package.to_owned(),
            version: version.clone(),
        });

        // Determine the fetch mode to use. We'll need to do a local diff if the
        // selected version has a git revision.
        let mode = cache.select_fetch_mode(sub_args.mode, version.git_rev.is_some());

        if mode != FetchMode::Local {
            let url = match mode {
                FetchMode::Sourcegraph => {
                    format!("https://sourcegraph.com/crates/{package}@v{version}")
                }
                FetchMode::DiffRs => {
                    format!("https://diff.rs/browse/{package}/{version}/")
                }
                FetchMode::Local => unreachable!(),
            };
            tokio::runtime::Handle::current()
                .block_on(prompt_criteria_eulas(
                    out,
                    cfg,
                    network.as_ref(),
                    &store,
                    package,
                    None,
                    version,
                    Some(&url),
                ))
                .into_diagnostic()?;

            open::that(&url).into_diagnostic().wrap_err_with(|| {
                format!("Couldn't open {url} in your browser, try --mode=local?")
            })?;

            writeln!(out, "\nUse |cargo vet certify| to record your audit.");
            return Ok(());
        }

        tokio::runtime::Handle::current().block_on(async {
            let (pkg, eulas) = tokio::join!(
                async {
                    // If we're fetching a git revision for inspection, don't
                    // use fetch_package, as we want to point the user at the
                    // actual cargo checkout, rather than our repack, which may
                    // be incomplete, and will be clobbered by GC.
                    if let Some(git_rev) = &version.git_rev {
                        storage::locate_local_checkout(&cfg.metadata, package, version).ok_or_else(
                            || FetchError::UnknownGitRevision {
                                package: package.to_owned(),
                                git_rev: git_rev.to_owned(),
                            },
                        )
                    } else {
                        cache
                            .fetch_package(&cfg.metadata, network.as_ref(), package, version)
                            .await
                    }
                },
                prompt_criteria_eulas(
                    out,
                    cfg,
                    network.as_ref(),
                    &store,
                    package,
                    None,
                    version,
                    None,
                ),
            );
            eulas.into_diagnostic()?;
            pkg.into_diagnostic()
        })?
    };

    #[cfg(target_family = "unix")]
    if let Some(shell) = std::env::var_os("SHELL") {
        // Loosely borrowed from cargo crev.
        writeln!(out, "Opening nested shell in: {fetched:#?}");
        writeln!(out, "Use `exit` or Ctrl-D to finish.",);
        let status = std::process::Command::new(shell)
            .current_dir(fetched.clone())
            .env("PWD", fetched)
            .status()
            .map_err(CommandError::CommandFailed)
            .into_diagnostic()?;

        writeln!(out, "\nUse |cargo vet certify| to record your audit.");

        if let Some(code) = status.code() {
            panic_any(ExitPanic(code));
        }
        return Ok(());
    }

    writeln!(out, "  fetched to {fetched:#?}");
    writeln!(out, "\nUse |cargo vet certify| to record your audit.");
    Ok(())
}

fn cmd_certify(
    out: &Arc<dyn Out>,
    cfg: &Config,
    sub_args: &CertifyArgs,
) -> Result<(), miette::Report> {
    // Certify that you have reviewed a crate's source for some version / delta
    let network = Network::acquire(cfg);
    let mut store = Store::acquire(cfg, network.as_ref(), false)?;

    // Grab the last fetch and immediately drop the cache
    let last_fetch = Cache::acquire(cfg)?.get_last_fetch();

    do_cmd_certify(out, cfg, sub_args, &mut store, network.as_ref(), last_fetch)?;

    store.commit()?;
    Ok(())
}

fn do_cmd_certify(
    out: &Arc<dyn Out>,
    cfg: &Config,
    sub_args: &CertifyArgs,
    store: &mut Store,
    network: Option<&Network>,
    last_fetch: Option<FetchCommand>,
) -> Result<(), CertifyError> {
    // Before setting up magic, we need to agree on a package
    let package = if let Some(package) = &sub_args.package {
        package.clone()
    } else if let Some(last_fetch) = &last_fetch {
        // If we just fetched a package, assume we want to certify it
        last_fetch.package().to_owned()
    } else {
        return Err(CertifyError::CouldntGuessPackage);
    };

    // FIXME: can/should we check if the version makes sense..?
    if !sub_args.force
        && !foreign_packages(&cfg.metadata, &store.config).any(|pkg| pkg.name == *package)
    {
        return Err(CertifyError::NotAPackage(package));
    }

    #[derive(Debug)]
    enum CertifyKind {
        Delta {
            from: VetVersion,
            to: VetVersion,
        },
        Full {
            version: VetVersion,
        },
        Wildcard {
            user_login: String,
            user_id: CratesUserId,
            start: chrono::NaiveDate,
            end: chrono::NaiveDate,
            set_renew_false: bool,
        },
    }

    let kind = if let Some(login) = &sub_args.wildcard {
        // Fetch publisher information for relevant versions of `package`.
        let publishers = store.ensure_publisher_versions(cfg, network, &package)?;
        let published_versions = publishers
            .iter()
            .filter(|publisher| &publisher.user_login == login);

        let earliest = published_versions
            .min_by_key(|p| p.when)
            .ok_or_else(|| CertifyError::NotAPublisher(login.to_owned(), package.to_owned()))?;

        // Get the from and to dates, defaulting to a from date of the earliest
        // published package by the user, and a to date of 12 months from today.
        let start = sub_args.start_date.unwrap_or(earliest.when);

        let max_end = cfg.today() + chrono::Months::new(12);
        let end = sub_args.end_date.unwrap_or(max_end);
        let set_renew_false = sub_args.end_date.is_some();
        if end > max_end {
            return Err(CertifyError::BadWildcardEndDate(end));
        }

        CertifyKind::Wildcard {
            user_login: earliest.user_login.to_owned(),
            user_id: earliest.user_id,
            start,
            end,
            set_renew_false,
        }
    } else if let Some(v1) = &sub_args.version1 {
        // If explicit versions were provided, use those
        if let Some(v2) = &sub_args.version2 {
            // This is a delta audit
            CertifyKind::Delta {
                from: v1.clone(),
                to: v2.clone(),
            }
        } else {
            // This is a full audit
            CertifyKind::Full {
                version: v1.clone(),
            }
        }
    } else if let Some(fetch) = last_fetch.filter(|f| f.package() == package) {
        // Otherwise, is we just fetched this package, use the version(s) we fetched
        match fetch {
            FetchCommand::Inspect { version, .. } => CertifyKind::Full { version },
            FetchCommand::Diff {
                version1, version2, ..
            } => CertifyKind::Delta {
                from: version1,
                to: version2,
            },
        }
    } else {
        return Err(CertifyError::CouldntGuessVersion(package));
    };

    let (username, who) = if sub_args.who.is_empty() {
        let user_info = get_user_info()?;
        let who = format!("{} <{}>", user_info.username, user_info.email);
        (user_info.username, vec![Spanned::from(who)])
    } else {
        (
            sub_args.who.join(", "),
            sub_args
                .who
                .iter()
                .map(|w| Spanned::from(w.clone()))
                .collect(),
        )
    };

    let (criteria_guess, prompt) = if sub_args.criteria.is_empty() {
        // If we don't have explicit cli criteria, guess the criteria
        //
        // * Check what would cause `cargo vet` to encounter fewer errors
        // * Otherwise check what would cause `cargo vet suggest` to suggest fewer audits
        // * Otherwise guess nothing
        //
        // Regardless of the guess, prompt the user to confirm (just needs to mash enter)
        match &kind {
            CertifyKind::Full { version } => (
                guess_audit_criteria(cfg, store, &package, None, version),
                Some(format!(
                    "choose criteria to certify for {package}:{version}"
                )),
            ),
            CertifyKind::Delta { from, to } => (
                guess_audit_criteria(cfg, store, &package, Some(from), to),
                Some(format!(
                    "choose criteria to certify for {package}:{from} -> {to}"
                )),
            ),
            CertifyKind::Wildcard { .. } => {
                // FIXME: Consider predicting the criteria better for wildcard
                // audits in the future.
                (
                    vec![format::SAFE_TO_DEPLOY.to_owned()],
                    Some(format!("choose criteria to certify for {package}:*")),
                )
            }
        }
    } else {
        // If we do have explcit criteria, don't prompt, but still pass through
        // prompt_pick_criteria to simplify and validate.
        (sub_args.criteria.clone(), None)
    };
    let criteria_names =
        criteria_picker(out, &store.audits.criteria, criteria_guess, prompt.as_ref())?;

    let statement = match &kind {
        CertifyKind::Full { version } => {
            format!(
                    "I, {username}, certify that I have audited version {version} of {package} in accordance with the above criteria.",
                )
        }
        CertifyKind::Delta { from, to } => {
            format!(
                    "I, {username}, certify that I have audited the changes from version {from} to {to} of {package} in accordance with the above criteria.",
                )
        }
        CertifyKind::Wildcard {
            user_login,
            start,
            end,
            ..
        } => {
            format!(
                    "I, {username}, certify that any version of {package} published by '{user_login}' between {start} and {end} will satisfy the above criteria.",
                )
        }
    };

    let mut notes = sub_args.notes.clone();
    if !sub_args.accept_all {
        // Get all the EULAs at once
        let eulas = tokio::runtime::Handle::current().block_on(join_all(
            criteria_names.iter().map(|criteria| async {
                (
                    &criteria[..],
                    eula_for_criteria(network, &store.audits.criteria, criteria).await,
                )
            }),
        ));

        let mut editor = out.editor("VET_CERTIFY")?;
        if let Some(notes) = &notes {
            editor.select_comment_char(notes);
        }

        editor.add_comments(
            "Please read the following criteria and then follow the instructions below:",
        )?;
        editor.add_text("")?;

        for (criteria, eula) in &eulas {
            editor.add_comments(&format!("=== BEGIN CRITERIA {criteria:?} ==="))?;
            editor.add_comments("")?;
            editor.add_comments(eula)?;
            editor.add_comments("")?;
            editor.add_comments("=== END CRITERIA ===")?;
            editor.add_comments("")?;
        }
        editor.add_comments("Uncomment the following statement:")?;
        editor.add_text("")?;
        editor.add_comments(&statement)?;
        editor.add_text("")?;
        editor.add_comments("Add any notes about your audit below this line:")?;
        editor.add_text("")?;
        if let Some(notes) = &notes {
            editor.add_text(notes)?;
        }

        let editor_result = editor.edit()?;

        // Check to make sure that the statement was uncommented as the first
        // line in the parsed file, and remove blank lines between the statement
        // and notes.
        let new_notes = match editor_result.trim_start().strip_prefix(&statement) {
            Some(notes) => notes.trim_start_matches('\n'),
            None => {
                // FIXME: Might be nice to try to save any notes the user typed
                // in and re-try the prompt if the user asks for it, in case
                // they wrote some nice notes, but forgot to uncomment the
                // statement.
                return Err(CertifyError::CouldntFindCertifyStatement);
            }
        };

        // Strip trailing newline if notes would otherwise contain no newlines.
        let new_notes = new_notes
            .strip_suffix('\n')
            .filter(|s| !s.contains('\n'))
            .unwrap_or(new_notes);

        notes = if new_notes.is_empty() {
            None
        } else {
            Some(new_notes.to_owned())
        };
    }

    let criteria = criteria_names.into_iter().map(|s| s.into()).collect();
    match kind {
        CertifyKind::Full { version } => {
            let kind = AuditKind::Full { version };
            let importable = kind.default_importable();
            store
                .audits
                .audits
                .entry(package.clone())
                .or_default()
                .push(AuditEntry {
                    kind,
                    criteria,
                    who,
                    importable,
                    notes,
                    aggregated_from: vec![],
                    is_fresh_import: false,
                });
        }
        CertifyKind::Delta { from, to } => {
            let from_is_git_version = from.git_rev.is_some();
            let kind = AuditKind::Delta { from, to };
            let importable = kind.default_importable();

            let mut entry = AuditEntry {
                kind,
                criteria,
                who,
                importable,
                notes,
                aggregated_from: vec![],
                is_fresh_import: false,
            };

            // Collapse a delta audit with a git `from` version with a prior audit that is
            // non-importable and has identical and satisfied criteria.
            //
            // We merge an adjacent audit for a prior version with the new audit (updating the new
            // audit). The later `update_store` call will remove the now-unused prior audit.
            if from_is_git_version && !sub_args.no_collapse {
                // A closure which returns whether the given audit entry satisfies the criteria
                // being certified.
                let is_rooted_for_criteria = {
                    let mapper = CriteriaMapper::new(&store.audits.criteria);
                    let criteria = mapper.criteria_from_list(&entry.criteria);
                    // If the audit graph fails to load, we always return `false` and thus don't
                    // make any changes.
                    let audit_graph = match resolver::AuditGraph::build(
                        store, &mapper, &package, None,
                    ) {
                        Ok(graph) => Some(graph),
                        Err(_) => {
                            warn!(
                                "failed to build audit graph to determine audit collapse validity, so not collapsing any audits"
                            );
                            None
                        }
                    };

                    move |audit: &AuditEntry| {
                        let Some(audit_graph) = &audit_graph else {
                            return false;
                        };
                        let version = match &audit.kind {
                            AuditKind::Delta { from, .. } => from,
                            AuditKind::Full { .. } => return true,
                            AuditKind::Violation { .. } => return false,
                        };

                        // NOTE we use `criteria` of the certification rather than the target audit
                        // to check root accessibility, which is okay since later in
                        // `try_collapse_with_prior` we verify that the criteria of the audit is
                        // identical to that of the certification.
                        mapper.minimal_indices(&criteria).all(|idx| {
                            audit_graph
                                .search(idx, version, resolver::SearchMode::PreferExemptions)
                                .is_ok()
                        })
                    }
                };
                for audit in store
                    .audits
                    .audits
                    .get(&package)
                    .into_iter()
                    .flatten()
                    .filter(|a| !a.importable && is_rooted_for_criteria(a))
                {
                    if let Some(new_entry) = entry.try_collapse_with_prior(audit) {
                        entry = new_entry;
                        break;
                    }
                }
            }

            store
                .audits
                .audits
                .entry(package.clone())
                .or_default()
                .push(entry);
        }
        CertifyKind::Wildcard {
            user_id,
            start,
            end,
            set_renew_false,
            ..
        } => {
            store
                .audits
                .wildcard_audits
                .entry(package.clone())
                .or_default()
                .push(WildcardEntry {
                    who,
                    criteria,
                    user_id,
                    start: start.into(),
                    end: end.into(),
                    renew: set_renew_false.then_some(false),
                    notes,
                    aggregated_from: vec![],
                    is_fresh_import: false,
                });
        }
    };

    store
        .validate(cfg.today(), false)
        .expect("the new audit entry made the store invalid?");

    // Minimize exemptions after adding the new audit. This will be used to potentially update
    // imports, and remove now-unnecessary exemptions and audits for the target package. We only
    // prefer fresh imports and prune exemptions for the package we certified, to avoid unrelated
    // changes.
    resolver::update_store(cfg, store, |name| resolver::UpdateMode {
        search_mode: if name == &package[..] {
            resolver::SearchMode::PreferFreshImports
        } else {
            resolver::SearchMode::PreferExemptions
        },
        prune_exemptions: name == &package[..],
        prune_non_importable_audits: name == &package[..],
        prune_imports: false,
    });

    Ok(())
}

fn criteria_picker(
    out: &Arc<dyn Out>,
    store_criteria: &SortedMap<CriteriaName, CriteriaEntry>,
    criteria_guess: Vec<CriteriaName>,
    prompt: Option<&impl AsRef<str>>,
) -> Result<Vec<CriteriaName>, CertifyError> {
    let criteria_mapper = CriteriaMapper::new(store_criteria);

    let mut chosen_criteria = criteria_guess;
    if let Some(prompt) = prompt {
        // Prompt for criteria
        loop {
            out.clear_screen()?;
            writeln!(out, "{}", prompt.as_ref());
            for (criteria_idx, criteria_name) in criteria_mapper.all_criteria_names().enumerate() {
                if chosen_criteria.iter().any(|s| s == criteria_name) {
                    writeln!(
                        out,
                        "  {}. {}",
                        criteria_idx + 1,
                        out.style().green().bold().apply_to(criteria_name)
                    );
                } else {
                    writeln!(
                        out,
                        "  {}. {}",
                        criteria_idx + 1,
                        out.style().bold().dim().apply_to(criteria_name)
                    );
                }
            }

            writeln!(out);
            writeln!(out, "current selection: {:?}", chosen_criteria);
            writeln!(out, "(press ENTER to accept the current criteria)");
            let input = out.read_line_with_prompt("> ")?;
            let input = input.trim();
            if input.is_empty() {
                if chosen_criteria.is_empty() {
                    return Err(CertifyError::NoCriteriaChosen);
                }
                // User done selecting criteria
                break;
            }

            // FIXME: these errors get cleared away right away
            let answer = if let Ok(val) = input.parse::<usize>() {
                val
            } else {
                // ERRORS: immediate error print to output for feedback, non-fatal
                writeln!(out, "error: not a valid integer");
                continue;
            };
            if answer == 0 || answer > criteria_mapper.len() {
                // ERRORS: immediate error print to output for feedback, non-fatal
                writeln!(out, "error: not a valid criteria");
                continue;
            }

            let selection = criteria_mapper.criteria_name(answer - 1).to_owned();
            if chosen_criteria.contains(&selection) {
                chosen_criteria.retain(|x| x != &selection);
            } else {
                chosen_criteria.push(selection);
            }
        }
    }

    // Round-trip this through the criteria_mapper to clean up `implies` relationships
    let criteria_set = criteria_mapper.criteria_from_list(&chosen_criteria);
    Ok(criteria_mapper
        .criteria_names(&criteria_set)
        .map(|s| s.to_owned())
        .collect::<Vec<_>>())
}

/// Attempt to guess which criteria are being certified for a given package and
/// audit kind.
///
/// The logic which this method uses to guess the criteria to use is as follows:
///
/// * Check what would cause `cargo vet` to encounter fewer errors
/// * Otherwise check what would cause `cargo vet suggest` to suggest fewer audits
/// * Otherwise guess nothing
fn guess_audit_criteria(
    cfg: &Config,
    store: &Store,
    package: PackageStr<'_>,
    from: Option<&VetVersion>,
    to: &VetVersion,
) -> Vec<String> {
    // Attempt to resolve a normal `cargo vet`, and try to find criteria which
    // would heal some errors in that result if it fails.
    let criteria = resolver::resolve(&cfg.metadata, cfg.cli.filter_graph.as_ref(), store)
        .compute_suggested_criteria(package, from, to);
    if !criteria.is_empty() {
        return criteria;
    }

    // If a normal `cargo vet` failed to turn up any criteria, try a more
    // aggressive `cargo vet suggest`.
    //
    // This is as much as we can do, so just return the result whether or not we
    // find anything.
    resolver::resolve(
        &cfg.metadata,
        cfg.cli.filter_graph.as_ref(),
        &store.clone_for_suggest(true),
    )
    .compute_suggested_criteria(package, from, to)
}

/// Prompt the user to read the EULAs for the expected criteria which they will
/// be certifying for with this diff or inspect command.
///
/// This method is async so it can be performed concurrently with waiting for
/// the downloads to complete.
#[allow(clippy::too_many_arguments)]
async fn prompt_criteria_eulas(
    out: &Arc<dyn Out>,
    cfg: &Config,
    network: Option<&Network>,
    store: &Store,
    package: PackageStr<'_>,
    from: Option<&VetVersion>,
    to: &VetVersion,
    url: Option<&str>,
) -> Result<(), io::Error> {
    let description = if let Some(from) = from {
        format!("You are about to diff versions {from} and {to} of '{package}'")
    } else {
        format!("You are about to inspect version {to} of '{package}'")
    };

    // Guess which criteria the user is going to be auditing the package for.
    let criteria_names = guess_audit_criteria(cfg, store, package, from, to);

    // FIXME: These `writeln` calls can do blocking I/O, but they hopefully
    // shouldn't block long enough for it interfere with downloading packages in
    // the background. We do the `read_line_with_prompt` call async.
    if criteria_names.is_empty() {
        writeln!(out, "{}", out.style().bold().apply_to(description));
        warn!("unable to determine likely criteria, this may not be a relevant audit for this project.");
    } else {
        let eulas = join_all(criteria_names.iter().map(|criteria| async {
            (
                &criteria[..],
                eula_for_criteria(network, &store.audits.criteria, criteria).await,
            )
        }))
        .await;

        for (idx, (criteria, eula)) in eulas.into_iter().enumerate() {
            let prompt = if idx == 0 {
                format!("{description}, likely to certify it for {criteria:?}, which means:")
            } else {
                format!("... and for {criteria:?}, which means:")
            };
            writeln!(
                out,
                "{}\n\n  {}",
                out.style().bold().apply_to(prompt),
                eula.replace('\n', "\n  "),
            );
        }

        writeln!(
            out,
            "{}",
            out.style().bold().apply_to(
                "Please read the above criteria and consider them when performing the audit."
            )
        );
    }

    writeln!(
        out,
        "{}",
        out.style().bold().apply_to(
            "Other software projects may rely on this audit. Ask for help if you're not sure.\n"
        )
    );

    let final_prompt = if let Some(url) = url {
        writeln!(
            out,
            "You can inspect the {} here: {}\n",
            if from.is_some() { "diff" } else { "crate" },
            url,
        );
        "(press ENTER to open in your browser, or re-run with --mode=local)"
    } else {
        "(press ENTER to inspect locally)"
    };

    let out_ = out.clone();
    tokio::task::spawn_blocking(move || out_.read_line_with_prompt(final_prompt)).await??;
    Ok(())
}

fn cmd_import(
    _out: &Arc<dyn Out>,
    cfg: &Config,
    sub_args: &ImportArgs,
) -> Result<(), miette::Report> {
    let Some(network) = Network::acquire(cfg) else {
        return Err(miette!("`cargo vet import` cannot be run while frozen"));
    };

    // Determine the URL for the import, potentially fetching the registry to
    // find it.
    let registry_file;
    let import_urls = if sub_args.url.is_empty() {
        registry_file = tokio::runtime::Handle::current().block_on(fetch_registry(&network))?;
        registry_file
            .registry
            .get(&sub_args.name)
            .ok_or_else(|| miette!("no peer named {} found in the registry", &sub_args.name))
            .map(|entry| entry.url.clone())?
    } else {
        sub_args.url.clone()
    };

    let mut store = Store::acquire_offline(cfg)?;

    // Insert a new entry for the new import, or update an existing entry to use
    // the newly specified URLs.
    store
        .config
        .imports
        .entry(sub_args.name.clone())
        .or_default()
        .url = import_urls;

    // After adding the new entry, go online, this will fetch the new import.
    let cache = Cache::acquire(cfg)?;
    tokio::runtime::Handle::current().block_on(store.go_online(cfg, &network, &cache, false))?;

    // Update the store state, pruning unnecessary exemptions, audits, and imports.
    resolver::update_store(cfg, &mut store, |_| resolver::UpdateMode {
        search_mode: resolver::SearchMode::PreferFreshImports,
        prune_exemptions: true,
        prune_non_importable_audits: true,
        prune_imports: true,
    });

    store.commit()?;

    Ok(())
}

fn cmd_trust(out: &Arc<dyn Out>, cfg: &Config, sub_args: &TrustArgs) -> Result<(), miette::Report> {
    // Certify that you have reviewed a crate's source for some version / delta
    let network = Network::acquire(cfg);
    let mut store = Store::acquire(cfg, network.as_ref(), false)?;

    do_cmd_trust(out, cfg, sub_args, &mut store, network.as_ref())?;

    store.commit()?;

    Ok(())
}

fn do_cmd_trust(
    out: &Arc<dyn Out>,
    cfg: &Config,
    sub_args: &TrustArgs,
    store: &mut Store,
    network: Option<&Network>,
) -> Result<(), miette::Report> {
    if let Some(package) = &sub_args.package {
        // Fetch publisher information for relevant versions of `package`.
        let publishers = store.ensure_publisher_versions(cfg, network, package)?;

        let publisher_login = if let Some(login) = &sub_args.publisher_login {
            login.clone()
        } else if let Some(first) = publishers.first() {
            if publishers
                .iter()
                .all(|publisher| publisher.user_id == first.user_id)
            {
                first.user_login.clone()
            } else {
                return Err(miette!(
                    "The package '{}' has multiple known publishers, \
                    please explicitly specify which publisher to trust",
                    package
                ));
            }
        } else {
            return Err(miette!(
                "The package '{}' has no known publishers, so cannot be trusted",
                package
            ));
        };

        apply_cmd_trust(
            out,
            cfg,
            store,
            network,
            package,
            &publisher_login,
            sub_args.start_date,
            sub_args.end_date,
            &sub_args.criteria,
            sub_args.notes.as_ref(),
        )
    } else if let Some(publisher_login) = &sub_args.all {
        // Run the resolver against the store in "suggest" mode to discover the
        // set of packages which either fail to audit or need exemptions.
        let suggest_store = store.clone_for_suggest(true);
        let report =
            resolver::resolve(&cfg.metadata, cfg.cli.filter_graph.as_ref(), &suggest_store);
        let resolver::Conclusion::FailForVet(fail) = &report.conclusion else {
            return Err(miette!(
                "No failing or exempted crates, trust --all will do nothing"
            ));
        };

        // Enumerate the failed packages to collect the set of packages which
        // will be trusted.
        let mut failed_criteria = report.criteria_mapper.no_criteria();
        let mut trust = Vec::new();
        let mut skipped = Vec::new();
        for (failure_idx, audit_failure) in &fail.failures {
            let package = &report.graph.nodes[*failure_idx];

            // Ensure the store has publisher information for this package. This
            // is a no-op if called multiple times for the same package.
            let publishers = store.ensure_publisher_versions(cfg, network, package.name)?;
            let by_user = publishers
                .iter()
                .filter(|p| &p.user_login == publisher_login)
                .count();
            if by_user == 0 {
                continue; // never published by this user
            }

            // Record if we're skipping this package due to multiple publishers.
            if by_user != publishers.len() && !sub_args.allow_multiple_publishers {
                skipped.push(package.name);
            } else {
                trust.push(package.name);
                failed_criteria.unioned_with(&audit_failure.criteria_failures);
            }
        }
        trust.sort();
        trust.dedup();

        // Delay warning about skipped entries until after `criteria_picker`, as
        // that may clear the terminal.
        let maybe_warn_skipped = || {
            if !skipped.is_empty() {
                skipped.sort();
                skipped.dedup();
                warn!(
                    "Skipped {} due to multiple publishers",
                    string_format::FormatShortList::new(skipped)
                );
                warn!("  Run with --allow-multiple-publishers to also trust these packages");
            }
        };

        if trust.is_empty() {
            maybe_warn_skipped();
            return Err(miette!(
                "No failing or exempted packages published by {publisher_login}"
            ));
        }

        let criteria_names = criteria_picker(
            out,
            &store.audits.criteria,
            if sub_args.criteria.is_empty() {
                report
                    .criteria_mapper
                    .criteria_names(&failed_criteria)
                    .map(|s| s.to_owned())
                    .collect()
            } else {
                sub_args.criteria.clone()
            },
            if sub_args.criteria.is_empty() {
                Some(format!(
                    "choose trusted criteria for packages published by {publisher_login} ({})",
                    string_format::FormatShortList::new(trust.clone())
                ))
            } else {
                None
            }
            .as_ref(),
        )?;

        maybe_warn_skipped();

        for package in &trust {
            apply_cmd_trust(
                out,
                cfg,
                store,
                network,
                package,
                publisher_login,
                sub_args.start_date,
                sub_args.end_date,
                &criteria_names,
                sub_args.notes.as_ref(),
            )?;
        }

        Ok(())
    } else {
        Err(miette!("Please specify either a package to trust or --all"))
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_cmd_trust(
    out: &Arc<dyn Out>,
    cfg: &Config,
    store: &mut Store,
    network: Option<&Network>,
    package: &str,
    publisher_login: &str,
    start_date: Option<chrono::NaiveDate>,
    end_date: Option<chrono::NaiveDate>,
    criteria: &[CriteriaName],
    notes: Option<&String>,
) -> Result<(), miette::Report> {
    // Fetch publisher information for relevant versions of `package`.
    let publishers = store.ensure_publisher_versions(cfg, network, package)?;

    let published_versions = publishers
        .iter()
        .filter(|publisher| publisher.user_login == publisher_login);

    let earliest = published_versions.min_by_key(|p| p.when).ok_or_else(|| {
        CertifyError::NotAPublisher(publisher_login.to_owned(), package.to_owned())
    })?;
    let user_id = earliest.user_id;

    // Get the from and to dates, defaulting to a from date of the earliest
    // published package by the user, and a to date of 12 months from today.
    let start = start_date.unwrap_or(earliest.when);

    let end = end_date.unwrap_or(cfg.today() + chrono::Months::new(12));

    let criteria_names = criteria_picker(
        out,
        &store.audits.criteria,
        if criteria.is_empty() {
            vec![format::SAFE_TO_DEPLOY.to_owned()]
        } else {
            criteria.to_owned()
        },
        if criteria.is_empty() {
            Some(format!(
                "choose trusted criteria for {package}:* published by {publisher_login}"
            ))
        } else {
            None
        }
        .as_ref(),
    )?;
    let criteria = criteria_names.into_iter().map(Spanned::from).collect();

    // Check if we have an existing trust entry which could be extended to
    // handle a wider date range, and update that instead if possible.
    let trust_entries = store.audits.trusted.entry(package.to_owned()).or_default();
    if let Some(trust_entry) = trust_entries.iter_mut().find(|trust_entry| {
        trust_entry.criteria == criteria
            && trust_entry.user_id == user_id
            && start <= *trust_entry.start
            && *trust_entry.end <= end
            && notes.is_none()
    }) {
        trust_entry.start = start.into();
        trust_entry.end = end.into();
    } else {
        trust_entries.push(TrustEntry {
            criteria,
            user_id,
            start: start.into(),
            end: end.into(),
            notes: notes.cloned(),
            aggregated_from: vec![],
        });
    }

    store
        .validate(cfg.today(), false)
        .expect("the new trusted entry made the store invalid?");

    // Minimize exemptions and audits after adding the new trust entry. This will be used to
    // potentially update imports, and remove now-unnecessary exemptions for the target package. We
    // only prefer fresh imports and prune exemptions for the package we trusted, to avoid
    // unrelated changes.
    resolver::update_store(cfg, store, |name| resolver::UpdateMode {
        search_mode: if name == package {
            resolver::SearchMode::PreferFreshImports
        } else {
            resolver::SearchMode::PreferExemptions
        },
        prune_exemptions: name == package,
        prune_non_importable_audits: name == package,
        prune_imports: false,
    });
    Ok(())
}

fn cmd_record_violation(
    out: &Arc<dyn Out>,
    cfg: &Config,
    sub_args: &RecordViolationArgs,
) -> Result<(), miette::Report> {
    // Mark a package as a violation
    let mut store = Store::acquire_offline(cfg)?;

    let kind = AuditKind::Violation {
        violation: sub_args.versions.clone(),
    };

    let (_username, who) = if sub_args.who.is_empty() {
        let user_info = get_user_info()?;
        let who = format!("{} <{}>", user_info.username, user_info.email);
        (user_info.username, vec![Spanned::from(who)])
    } else {
        (
            sub_args.who.join(", "),
            sub_args
                .who
                .iter()
                .map(|w| Spanned::from(w.clone()))
                .collect(),
        )
    };

    let notes = sub_args.notes.clone();

    let criteria = if sub_args.criteria.is_empty() {
        // TODO: provide an interactive prompt for this
        vec![store.config.default_criteria.clone().into()]
    } else {
        sub_args
            .criteria
            .iter()
            .map(|s| s.to_owned().into())
            .collect()
    };

    // FIXME: can/should we check if the version makes sense..?
    if !sub_args.force
        && !foreign_packages(&cfg.metadata, &store.config).any(|pkg| pkg.name == sub_args.package)
    {
        // ERRORS: immediate fatal diagnostic? should we allow you to forbid random packages?
        // You're definitely *allowed* to have unused audits, otherwise you'd be constantly deleting
        // useful audits whenever you update your dependencies! But this might be a useful guard
        // against typosquatting or other weird issues?
        return Err(miette!(
            "'{}' isn't one of your foreign packages",
            sub_args.package
        ));
    }

    // Ok! Ready to commit the audit!
    let new_entry = AuditEntry {
        kind,
        criteria,
        who,
        importable: true,
        notes,
        aggregated_from: vec![],
        is_fresh_import: false,
    };

    store
        .audits
        .audits
        .entry(sub_args.package.clone())
        .or_default()
        .push(new_entry);

    store.commit()?;

    writeln!(out, "If you've identified a security vulnerability in {} please report it at https://github.com/rustsec/advisory-db#reporting-vulnerabilities", sub_args.package);

    Ok(())
}

fn cmd_add_exemption(
    _out: &Arc<dyn Out>,
    cfg: &Config,
    sub_args: &AddExemptionArgs,
) -> Result<(), miette::Report> {
    // Add an exemption entry
    let mut store = Store::acquire_offline(cfg)?;

    let notes = sub_args.notes.clone();

    let criteria = if sub_args.criteria.is_empty() {
        // TODO: provide an interactive prompt for this
        vec![store.config.default_criteria.clone().into()]
    } else {
        sub_args
            .criteria
            .iter()
            .map(|s| s.to_owned().into())
            .collect()
    };

    let suggest = !sub_args.no_suggest;

    // FIXME: can/should we check if the version makes sense..?
    if !sub_args.force
        && !foreign_packages(&cfg.metadata, &store.config).any(|pkg| pkg.name == sub_args.package)
    {
        // ERRORS: immediate fatal diagnostic? should we allow you to certify random packages?
        // You're definitely *allowed* to have unused audits, otherwise you'd be constantly deleting
        // useful audits whenever you update your dependencies! But this might be a useful guard
        // against typosquatting or other weird issues?
        return Err(miette!(
            "'{}' isn't one of your foreign packages",
            sub_args.package
        ));
    }

    // Ok! Ready to commit the audit!
    let new_entry = ExemptedDependency {
        criteria,
        notes,
        version: sub_args.version.clone(),
        suggest,
    };

    store
        .config
        .exemptions
        .entry(sub_args.package.clone())
        .or_default()
        .push(new_entry);

    store.commit()?;

    Ok(())
}

fn cmd_suggest(
    out: &Arc<dyn Out>,
    cfg: &Config,
    _sub_args: &SuggestArgs,
) -> Result<(), miette::Report> {
    // Run the checker to validate that the current set of deps is covered by the current cargo vet store
    trace!("suggesting...");
    let network = Network::acquire(cfg);
    let suggest_store = Store::acquire(cfg, network.as_ref(), false)?.clone_for_suggest(true);

    // DO THE THING!!!!
    let report = resolver::resolve(&cfg.metadata, cfg.cli.filter_graph.as_ref(), &suggest_store);
    let suggest = report.compute_suggest(cfg, &suggest_store, network.as_ref())?;
    match cfg.cli.output_format {
        OutputFormat::Human => report
            .print_suggest_human(out, cfg, suggest.as_ref())
            .into_diagnostic()?,
        OutputFormat::Json => report.print_json(out, suggest.as_ref())?,
    }

    Ok(())
}

fn cmd_regenerate_imports(
    out: &Arc<dyn Out>,
    cfg: &Config,
    _sub_args: &RegenerateImportsArgs,
) -> Result<(), miette::Report> {
    trace!("regenerating imports...");

    if cfg.cli.locked {
        // ERRORS: just a warning that you're holding it wrong, unclear if immediate or buffered,
        // or if this should be a hard error, or if we should ignore the --locked flag and
        // just do it anyway
        writeln!(
            out,
            "warning: ran `regenerate imports` with --locked, this won't do anything!"
        );
        return Ok(());
    }

    let network = Network::acquire(cfg);
    let mut store = Store::acquire(cfg, network.as_ref(), true)?;

    // Update the store state, pruning unnecessary exemptions, audits, and imports.
    resolver::update_store(cfg, &mut store, |_| resolver::UpdateMode {
        search_mode: resolver::SearchMode::PreferFreshImports,
        prune_exemptions: true,
        prune_non_importable_audits: true,
        prune_imports: true,
    });

    store.commit()?;
    Ok(())
}

fn cmd_regenerate_audit_as(
    _out: &Arc<dyn Out>,
    cfg: &Config,
    _sub_args: &RegenerateAuditAsCratesIoArgs,
) -> Result<(), miette::Report> {
    trace!("regenerating audit-as-crates-io...");
    let network = Network::acquire(cfg);
    let mut store = Store::acquire_offline(cfg)?;

    tokio::runtime::Handle::current().block_on(fix_audit_as(cfg, network.as_ref(), &mut store))?;

    // We were successful, commit the store
    store.commit()?;

    Ok(())
}

fn cmd_regenerate_unpublished(
    out: &Arc<dyn Out>,
    cfg: &Config,
    _sub_args: &RegenerateUnpublishedArgs,
) -> Result<(), miette::Report> {
    trace!("regenerating unpublished entries...");

    if cfg.cli.locked {
        // ERRORS: just a warning that you're holding it wrong, unclear if immediate or buffered,
        // or if this should be a hard error, or if we should ignore the --locked flag and
        // just do it anyway
        writeln!(
            out,
            "warning: ran `regenerate unpublished` with --locked, this won't do anything!"
        );
        return Ok(());
    }

    let network = Network::acquire(cfg);
    let mut store = Store::acquire(cfg, network.as_ref(), false)?;

    // Strip all non-fresh entries from the unpublished table, marking the
    // previously fresh entries as non-fresh.
    if let Some(live_imports) = &mut store.live_imports {
        for unpublished in live_imports.unpublished.values_mut() {
            unpublished.retain_mut(|u| std::mem::replace(&mut u.is_fresh_import, false));
        }
    }

    // Run a minimal store update to import new entries which would now be
    // required for `check` to pass. Note that this won't ensure `check`
    // actually passes after the change.
    resolver::update_store(cfg, &mut store, |_| resolver::UpdateMode {
        search_mode: resolver::SearchMode::PreferExemptions,
        prune_exemptions: false,
        prune_non_importable_audits: false,
        prune_imports: false,
    });

    store.commit()?;
    Ok(())
}

fn cmd_renew(out: &Arc<dyn Out>, cfg: &Config, sub_args: &RenewArgs) -> Result<(), miette::Report> {
    trace!("renewing wildcard audits");
    let network = Network::acquire(cfg);
    let mut store = Store::acquire(cfg, network.as_ref(), false)?;
    do_cmd_renew(out, cfg, &mut store, sub_args);
    store.commit()?;
    Ok(())
}

fn do_cmd_renew(out: &Arc<dyn Out>, cfg: &Config, store: &mut Store, sub_args: &RenewArgs) {
    assert!(sub_args.expiring ^ sub_args.crate_name.is_some());

    // We need the cache to map user ids to user names, though we can work around it if there is an
    // error.
    let cache = Cache::acquire(cfg).ok();

    let new_end_date = cfg.today() + chrono::Months::new(12);

    let mut renewing: WildcardAuditRenewal;

    if let Some(name) = &sub_args.crate_name {
        match WildcardAuditRenewal::single_crate(name, store) {
            Some(renewal) => {
                renewing = renewal;
                if renewing.is_empty() {
                    info!("no wildcard audits for {name} are eligible for renewal (all have `renew = false`)");
                    return;
                }
            }
            None => {
                warn!("ran `renew {name}`, but there are no wildcard audits for the crate");
                return;
            }
        }
    } else {
        // Find and update all expiring crates.
        assert!(sub_args.expiring);
        renewing = WildcardAuditRenewal::expiring(cfg, store, !sub_args.include_inactive);

        if renewing.is_empty() {
            info!("no wildcard audits that are eligible for renewal have expired or are expiring in the next {WILDCARD_AUDIT_EXPIRATION_STRING}");
            return;
        }
    }

    renewing.renew(new_end_date);

    writeln!(
        out,
        "Updated wildcard audits for the following crates and publishers to expire on {new_end_date}:"
    );

    let user_string = |user_id: u64| -> String {
        cache
            .as_ref()
            .and_then(|c| c.get_crates_user_info(user_id))
            .map(|n| n.to_string())
            .unwrap_or_else(|| format!("id={}", user_id))
    };
    for (name, entries) in renewing.crates {
        writeln!(
            out,
            "  {}: {:80}",
            name,
            string_format::FormatShortList::new(
                entries
                    .iter()
                    .map(|(entry, _)| user_string(entry.user_id))
                    .collect()
            )
        );
    }
}

/// Adjust the store to satisfy audit-as-crates-io issues
///
/// Every reported issue will be resolved by just setting `audit-as-crates-io = Some(false)`,
/// because that always works, no matter what the problem is.
async fn fix_audit_as(
    cfg: &Config,
    network: Option<&Network>,
    store: &mut Store,
) -> Result<(), CacheAcquireError> {
    let _spinner = indeterminate_spinner("Fetching", "crate metadata");

    let mut cache = Cache::acquire(cfg)?;

    let third_party_packages = foreign_packages_strict(&cfg.metadata, &store.config)
        .map(|p| &p.name)
        .collect::<SortedSet<_>>();

    let issues = check_audit_as_crates_io(cfg, store, network, &mut cache).await;
    if let Err(AuditAsErrors { errors }) = issues {
        fn get_policy_entry<'a>(
            store: &'a mut Store,
            cfg: &Config,
            third_party_packages: &SortedSet<&String>,
            error: &PackageError,
        ) -> &'a mut PolicyEntry {
            let is_third_party = third_party_packages.contains(&error.package);
            let all_versions = || {
                cfg.metadata
                    .packages
                    .iter()
                    .filter(|&p| (p.name == error.package))
                    .map(|p| p.vet_version())
                    .collect()
            };
            // This can only fail if there's a logical error in `check_audit_as_crates_io`.
            store
                .config
                .policy
                .get_mut_or_default(
                    error.package.clone(),
                    is_third_party.then_some(error.version.as_ref()).flatten(),
                    all_versions,
                )
                .expect("unexpected crate policy state")
        }

        for error in errors {
            match error {
                AuditAsError::NeedsAuditAs(NeedsAuditAsErrors { errors }) => {
                    for err in errors {
                        // We'll default audit-as-crates-io to true if the
                        // crate's description or repository matches an existing
                        // package on crates.io.
                        //
                        // XXX: This is just indended to reduce the chance of
                        // false positives, but is certainly a bit of a loose
                        // comparison. If it turns out to be an issue we can
                        // improve it in the future.
                        //
                        // NOTE: Handle all errors silently here, as we can
                        // always recover by setting `audit-as-crates-io =
                        // false`. The error cases below are very unlikely to
                        // occur since information will be cached from the
                        // initial checks which generated the
                        // NeedsAuditAsErrors.
                        let default_audit_as =
                            match cache.crates_io_info(network, &err.package).await {
                                Ok(entry) => cfg.metadata.packages.iter().any(|p| {
                                    p.name == err.package && entry.metadata.consider_as_same(p)
                                }),
                                Err(e) => {
                                    warn!("crate metadata error for {}: {e}", &err.package);
                                    false
                                }
                            };

                        get_policy_entry(store, cfg, &third_party_packages, &err)
                            .audit_as_crates_io = Some(default_audit_as);
                    }
                }
                AuditAsError::ShouldntBeAuditAs(ShouldntBeAuditAsErrors { errors }) => {
                    for err in errors {
                        get_policy_entry(store, cfg, &third_party_packages, &err)
                            .audit_as_crates_io = Some(false);
                    }
                }
                AuditAsError::UnusedAuditAs(unuseds) => {
                    for err in unuseds.errors {
                        // XXX: consider removing the policy completely if
                        // there's nothing left in it anymore?
                        if let Some(policy) = store
                            .config
                            .policy
                            .get_mut(&err.package, err.version.as_ref())
                        {
                            policy.audit_as_crates_io = None;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn cmd_regenerate_exemptions(
    _out: &Arc<dyn Out>,
    cfg: &Config,
    _sub_args: &RegenerateExemptionsArgs,
) -> Result<(), miette::Report> {
    trace!("regenerating exemptions...");
    let network = Network::acquire(cfg);
    let mut store = Store::acquire(cfg, network.as_ref(), false)?;

    // Update the store using a full RegenerateExemptions search.
    resolver::update_store(cfg, &mut store, |_| resolver::UpdateMode {
        search_mode: resolver::SearchMode::RegenerateExemptions,
        prune_exemptions: true,
        prune_non_importable_audits: true,
        prune_imports: true,
    });

    // We were successful, commit the store
    store.commit()?;

    Ok(())
}

fn cmd_diff(out: &Arc<dyn Out>, cfg: &Config, sub_args: &DiffArgs) -> Result<(), miette::Report> {
    let version1 = &sub_args.version1;
    let version2 = &sub_args.version2;
    let package = &*sub_args.package;

    let to_compare = {
        let network = Network::acquire(cfg);
        let store = Store::acquire(cfg, network.as_ref(), false)?;
        let cache = Cache::acquire(cfg)?;

        // Record this command for magic in `vet certify`
        cache.set_last_fetch(FetchCommand::Diff {
            package: package.to_owned(),
            version1: version1.clone(),
            version2: version2.clone(),
        });

        // Determine the fetch mode to use. We'll need to do a local diff if the
        // selected version has a git revision.
        let mode = cache.select_fetch_mode(
            sub_args.mode,
            version1.git_rev.is_some() || version2.git_rev.is_some(),
        );

        if mode != FetchMode::Local {
            let url = match mode {
                FetchMode::Sourcegraph => {
                    format!(
                        "https://sourcegraph.com/crates/{package}/-/compare/v{version1}...v{version2}?visible=7000"
                    )
                }
                FetchMode::DiffRs => {
                    format!("https://diff.rs/{package}/{version1}/{version2}/")
                }
                FetchMode::Local => unreachable!(),
            };
            tokio::runtime::Handle::current()
                .block_on(prompt_criteria_eulas(
                    out,
                    cfg,
                    network.as_ref(),
                    &store,
                    package,
                    Some(version1),
                    version2,
                    Some(&url),
                ))
                .into_diagnostic()?;

            open::that(&url).into_diagnostic().wrap_err_with(|| {
                format!("Couldn't open {url} in your browser, try --mode=local?")
            })?;

            writeln!(out, "\nUse |cargo vet certify| to record your audit.");

            return Ok(());
        }

        tokio::runtime::Handle::current().block_on(async {
            // NOTE: don't `try_join` everything as we don't want to abort the
            // prompt to the user if the download fails while it is being shown, as
            // that could be disorienting.
            let (to_compare, eulas) = tokio::join!(
                async {
                    let (pkg1, pkg2) = tokio::try_join!(
                        cache.fetch_package(&cfg.metadata, network.as_ref(), package, version1),
                        cache.fetch_package(&cfg.metadata, network.as_ref(), package, version2)
                    )?;
                    let (_, to_compare) = cache
                        .diffstat_package(
                            &pkg1,
                            &pkg2,
                            version1.git_rev.is_some() || version2.git_rev.is_some(),
                        )
                        .await?;
                    Ok::<_, FetchAndDiffError>(to_compare)
                },
                prompt_criteria_eulas(
                    out,
                    cfg,
                    network.as_ref(),
                    &store,
                    package,
                    Some(version1),
                    version2,
                    None,
                )
            );
            eulas.into_diagnostic()?;
            to_compare.into_diagnostic()
        })?
    };

    writeln!(out);

    // Start a pager to show the output from our diff invocations. This will
    // fall back to just printing to `stdout` if no pager is available or we're
    // not piped to a terminal.
    let mut pager = Pager::new(&**out).into_diagnostic()?;

    for (from, to) in to_compare {
        let output = std::process::Command::new("git")
            .arg("-c")
            .arg("core.safecrlf=false")
            .arg("diff")
            .arg(if pager.use_color() {
                "--color=always"
            } else {
                "--color=never"
            })
            .arg("--no-index")
            .arg("--ignore-cr-at-eol")
            .arg("--abbrev=7")
            .arg(&from)
            .arg(&to)
            .stdout(Stdio::piped())
            .output()
            .map_err(CommandError::CommandFailed)
            .into_diagnostic()?;
        io::Write::write_all(&mut pager, &output.stdout).into_diagnostic()?;
    }

    pager.wait().into_diagnostic()?;

    writeln!(out, "\nUse |cargo vet certify| to record your audit.");

    Ok(())
}

fn cmd_check(
    out: &Arc<dyn Out>,
    cfg: &Config,
    _sub_args: &CheckArgs,
) -> Result<(), miette::Report> {
    // Run the checker to validate that the current set of deps is covered by the current cargo vet store
    trace!("vetting...");

    let network = Network::acquire(cfg);
    let mut store = Store::acquire(cfg, network.as_ref(), false)?;

    if !cfg.cli.locked {
        // Check if any of our first-parties are in the crates.io registry
        let mut cache = Cache::acquire(cfg).into_diagnostic()?;
        // Check crate policies prior to audit_as_crates_io because the suggestions of
        // check_audit_as_crates_io will rely on the correct structure of crate policies.
        check_crate_policies(cfg, &store)?;
        tokio::runtime::Handle::current().block_on(check_audit_as_crates_io(
            cfg,
            &store,
            network.as_ref(),
            &mut cache,
        ))?;
    }

    // DO THE THING!!!!
    let report = resolver::resolve(&cfg.metadata, cfg.cli.filter_graph.as_ref(), &store);

    // Bare `cargo vet` shouldn't suggest in CI
    let suggest = if !cfg.cli.locked {
        report.compute_suggest(cfg, &store, network.as_ref())?
    } else {
        None
    };

    match cfg.cli.output_format {
        OutputFormat::Human => report
            .print_human(out, cfg, suggest.as_ref())
            .into_diagnostic()?,
        OutputFormat::Json => report.print_json(out, suggest.as_ref())?,
    }

    // Only save imports if we succeeded, to avoid any modifications on error.
    if report.has_errors() {
        // ERRORS: immediate fatal diagnostic? Arguably should be silent.
        // Err(eyre!("report contains errors"))?;
        panic_any(ExitPanic(-1));
    } else {
        if !cfg.cli.locked {
            // Simulate a full `fetch-imports` run, and record the potential
            // pruned imports and exemptions.
            let updates = resolver::get_store_updates(cfg, &store, |_| resolver::UpdateMode {
                search_mode: resolver::SearchMode::PreferFreshImports,
                prune_exemptions: true,
                prune_non_importable_audits: true,
                prune_imports: true,
            });

            // Perform a minimal store update to pull in necessary imports,
            // while avoiding any other changes to exemptions or imports.
            resolver::update_store(cfg, &mut store, |_| resolver::UpdateMode {
                search_mode: resolver::SearchMode::PreferExemptions,
                prune_exemptions: false,
                prune_non_importable_audits: false,
                prune_imports: false,
            });

            // XXX: Consider trying to be more precise here? Would require some
            // more clever comparisons.
            if store.config.exemptions != updates.exemptions {
                warn!("Your supply-chain has unnecessary exemptions which could be relaxed or pruned.");
                warn!("  Consider running `cargo vet prune` to prune unnecessary exemptions and imports.");
            } else if store.imports != updates.imports {
                warn!("Your supply-chain has unnecessary imports which could be pruned.");
                warn!("  Consider running `cargo vet prune` to prune unnecessary imports.");
            } else if store.audits.audits != updates.audits {
                warn!("Your supply-chain has unnecessary audits which could be pruned.");
                warn!("  Consider running `cargo vet prune` to prune unnecessary imports.");
            }

            // Check if we have `unpublished` entries for crates which have since been published.
            let since_published: Vec<_> = updates
                .imports
                .unpublished
                .iter()
                .filter(|(_, unpublished)| unpublished.iter().any(|u| !u.still_unpublished))
                .map(|(package, _)| package)
                .collect();
            if !since_published.is_empty() {
                let published = string_format::FormatShortList::new(since_published);
                warn!("Your supply-chain depends on previously unpublished versions of {published} which have since been published.");
                warn!("  Consider running `cargo vet regenerate unpublished` to remove these entries.");
            }

            // Warn about wildcard audits which will be expiring soon or have expired.
            let expiry = WildcardAuditRenewal::expiring(cfg, &mut store, true);

            if !expiry.is_empty() {
                let expired = expiry.expired_crates();
                let expiring_soon = expiry.expiring_crates();
                if !expired.is_empty() {
                    let expired = string_format::FormatShortList::new(expired);
                    warn!(
                        "Your audit set contains wildcard audits for {expired} which have expired."
                    );
                }
                if !expiring_soon.is_empty() {
                    let expiring = string_format::FormatShortList::new(expiring_soon);
                    warn!("Your audit set contains wildcard audits for {expiring} which expire within the next {WILDCARD_AUDIT_EXPIRATION_STRING}.");
                }
                warn!("  Consider running `cargo vet renew --expiring` or adding `renew = false` to the wildcard entries in audits.toml.");
            }
        }

        store.commit()?;
    }

    Ok(())
}

#[derive(Default)]
struct WildcardAuditRenewal<'a> {
    // the bool indicates whether the entry for that user id is already expired (true) or will
    // expire soon (false)
    pub crates: SortedMap<PackageStr<'a>, Vec<(&'a mut WildcardEntry, bool)>>,
}

impl<'a> WildcardAuditRenewal<'a> {
    /// Get all wildcard audit entries which have expired or will expire soon.
    ///
    /// This function _does not_ modify the store, but since the mutable references to the entries
    /// are stored (for potential use by `renew`), it must take a mutable Store.
    pub fn expiring(cfg: &Config, store: &'a mut Store, ignore_inactive: bool) -> Self {
        let expire_date = cfg.today() + *WILDCARD_AUDIT_EXPIRATION_DURATION;

        let mut crates: SortedMap<PackageStr<'a>, Vec<(&'a mut WildcardEntry, bool)>> =
            Default::default();
        for (name, audits) in store.audits.wildcard_audits.iter_mut() {
            // Get the most recent publication time for this crate on crates.io,
            // which will be used to avoid expiry warnings for inactive crates.
            let last_publish_date = store
                .live_imports
                .as_ref()
                .and_then(|imports| imports.publisher.get(name))
                .map(|publishers| &publishers[..])
                .unwrap_or(&[])
                .iter()
                .map(|p| p.when)
                .max()
                .unwrap_or(cfg.today());

            // Check whether there are any audits expiring by the expiration date. Of those
            // audits, check whether all of them are already expired (to change the warning
            // message to be more informative).
            for entry in audits.iter_mut().filter(|e| e.should_renew(expire_date)) {
                let expired = entry.should_renew(cfg.today());

                // If the crate has not been published since the wildcard audit
                // expired, and the last published version by that user is over
                // 4 months ago, we silence the expiring/expired renewal
                // warning.
                if ignore_inactive
                    && last_publish_date < *entry.end
                    && last_publish_date < cfg.today() - *WILDCARD_AUDIT_INACTIVE_CRATE_DURATION
                {
                    continue;
                }

                crates.entry(name).or_default().push((entry, expired));
            }
        }

        WildcardAuditRenewal { crates }
    }

    /// Create a renewal with a single crate explicitly provided.
    ///
    /// This will renew all eligible audits, regardless of expiration. Thus `expired_crates` and
    /// `expiring_crates` should not be used.
    pub fn single_crate(name: PackageStr<'a>, store: &'a mut Store) -> Option<Self> {
        let mut crates: SortedMap<PackageStr<'a>, Vec<(&'a mut WildcardEntry, bool)>> =
            Default::default();
        let audits = store.audits.wildcard_audits.get_mut(name)?;
        for entry in audits {
            if entry.renew.unwrap_or(true) {
                // We don't care about the expiring/expired, so insert with false.
                crates.entry(name).or_default().push((entry, false));
            }
        }
        Some(WildcardAuditRenewal { crates })
    }

    /// Whether there are no wildcard audits expiring or expired.
    pub fn is_empty(&self) -> bool {
        self.crates.is_empty()
    }

    /// Get the crate names for which wildcard audits have expired.
    pub fn expired_crates(&'a self) -> Vec<PackageStr<'a>> {
        self.crates
            .iter()
            .filter_map(|(name, ids)| ids.iter().any(|(_, expired)| *expired).then_some(*name))
            .collect()
    }

    /// Get the crate names for which wildcard audits will expire soon.
    pub fn expiring_crates(&'a self) -> Vec<PackageStr<'a>> {
        self.crates
            .iter()
            .filter_map(|(name, ids)| ids.iter().any(|(_, expired)| !*expired).then_some(*name))
            .collect()
    }

    /// Renew all stored entries.
    pub fn renew(&mut self, new_end_date: chrono::NaiveDate) {
        for entry in self
            .crates
            .values_mut()
            .flat_map(|v| v.iter_mut().map(|t| &mut t.0))
        {
            entry.end = new_end_date.into();
        }
    }
}

fn cmd_prune(
    _out: &Arc<dyn Out>,
    cfg: &Config,
    sub_args: &PruneArgs,
) -> Result<(), miette::Report> {
    let network = Network::acquire(cfg);
    let mut store = Store::acquire(cfg, network.as_ref(), false)?;

    let _spinner = indeterminate_spinner("Pruning", "unnecessary imports and exemptions");

    // Update the store with the live state, pruning unnecessary exemptions and
    // imports.
    resolver::update_store(cfg, &mut store, |_| resolver::UpdateMode {
        search_mode: if sub_args.no_exemptions {
            resolver::SearchMode::PreferExemptions
        } else {
            resolver::SearchMode::PreferFreshImports
        },
        prune_exemptions: !sub_args.no_exemptions,
        prune_non_importable_audits: !sub_args.no_audits,
        prune_imports: !sub_args.no_imports,
    });

    store.commit()?;

    Ok(())
}

fn cmd_aggregate(
    out: &Arc<dyn Out>,
    cfg: &PartialConfig,
    sub_args: &AggregateArgs,
) -> Result<(), miette::Report> {
    let network =
        Network::acquire(cfg).ok_or_else(|| miette!("cannot aggregate imports when --frozen"))?;

    let mut urls = Vec::new();
    {
        let sources_file = BufReader::new(
            File::open(&sub_args.sources)
                .into_diagnostic()
                .wrap_err("failed to open sources file")?,
        );
        for line_result in sources_file.lines() {
            let line = line_result
                .into_diagnostic()
                .wrap_err("failed to read sources file")?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                // Ignore comment and empty lines.
                continue;
            }
            urls.push(
                Url::parse(trimmed)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to parse url: {trimmed:?}"))?,
            );
        }
    }

    let progress_bar = progress_bar("Fetching", "source audits", urls.len() as u64);
    let sources = tokio::runtime::Handle::current()
        .block_on(try_join_all(urls.into_iter().map(|url| async {
            let _guard = IncProgressOnDrop(&progress_bar, 1);
            let url_string = url.to_string();
            let audit_bytes = network.download(url).await?;
            let audit_string = String::from_utf8(audit_bytes).map_err(LoadTomlError::from)?;
            let audit_source = SourceFile::new(&url_string, audit_string);

            // We use foreign audit file parsing when loading sources to
            // aggregate, so that we catch and emit warnings when aggregation
            // fails, and don't generate invalid aggregated audit files.
            let audit_file =
                storage::foreign_audit_source_to_local_warn(&url_string, audit_source)?;
            Ok::<_, FetchAuditError>((url_string, audit_file))
        })))
        .into_diagnostic()?;

    let merged_audits = do_aggregate_audits(sources).into_diagnostic()?;
    let document = serialization::to_formatted_toml(merged_audits, None).into_diagnostic()?;
    write!(out, "{document}");
    Ok(())
}

fn do_aggregate_audits(sources: Vec<(String, AuditsFile)>) -> Result<AuditsFile, AggregateErrors> {
    let mut errors = Vec::new();
    let mut aggregate = AuditsFile {
        criteria: SortedMap::new(),
        wildcard_audits: SortedMap::new(),
        audits: SortedMap::new(),
        // FIXME: How should we handle aggregating trusted entries? Should we do
        // any form of de-duplication?
        trusted: SortedMap::new(),
    };

    for (source, audit_file) in sources {
        // Add each criteria from the original source, managing duplicates by
        // ensuring that their descriptions map 1:1.
        for (criteria_name, mut criteria_entry) in audit_file.criteria {
            match aggregate.criteria.entry(criteria_name) {
                std::collections::btree_map::Entry::Vacant(vacant) => {
                    criteria_entry.aggregated_from.push(source.clone().into());
                    vacant.insert(criteria_entry);
                }
                std::collections::btree_map::Entry::Occupied(occupied) => {
                    let prev_source = occupied
                        .get()
                        .aggregated_from
                        .last()
                        .map(|s| s.to_string())
                        .unwrap_or_default();
                    // NOTE: We don't record the new `aggregated_from` chain in
                    // this case, as we already have a chain for the existing
                    // entry which we don't want to clobber. This means that
                    // source order in the `sources.list` file can impact where
                    // your criteria are credited to originate from.
                    if occupied.get().description != criteria_entry.description
                        || occupied.get().description_url != criteria_entry.description_url
                    {
                        errors.push(AggregateError::CriteriaDescriptionMismatch(
                            AggregateCriteriaDescriptionMismatchError {
                                criteria_name: occupied.key().to_owned(),
                                first: AggregateCriteriaDescription {
                                    source: prev_source.clone(),
                                    description: occupied.get().description.clone(),
                                    description_url: occupied.get().description_url.clone(),
                                },
                                second: AggregateCriteriaDescription {
                                    source: source.clone(),
                                    description: criteria_entry.description.clone(),
                                    description_url: criteria_entry.description_url.clone(),
                                },
                            },
                        ))
                    }
                    if occupied.get().implies != criteria_entry.implies {
                        errors.push(AggregateError::ImpliesMismatch(
                            AggregateImpliesMismatchError {
                                criteria_name: occupied.key().to_owned(),
                                first: AggregateCriteriaImplies {
                                    source: prev_source.clone(),
                                    implies: occupied
                                        .get()
                                        .implies
                                        .iter()
                                        .map(|c| c.to_string())
                                        .collect(),
                                },
                                second: AggregateCriteriaImplies {
                                    source: source.clone(),
                                    implies: criteria_entry
                                        .implies
                                        .iter()
                                        .map(|c| c.to_string())
                                        .collect(),
                                },
                            },
                        ));
                    }
                }
            }
        }
        for (package_name, entries) in audit_file.audits {
            aggregate.audits.entry(package_name).or_default().extend(
                entries
                    .into_iter()
                    .filter(|audit_entry| audit_entry.importable)
                    .map(|mut audit_entry| {
                        audit_entry.aggregated_from.push(source.clone().into());
                        audit_entry
                    }),
            );
        }
        for (package_name, entries) in audit_file.wildcard_audits {
            aggregate
                .wildcard_audits
                .entry(package_name)
                .or_default()
                .extend(entries.into_iter().map(|mut wildcard_entry| {
                    wildcard_entry.aggregated_from.push(source.clone().into());
                    wildcard_entry
                }));
        }
        for (package_name, entries) in audit_file.trusted {
            aggregate
                .trusted
                .entry(package_name)
                .or_default()
                .extend(entries.into_iter().map(|mut trusted_entry| {
                    trusted_entry.aggregated_from.push(source.clone().into());
                    trusted_entry
                }));
        }
    }

    aggregate.tidy();

    if errors.is_empty() {
        Ok(aggregate)
    } else {
        Err(AggregateErrors { errors })
    }
}

fn cmd_dump_graph(
    out: &Arc<dyn Out>,
    cfg: &Config,
    sub_args: &DumpGraphArgs,
) -> Result<(), miette::Report> {
    // Dump a mermaid-js graph
    trace!("dumping...");

    let graph = resolver::DepGraph::new(&cfg.metadata, cfg.cli.filter_graph.as_ref(), None);
    match cfg.cli.output_format {
        OutputFormat::Human => graph.print_mermaid(out, sub_args).into_diagnostic()?,
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&**out, &graph.nodes).into_diagnostic()?
        }
    }

    Ok(())
}

fn cmd_fmt(_out: &Arc<dyn Out>, cfg: &Config, _sub_args: &FmtArgs) -> Result<(), miette::Report> {
    // Reformat all the files (just load and store them, formatting is implicit).
    trace!("formatting...");
    // We don't need to fetch foreign audits to format files
    let store = Store::acquire_offline(cfg)?;
    store.commit()?;
    Ok(())
}

/// Perform crimes on clap long_help to generate markdown docs
fn cmd_help_md(
    out: &Arc<dyn Out>,
    _cfg: &PartialConfig,
    _sub_args: &HelpMarkdownArgs,
) -> Result<(), miette::Report> {
    let app_name = "cargo-vet";
    let pretty_app_name = "cargo vet";
    // Make a new App to get the help message this time.

    writeln!(out, "# {pretty_app_name} CLI manual");
    writeln!(out);
    writeln!(
        out,
        "> This manual can be regenerated with `{pretty_app_name} help-markdown`"
    );
    writeln!(out);

    let mut fake_cli = FakeCli::command().term_width(0);
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

        if is_full_command {
            writeln!(out, "Version: `{version_line}`");
            writeln!(out);
        } else {
            // Give subcommands some breathing room
            writeln!(out, "<br><br><br>");
            writeln!(out, "## {pretty_app_name} {subcommand_name}");
        }

        let mut in_subcommands_listing = false;
        let mut in_usage = false;
        let mut in_global_options = false;
        for line in lines {
            // Use a trailing colon to indicate a heading
            if let Some(heading) = line.strip_suffix(':') {
                if !line.starts_with(' ') {
                    // SCREAMING headers are Main headings
                    if heading.to_ascii_uppercase() == heading {
                        in_subcommands_listing = heading == "SUBCOMMANDS";
                        in_usage = heading == "USAGE";
                        in_global_options = heading == "GLOBAL OPTIONS";

                        writeln!(out, "### {heading}");

                        if in_global_options && !is_full_command {
                            writeln!(
                                out,
                                "This subcommand accepts all the [global options](#global-options)"
                            );
                        }
                    } else {
                        writeln!(out, "### {heading}");
                    }
                    continue;
                }
            }

            if in_global_options && !is_full_command {
                // Skip global options for non-primary commands
                continue;
            }

            if in_subcommands_listing && !line.starts_with("     ") {
                // subcommand names are list items
                let own_subcommand_name = line.trim();
                write!(
                    out,
                    "* [{own_subcommand_name}](#{app_name}-{own_subcommand_name}): "
                );
                continue;
            }
            // The rest is indented, get rid of that
            let line = line.trim();

            // Usage strings get wrapped in full code blocks
            if in_usage && line.starts_with(pretty_app_name) {
                writeln!(out, "```");
                writeln!(out, "{line}");
                writeln!(out, "```");
                continue;
            }

            // argument names are subheadings
            if line.starts_with('-') || line.starts_with('<') {
                writeln!(out, "#### `{line}`");
                continue;
            }

            // escape default/value strings
            if line.starts_with('[') {
                writeln!(out, "\\{line}  ");
                continue;
            }

            // Normal paragraph text
            writeln!(out, "{line}");
        }
        writeln!(out);

        // The todo list is a stack, and processed in reverse-order, append
        // these commands to the end in reverse-order so the first command is
        // processed first (i.e. at the end of the list).
        todo.extend(
            command
                .get_subcommands_mut()
                .filter(|cmd| !cmd.is_hide_set())
                .collect::<Vec<_>>()
                .into_iter()
                .rev(),
        );
        is_full_command = false;
    }

    Ok(())
}

fn cmd_gc(
    out: &Arc<dyn Out>,
    cfg: &PartialConfig,
    sub_args: &GcArgs,
) -> Result<(), miette::Report> {
    let cache = Cache::acquire(cfg)?;

    if sub_args.clean {
        writeln!(
            out,
            "cleaning entire contents of cache directory: {}",
            cfg.cache_dir.display()
        );
        cache.clean_sync().into_diagnostic()?;
        return Ok(());
    }

    if sub_args.max_package_age_days.is_nan() {
        return Err(miette!("max package age cannot be NaN"));
    }
    if sub_args.max_package_age_days < 0.0 {
        return Err(miette!("max package age cannot be negative"));
    }

    cache.gc_sync(DURATION_DAY.mul_f64(sub_args.max_package_age_days));
    Ok(())
}

// Utils

struct UserInfo {
    username: String,
    email: String,
}

fn get_user_info() -> Result<UserInfo, UserInfoError> {
    fn get_git_config(value_name: &str) -> Result<String, CommandError> {
        let out = std::process::Command::new("git")
            .arg("config")
            .arg("--get")
            .arg(value_name)
            .output()
            .map_err(CommandError::CommandFailed)?;

        if !out.status.success() {
            return Err(CommandError::BadStatus(out.status.code().unwrap()));
        }
        String::from_utf8(out.stdout)
            .map(|s| s.trim().to_string())
            .map_err(CommandError::BadOutput)
    }

    let username = get_git_config("user.name").map_err(UserInfoError::UserCommandFailed)?;
    let email = get_git_config("user.email").map_err(UserInfoError::EmailCommandFailed)?;

    Ok(UserInfo { username, email })
}

async fn eula_for_criteria(
    network: Option<&Network>,
    criteria_map: &SortedMap<CriteriaName, CriteriaEntry>,
    criteria: CriteriaStr<'_>,
) -> String {
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

    // First try the builtins
    let builtin = builtin_eulas.get(criteria).map(|s| s.to_string());
    if let Some(eula) = builtin {
        return eula;
    }

    // ERRORS: the caller should have verified this entry already!
    let criteria_entry = criteria_map
        .get(criteria)
        .unwrap_or_else(|| panic!("no entry for the criteria {criteria}"));
    assert!(
        criteria_entry.description.is_some() || criteria_entry.description_url.is_some(),
        "entry for criteria {criteria} is corrupt!"
    );

    // Now try the description
    if let Some(eula) = criteria_entry.description.clone() {
        return eula;
    }

    // If we get here then there must be a URL, try to fetch it. If it fails, just print the URL
    let url = Url::parse(criteria_entry.description_url.as_ref().unwrap()).unwrap();
    if let Some(network) = network {
        if let Ok(eula) = network.download(url.clone()).await.and_then(|bytes| {
            String::from_utf8(bytes).map_err(|error| DownloadError::InvalidText {
                url: Box::new(url.clone()),
                error,
            })
        }) {
            return eula;
        }
    }

    // If we get here then the download failed, just print the URL
    format!("Could not download criteria description, it should be available at {url}")
}

/// All third-party packages, with the audit-as-crates-io policy applied
fn foreign_packages<'a>(
    metadata: &'a Metadata,
    config: &'a ConfigFile,
) -> impl Iterator<Item = &'a Package> + 'a {
    // Only analyze things from crates.io (no source = path-dep / workspace-member)
    metadata
        .packages
        .iter()
        .filter(|package| package.is_third_party(&config.policy))
}

/// All first-party packages, **without** the audit-as-crates-io policy applied
/// (because it's used for validating that field's value).
fn first_party_packages_strict<'a>(
    metadata: &'a Metadata,
    _config: &'a ConfigFile,
) -> impl Iterator<Item = &'a Package> + 'a {
    metadata
        .packages
        .iter()
        .filter(move |package| !package.is_crates_io())
}

/// All third-party packages, **without** the audit-as-crates-io policy applied (used in crate
/// policy verification).
fn foreign_packages_strict<'a>(
    metadata: &'a Metadata,
    _config: &ConfigFile,
) -> impl Iterator<Item = &'a Package> + 'a {
    metadata
        .packages
        .iter()
        .filter(move |package| package.is_crates_io())
}

async fn check_audit_as_crates_io(
    cfg: &Config,
    store: &Store,
    network: Option<&Network>,
    cache: &mut Cache,
) -> Result<(), AuditAsErrors> {
    let first_party_packages: Vec<_> =
        first_party_packages_strict(&cfg.metadata, &store.config).collect();

    let mut errors = vec![];

    {
        let mut unused_audit_as: SortedSet<(PackageName, Option<VetVersion>)> = store
            .config
            .policy
            .iter()
            .filter(|(_, _, policy)| policy.audit_as_crates_io.is_some())
            .map(|(name, version, _)| (name.clone(), version.cloned()))
            .collect();

        for package in &first_party_packages {
            // Remove both versioned and unversioned entries
            unused_audit_as.remove(&(package.name.clone(), Some(package.vet_version())));
            unused_audit_as.remove(&(package.name.clone(), None));
        }
        if !unused_audit_as.is_empty() {
            errors.push(AuditAsError::UnusedAuditAs(UnusedAuditAsErrors {
                errors: unused_audit_as
                    .into_iter()
                    .map(|(package, version)| PackageError { package, version })
                    .collect(),
            }))
        }
    }

    // We should only check the audit-as-crates-io entries if we have a network, because we
    // shouldn't make recommendations based on potentially stale information.
    if network.is_some() {
        let progress = progress_bar(
            "Validating",
            "audit-as-crates-io specifications",
            first_party_packages.len() as u64,
        );

        enum CheckAction {
            NeedAuditAs,
            ShouldntBeAuditAs,
        }

        let actions: Vec<_> = join_all(first_party_packages.into_iter().map(|package| {
            let progress = &progress;
            let cache = &cache;
            async move {
                let _inc_progress = IncProgressOnDrop(progress, 1);

                let audit_policy = package
                    .policy_entry(&store.config.policy)
                    .and_then(|policy| policy.audit_as_crates_io);
                if audit_policy == Some(false) {
                    // They've explicitly said this is first-party so we don't care about what's in the
                    // registry.
                    return None;
                }

                let matches_crates_io_package = cache
                    .crates_io_info(network, &package.name)
                    .await
                    .is_ok_and(|entry| entry.metadata.consider_as_same(package));

                if matches_crates_io_package && audit_policy.is_none() {
                    // We found a package that has similar metadata to one with the same name
                    // on crates.io: having no policy is an error.
                    return Some((CheckAction::NeedAuditAs, package));
                }
                if !matches_crates_io_package && audit_policy == Some(true) {
                    return Some((CheckAction::ShouldntBeAuditAs, package));
                }
                None
            }
        }))
        .await
        .into_iter()
        .flatten()
        .collect();

        let mut needs_audit_as_entry = vec![];
        let mut shouldnt_be_audit_as = vec![];

        for (action, package) in actions {
            match action {
                CheckAction::NeedAuditAs => {
                    needs_audit_as_entry.push(PackageError {
                        package: package.name.clone(),
                        version: Some(package.vet_version()),
                    });
                }
                CheckAction::ShouldntBeAuditAs => {
                    shouldnt_be_audit_as.push(PackageError {
                        package: package.name.clone(),
                        version: Some(package.vet_version()),
                    });
                }
            }
        }

        if !needs_audit_as_entry.is_empty() {
            errors.push(AuditAsError::NeedsAuditAs(NeedsAuditAsErrors {
                errors: needs_audit_as_entry,
            }));
        }
        if !shouldnt_be_audit_as.is_empty() {
            errors.push(AuditAsError::ShouldntBeAuditAs(ShouldntBeAuditAsErrors {
                errors: shouldnt_be_audit_as,
            }));
        }
    }

    if !errors.is_empty() {
        Err(AuditAsErrors { errors })
    } else {
        Ok(())
    }
}

/// Check crate policies for correctness.
///
/// This verifies two rules:
/// 1. Policies using `dependency-criteria` which relate to third-party crates must have associated
///    version(s). If a crate has any `dependency-criteria` specified and exists as a third-party
///    dependency anywhere in the dependency graph, all versions must be specified.
/// 2. Any versioned policies must correspond to a crate in the graph.
fn check_crate_policies(cfg: &Config, store: &Store) -> Result<(), CratePolicyErrors> {
    // All defined policy package names (to be removed).
    let mut policy_crates: SortedSet<&PackageName> = store.config.policy.package.keys().collect();

    // All defined policy (name, version) pairs (to be visited and removed).
    let mut versioned_policy_crates: SortedSet<(PackageName, VetVersion)> = store
        .config
        .policy
        .iter()
        .filter_map(|(name, version, _)| version.map(|version| (name.clone(), version.clone())))
        .collect();

    // The set of all third-party packages (for lookup of whether a crate has any third-party
    // versions in use).
    let third_party_packages = foreign_packages_strict(&cfg.metadata, &store.config)
        .map(|p| &p.name)
        .collect::<SortedSet<_>>();

    // The set of all packages which have a `dependency-criteria` specified in a policy.
    let dependency_criteria_packages = store
        .config
        .policy
        .iter()
        .filter_map(|(name, _, entry)| (!entry.dependency_criteria.is_empty()).then_some(name))
        .collect::<SortedSet<_>>();

    let mut needs_policy_version_errors = Vec::new();

    for package in &cfg.metadata.packages {
        policy_crates.remove(&package.name);

        let versioned_policy_exists =
            versioned_policy_crates.remove(&(package.name.clone(), package.vet_version()));

        // If a crate has at least one third-party package and some crate policy specifies a
        // `dependency-criteria`, a versioned policy for all used versions must exist.
        if third_party_packages.contains(&package.name)
            && dependency_criteria_packages.contains(&package.name)
            && !versioned_policy_exists
        {
            needs_policy_version_errors.push(PackageError {
                package: package.name.clone(),
                version: Some(package.vet_version()),
            });
        }
    }

    let unused_policy_version_errors: Vec<_> = policy_crates
        .into_iter()
        .map(|name| PackageError {
            package: name.clone(),
            version: None,
        })
        .chain(
            versioned_policy_crates
                .into_iter()
                .map(|(package, version)| PackageError {
                    package,
                    version: Some(version),
                }),
        )
        .collect();

    if !needs_policy_version_errors.is_empty() || !unused_policy_version_errors.is_empty() {
        let mut errors = Vec::new();
        if !needs_policy_version_errors.is_empty() {
            errors.push(CratePolicyError::NeedsVersion(NeedsPolicyVersionErrors {
                errors: needs_policy_version_errors,
            }));
        }
        if !unused_policy_version_errors.is_empty() {
            errors.push(CratePolicyError::UnusedVersion(UnusedPolicyVersionErrors {
                errors: unused_policy_version_errors,
            }));
        }
        Err(CratePolicyErrors { errors })
    } else {
        Ok(())
    }
}
