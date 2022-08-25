use std::collections::HashMap;
use std::ops::Deref;
use std::panic::panic_any;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{fs::File, io, panic, path::PathBuf};

use cargo_metadata::{Metadata, Package, Version};
use clap::{CommandFactory, Parser};
use console::Term;
use errors::{
    AuditAsError, AuditAsErrors, CacheAcquireError, CertifyError, NeedsAuditAsError,
    NeedsAuditAsErrors, ShouldntBeAuditAsError, ShouldntBeAuditAsErrors, UserInfoError,
};
use format::{CriteriaName, CriteriaStr, PackageName, PolicyEntry};
use futures_util::future::join_all;
use lazy_static::lazy_static;
use miette::{miette, Context, Diagnostic, IntoDiagnostic};
use network::Network;
use reqwest::Url;
use serde::de::Deserialize;
use thiserror::Error;
use tracing::{error, info, trace, warn};

use crate::cli::*;
use crate::errors::{CommandError, DownloadError, RegenerateExemptionsError};
use crate::format::{
    AuditEntry, AuditKind, AuditsFile, ConfigFile, CriteriaEntry, Delta, DependencyCriteria,
    ExemptedDependency, FetchCommand, ImportsFile, MetaConfig, MetaConfigInstance, PackageStr,
    SortedMap, StoreInfo,
};
use crate::out::Out;
use crate::resolver::{CriteriaMapper, CriteriaNamespace, DepGraph, ResolveDepth};
use crate::storage::{Cache, Store};

mod cli;
mod editor;
pub mod errors;
mod flock;
pub mod format;
pub mod network;
mod out;
pub mod resolver;
mod serialization;
pub mod storage;
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
    /// Path to the cache directory we're using
    pub cache_dir: PathBuf,
    /// Whether we should mock the global cache (for unit testing)
    pub mock_cache: bool,
}

// Makes it a bit easier to have both a "partial" and "full" config
impl Deref for Config {
    type Target = PartialConfig;
    fn deref(&self) -> &Self::Target {
        &self._rest
    }
}

pub trait PackageExt {
    fn is_third_party(&self, policy: &SortedMap<PackageName, PolicyEntry>) -> bool;
}

impl PackageExt for Package {
    fn is_third_party(&self, policy: &SortedMap<PackageName, PolicyEntry>) -> bool {
        let forced_third_party = policy
            .get(&self.name)
            .and_then(|policy| policy.audit_as_crates_io)
            .unwrap_or(false);
        let is_crates_io = self
            .source
            .as_ref()
            .map(|s| s.is_crates_io())
            .unwrap_or(false);

        forced_third_party || is_crates_io
    }
}

const CACHE_DIR_SUFFIX: &str = "cargo-vet";
const CARGO_ENV: &str = "CARGO";
// package.metadata.vet
const PACKAGE_VET_CONFIG: &str = "vet";
// workspace.metadata.vet
const WORKSPACE_VET_CONFIG: &str = "vet";

const DURATION_DAY: Duration = Duration::from_secs(60 * 60 * 24);

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
        writeln!(out, r#"{{"error": {}}}"#, report);
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
            .with_writer(std::io::stderr)
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

    // TODO: make this configurable
    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join(CACHE_DIR_SUFFIX);
    let partial_cfg = PartialConfig {
        cli,
        cache_dir,
        mock_cache: false,
    };

    match &partial_cfg.cli.command {
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
    cmd.other_options(other_options);

    info!("Running: {:#?}", cmd.cargo_command());

    // ERRORS: immediate fatal diagnostic
    let metadata = cmd
        .exec()
        .into_diagnostic()
        .wrap_err("'cargo metadata' exited unsuccessfully")?;

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
        Some(AddExemption(sub_args)) => cmd_add_exemption(&out, &cfg, sub_args),
        Some(RecordViolation(sub_args)) => cmd_record_violation(&out, &cfg, sub_args),
        Some(Suggest(sub_args)) => cmd_suggest(&out, &cfg, sub_args),
        Some(Fmt(sub_args)) => cmd_fmt(&out, &cfg, sub_args),
        Some(FetchImports(sub_args)) => cmd_fetch_imports(&out, &cfg, sub_args),
        Some(DumpGraph(sub_args)) => cmd_dump_graph(&out, &cfg, sub_args),
        Some(Inspect(sub_args)) => cmd_inspect(&out, &cfg, sub_args),
        Some(Diff(sub_args)) => cmd_diff(&out, &cfg, sub_args),
        Some(Regenerate(Imports(sub_args))) => cmd_regenerate_imports(&out, &cfg, sub_args),
        Some(Regenerate(Exemptions(sub_args))) => cmd_regenerate_exemptions(&out, &cfg, sub_args),
        Some(Regenerate(AuditAsCratesIo(sub_args))) => {
            cmd_regenerate_audit_as(&out, &cfg, sub_args)
        }
        Some(HelpMarkdown(_)) | Some(Gc(_)) => unreachable!("handled earlier"),
    }
}

fn cmd_init(_out: &Arc<dyn Out>, cfg: &Config, _sub_args: &InitArgs) -> Result<(), miette::Report> {
    // Initialize vet
    trace!("initializing...");

    let mut store = Store::create(cfg)?;

    let (config, audits, imports) = init_files(&cfg.metadata, cfg.cli.filter_graph.as_ref());
    store.config = config;
    store.audits = audits;
    store.imports = imports;

    fix_audit_as(cfg, &mut store)?;

    store.commit()?;

    Ok(())
}

pub fn init_files(
    metadata: &Metadata,
    filter_graph: Option<&Vec<GraphFilter>>,
) -> (ConfigFile, AuditsFile, ImportsFile) {
    // Default audits file is empty
    let audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: SortedMap::new(),
    };

    // Default imports file is empty
    let imports = ImportsFile {
        audits: SortedMap::new(),
    };

    // This is the hard one
    let config = {
        let mut dependencies = SortedMap::new();
        let graph = DepGraph::new(metadata, filter_graph, None);
        for package in &graph.nodes {
            if !package.is_third_party {
                // Only care about third-party packages
                continue;
            }
            let criteria = if package.is_dev_only {
                vec![format::DEFAULT_POLICY_DEV_CRITERIA.to_string().into()]
            } else {
                vec![format::DEFAULT_POLICY_CRITERIA.to_string().into()]
            };
            // NOTE: May have multiple copies of a package!
            let item = ExemptedDependency {
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
            exemptions: dependencies,
            policy: SortedMap::new(),
        }
    };

    (config, audits, imports)
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

        if sub_args.mode == FetchMode::Sourcegraph {
            let url = format!("https://sourcegraph.com/crates/{package}@v{version}");
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
                cache.fetch_package(network.as_ref(), package, version),
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
        writeln!(out, "Opening nested shell in: {:#?}", fetched);
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

    writeln!(out, "  fetched to {:#?}", fetched);
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

    // Minimize exemptions after adding the new `certify`. This will be used to
    // potentially update imports, and remove now-unnecessary exemptions.
    // Explicitly disallow new exemptions so that exemptions are only updated
    // once we start passing vet.
    match resolver::regenerate_exemptions(cfg, &mut store, false, false) {
        Ok(()) | Err(RegenerateExemptionsError::ViolationConflict) => {}
    }

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

    let dependency_criteria = if sub_args.dependency_criteria.is_empty() {
        // TODO: look at the current audits to infer this? prompt?
        DependencyCriteria::new()
    } else {
        let mut dep_criteria = DependencyCriteria::new();
        for arg in &sub_args.dependency_criteria {
            dep_criteria
                .entry(arg.dependency.clone())
                .or_insert_with(Vec::new)
                .push(arg.criteria.clone().into());
        }
        dep_criteria
    };

    let kind = if let Some(v1) = &sub_args.version1 {
        // If explicit versions were provided, use those
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
    } else if let Some(fetch) = last_fetch.filter(|f| f.package() == package) {
        // Otherwise, is we just fetched this package, use the version(s) we fetched
        match fetch {
            FetchCommand::Inspect { version, .. } => AuditKind::Full {
                version,
                dependency_criteria,
            },
            FetchCommand::Diff {
                version1, version2, ..
            } => AuditKind::Delta {
                delta: Delta {
                    from: version1,
                    to: version2,
                },
                dependency_criteria,
            },
        }
    } else {
        return Err(CertifyError::CouldntGuessVersion(package));
    };

    let (username, who) = if let Some(who) = &sub_args.who {
        (who.clone(), Some(who.clone()))
    } else {
        let user_info = get_user_info()?;
        let who = format!("{} <{}>", user_info.username, user_info.email);
        (user_info.username, Some(who))
    };

    let criteria_mapper = CriteriaMapper::new(
        &store.audits.criteria,
        store.imported_audits(),
        &store.config.imports,
    );

    let criteria_names = if sub_args.criteria.is_empty() {
        let (from, to) = match &kind {
            AuditKind::Full { version, .. } => (None, version),
            AuditKind::Delta { delta, .. } => (Some(&delta.from), &delta.to),
            _ => unreachable!(),
        };

        // If we don't have explicit cli criteria, guess the criteria
        //
        // * Check what would cause `cargo vet` to encounter fewer errors
        // * Otherwise check what would cause `cargo vet suggest` to suggest fewer audits
        // * Otherwise guess nothing
        //
        // Regardless of the guess, prompt the user to confirm (just needs to mash enter)
        let mut chosen_criteria = guess_audit_criteria(cfg, store, &package, from, to);

        // Prompt for criteria
        loop {
            out.clear_screen()?;
            write!(out, "choose criteria to certify for {}", package);
            match &kind {
                AuditKind::Full { version, .. } => write!(out, ":{}", version),
                AuditKind::Delta { delta, .. } => write!(out, ":{} -> {}", delta.from, delta.to),
                AuditKind::Violation { .. } => unreachable!(),
            }
            writeln!(out);
            writeln!(out, "  0. <clear selections>");
            let implied_criteria = criteria_mapper.criteria_from_list(&chosen_criteria);
            // Iterate over all the local criteria. Note that it's fine for us to do the enumerate
            // first, because local criteria are added to the list before foreign criteria, so they
            // should be contiguous from 0..N.
            let local_criteria = criteria_mapper
                .list
                .iter()
                .enumerate()
                .filter(|(_, info)| matches!(info.namespace, CriteriaNamespace::Local));
            for (criteria_idx, criteria_info) in local_criteria {
                if chosen_criteria.contains(&criteria_info.namespaced_name) {
                    writeln!(
                        out,
                        "  {}. {}",
                        criteria_idx + 1,
                        out.style().green().apply_to(&criteria_info.namespaced_name)
                    );
                } else if implied_criteria.has_criteria(criteria_idx) {
                    writeln!(
                        out,
                        "  {}. {}",
                        criteria_idx + 1,
                        out.style()
                            .yellow()
                            .apply_to(&criteria_info.namespaced_name)
                    );
                } else {
                    writeln!(
                        out,
                        "  {}. {}",
                        criteria_idx + 1,
                        &criteria_info.namespaced_name
                    );
                }
            }

            writeln!(out);
            writeln!(
                out,
                "current selection: {:?}",
                criteria_mapper
                    .criteria_names(&implied_criteria)
                    .collect::<Vec<_>>()
            );
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
            if answer == 0 {
                chosen_criteria.clear();
                continue;
            }
            if answer > criteria_mapper.list.len() {
                // ERRORS: immediate error print to output for feedback, non-fatal
                writeln!(out, "error: not a valid criteria");
                continue;
            }
            chosen_criteria.push(criteria_mapper.list[answer - 1].namespaced_name.clone());
        }
        chosen_criteria
    } else {
        sub_args.criteria.clone()
    };

    // Round-trip this through the criteria_mapper to clean up `implies` relationships
    let criteria_set = criteria_mapper.criteria_from_list(&criteria_names);
    let criteria_names = criteria_mapper
        .criteria_names(&criteria_set)
        .collect::<Vec<_>>();

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
        "I, {}, certify that I have audited {} of {} in accordance with the above criteria.",
        username, what_version, package,
    );

    let mut notes = sub_args.notes.clone();
    if !sub_args.accept_all {
        // Get all the EULAs at once
        let eulas = tokio::runtime::Handle::current().block_on(join_all(
            criteria_names.iter().map(|criteria| async {
                (
                    *criteria,
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
            editor.add_comments(&format!("=== BEGIN CRITERIA {:?} ===", criteria))?;
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

    let new_entry = AuditEntry {
        kind: kind.clone(),
        criteria: criteria_names
            .iter()
            .map(|s| s.to_string().into())
            .collect(),
        who,
        notes,
        is_fresh_import: false,
    };

    store
        .audits
        .audits
        .entry(package.clone())
        .or_insert(vec![])
        .push(new_entry);

    // If we're submitting a full audit, look for a matching exemption entry to remove
    if let AuditKind::Full { version, .. } = &kind {
        if let Some(exemption_list) = store.config.exemptions.get_mut(&package) {
            let cur_criteria_set = criteria_mapper.criteria_from_list(criteria_names);
            // Iterate backwards so that we can delete while iterating
            // (will only affect indices that we've already visited!)
            for idx in (0..exemption_list.len()).rev() {
                let entry = &exemption_list[idx];
                let entry_criteria_set = criteria_mapper.criteria_from_list(&entry.criteria);
                if &entry.version == version && cur_criteria_set.contains(&entry_criteria_set) {
                    exemption_list.remove(idx);
                }
            }
            if exemption_list.is_empty() {
                store.config.exemptions.remove(&package);
            }
        }
    }

    Ok(())
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
    from: Option<&Version>,
    to: &Version,
) -> Vec<String> {
    // Attempt to resolve a normal `cargo vet`, and try to find criteria which
    // would heal some errors in that result if it fails.
    let criteria = resolver::resolve(
        &cfg.metadata,
        cfg.cli.filter_graph.as_ref(),
        store,
        ResolveDepth::Deep,
    )
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
        &store.clone_for_suggest(),
        ResolveDepth::Deep,
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
    from: Option<&Version>,
    to: &Version,
    url: Option<&str>,
) -> Result<(), io::Error> {
    let description = if let Some(from) = from {
        format!(
            "You are about to diff versions {} and {} of '{}'",
            from, to, package
        )
    } else {
        format!("You are about to inspect version {} of '{}'", to, package)
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
                format!(
                    "{}, likely to certify it for {:?}, which means:",
                    description, criteria
                )
            } else {
                format!("... and for {:?}, which means:", criteria)
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

    let (_username, who) = if let Some(who) = &sub_args.who {
        (who.clone(), Some(who.clone()))
    } else {
        let user_info = get_user_info()?;
        let who = format!("{} <{}>", user_info.username, user_info.email);
        (user_info.username, Some(who))
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
        notes,
        is_fresh_import: false,
    };

    store
        .audits
        .audits
        .entry(sub_args.package.clone())
        .or_insert(vec![])
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

    let dependency_criteria = if sub_args.dependency_criteria.is_empty() {
        // TODO: look at the current audits to infer this? prompt?
        DependencyCriteria::new()
    } else {
        let mut dep_criteria = DependencyCriteria::new();
        for arg in &sub_args.dependency_criteria {
            dep_criteria
                .entry(arg.dependency.clone())
                .or_insert_with(Vec::new)
                .push(arg.criteria.clone().into());
        }
        dep_criteria
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
        dependency_criteria,
        suggest,
    };

    store
        .config
        .exemptions
        .entry(sub_args.package.clone())
        .or_insert(vec![])
        .push(new_entry);

    store.commit()?;

    Ok(())
}

fn cmd_suggest(
    out: &Arc<dyn Out>,
    cfg: &Config,
    sub_args: &SuggestArgs,
) -> Result<(), miette::Report> {
    // Run the checker to validate that the current set of deps is covered by the current cargo vet store
    trace!("suggesting...");
    let network = Network::acquire(cfg);
    let suggest_store = Store::acquire(cfg, network.as_ref(), false)?.clone_for_suggest();

    // DO THE THING!!!!
    let report = resolver::resolve(
        &cfg.metadata,
        cfg.cli.filter_graph.as_ref(),
        &suggest_store,
        if sub_args.shallow {
            ResolveDepth::Shallow
        } else {
            ResolveDepth::Deep
        },
    );
    let suggest = report.compute_suggest(cfg, network.as_ref(), true)?;
    match cfg.cli.output_format {
        OutputFormat::Human => report
            .print_suggest_human(out, cfg, suggest.as_ref())
            .into_diagnostic()?,
        OutputFormat::Json => report.print_json(out, cfg, suggest.as_ref())?,
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

    // NOTE: Explicitly ignore the `ViolationConflict` error, as we still want
    // to update imports in that case.
    match resolver::regenerate_exemptions(cfg, &mut store, false, true) {
        Ok(()) | Err(RegenerateExemptionsError::ViolationConflict) => {}
    }

    store.commit()?;
    Ok(())
}

fn cmd_regenerate_audit_as(
    _out: &Arc<dyn Out>,
    cfg: &Config,
    _sub_args: &RegenerateAuditAsCratesIoArgs,
) -> Result<(), miette::Report> {
    trace!("regenerating audit-as-crates-io...");
    let mut store = Store::acquire_offline(cfg)?;

    fix_audit_as(cfg, &mut store)?;

    // We were successful, commit the store
    store.commit()?;

    Ok(())
}

/// Adjust the store to satisfy audit-as-crates-io issues
///
/// Every reported issue will be resolved by just setting `audit-as-crates-io = Some(false)`,
/// because that always works, no matter what the problem is.
fn fix_audit_as(cfg: &Config, store: &mut Store) -> Result<(), CacheAcquireError> {
    // NOTE: In the future this might require Network, but for now `cargo metadata` is a precondition
    // and guarantees a fully populated and up to date index, so we can just rely on that and know
    // this is Networkless.
    let issues = check_audit_as_crates_io(cfg, store);
    if let Err(AuditAsErrors { errors }) = issues {
        for error in errors {
            match error {
                AuditAsError::NeedsAuditAs(needs) => {
                    for err in needs.errors {
                        store
                            .config
                            .policy
                            .entry(err.package)
                            .or_default()
                            .audit_as_crates_io = Some(false);
                    }
                }
                AuditAsError::ShouldntBeAuditAs(shouldnts) => {
                    for err in shouldnts.errors {
                        store
                            .config
                            .policy
                            .entry(err.package)
                            .or_default()
                            .audit_as_crates_io = Some(false);
                    }
                }
                AuditAsError::CacheAcquire(err) => return Err(err),
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

    resolver::regenerate_exemptions(cfg, &mut store, true, false)?;

    // We were successful, commit the store
    store.commit()?;

    Ok(())
}

fn cmd_diff(out: &Arc<dyn Out>, cfg: &Config, sub_args: &DiffArgs) -> Result<(), miette::Report> {
    let version1 = &sub_args.version1;
    let version2 = &sub_args.version2;
    let package = &*sub_args.package;

    let (fetched1, fetched2) = {
        let network = Network::acquire(cfg);
        let store = Store::acquire(cfg, network.as_ref(), false)?;
        let cache = Cache::acquire(cfg)?;

        // Record this command for magic in `vet certify`
        cache.set_last_fetch(FetchCommand::Diff {
            package: package.to_owned(),
            version1: version1.clone(),
            version2: version2.clone(),
        });

        if sub_args.mode == FetchMode::Sourcegraph {
            let url = format!(
                "https://sourcegraph.com/crates/{package}/-/compare/v{version1}...v{version2}"
            );
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
            let (pkgs, eulas) = tokio::join!(
                async {
                    tokio::try_join!(
                        cache.fetch_package(network.as_ref(), package, version1),
                        cache.fetch_package(network.as_ref(), package, version2)
                    )
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
            pkgs.into_diagnostic()
        })?
    };

    writeln!(out);

    // FIXME: mask out .cargo_vcs_info.json

    std::process::Command::new("git")
        .arg("diff")
        .arg("--no-index")
        .arg(&fetched1)
        .arg(&fetched2)
        .status()
        .map_err(CommandError::CommandFailed)
        .into_diagnostic()?;

    writeln!(out, "\nUse |cargo vet certify| to record your audit.");

    Ok(())
}

fn cmd_check(out: &Arc<dyn Out>, cfg: &Config, sub_args: &CheckArgs) -> Result<(), miette::Report> {
    // Run the checker to validate that the current set of deps is covered by the current cargo vet store
    trace!("vetting...");

    let network = Network::acquire(cfg);
    let mut store = Store::acquire(cfg, network.as_ref(), false)?;

    if !cfg.cli.locked {
        // Check if any of our first-parties are in the crates.io registry
        check_audit_as_crates_io(cfg, &store)?;
    }

    // DO THE THING!!!!
    let report = resolver::resolve(
        &cfg.metadata,
        cfg.cli.filter_graph.as_ref(),
        &store,
        if sub_args.shallow {
            ResolveDepth::Shallow
        } else {
            ResolveDepth::Deep
        },
    );

    // Bare `cargo vet` shouldn't suggest in CI
    let suggest = if !cfg.cli.locked {
        report.compute_suggest(cfg, network.as_ref(), true)?
    } else {
        None
    };

    match cfg.cli.output_format {
        OutputFormat::Human => report
            .print_human(out, cfg, suggest.as_ref())
            .into_diagnostic()?,
        OutputFormat::Json => report.print_json(out, cfg, suggest.as_ref())?,
    }

    // Only save imports if we succeeded, to avoid any modifications on error.
    if report.has_errors() {
        // ERRORS: immediate fatal diagnostic? Arguably should be silent.
        // Err(eyre!("report contains errors"))?;
        panic_any(ExitPanic(-1));
    } else {
        if !cfg.cli.locked {
            #[allow(clippy::single_match)]
            match resolver::regenerate_exemptions(cfg, &mut store, false, false) {
                Err(RegenerateExemptionsError::ViolationConflict) => {
                    unreachable!("unexpeced violation conflict regenerating exemptions?")
                }
                Ok(()) => {}
            }
        }
        store.commit()?;
    }

    Ok(())
}

fn cmd_fetch_imports(
    out: &Arc<dyn Out>,
    cfg: &Config,
    _sub_args: &FetchImportsArgs,
) -> Result<(), miette::Report> {
    trace!("fetching imports...");

    if cfg.cli.locked {
        // ERRORS: just a warning that you're holding it wrong, unclear if immediate or buffered,
        // or if this should be a hard error, or if we should ignore the --locked flag and
        // just do it anyway
        writeln!(
            out,
            "warning: ran fetch-imports with --locked, this won't do anything!"
        );

        return Ok(());
    }

    let network = Network::acquire(cfg);
    let mut store = Store::acquire(cfg, network.as_ref(), false)?;

    // NOTE: Explicitly ignore the `ViolationConflict` error, as we still want
    // to update imports in that case.
    match resolver::regenerate_exemptions(cfg, &mut store, false, true) {
        Ok(()) | Err(RegenerateExemptionsError::ViolationConflict) => {}
    }

    store.commit()?;

    Ok(())
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
        .unwrap_or_else(|| panic!("no entry for the criteria {}", criteria));
    assert!(
        criteria_entry.description.is_some() || criteria_entry.description_url.is_some(),
        "entry for criteria {} is corrupt!",
        criteria
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
                url: url.clone(),
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
    // Opposite of third-party, but with an empty `policy`
    let empty_policy = SortedMap::new();
    metadata
        .packages
        .iter()
        .filter(move |package| !package.is_third_party(&empty_policy))
}

fn check_audit_as_crates_io(cfg: &Config, store: &Store) -> Result<(), AuditAsErrors> {
    let cache = Cache::acquire(cfg).map_err(|e| AuditAsErrors {
        errors: vec![AuditAsError::CacheAcquire(e)],
    })?;
    let mut needs_audit_as_entry = vec![];
    let mut shouldnt_be_audit_as = vec![];

    'packages: for package in first_party_packages_strict(&cfg.metadata, &store.config) {
        let audit_policy = store
            .config
            .policy
            .get(&package.name)
            .and_then(|policy| policy.audit_as_crates_io);
        if audit_policy == Some(false) {
            // They've explicitly said this is first-party so we don't care about what's in the registry
            continue;
        }

        if let Some(index_entry) = cache.query_package_from_index(&package.name) {
            if storage::exact_version(&index_entry, &package.version).is_some() {
                // We found a version of this package in the registry!
                if audit_policy == None {
                    // At this point, having no policy is an error
                    needs_audit_as_entry.push(NeedsAuditAsError {
                        package: package.name.clone(),
                        version: package.version.clone(),
                    });
                }
                // Now that we've found a version match, we're done with this package
                continue 'packages;
            }
        }

        // If we reach this point, then we couldn't find a matching package in the registry,
        // So any `audit-as-crates-io = true` is an error that should be corrected
        if audit_policy == Some(true) {
            shouldnt_be_audit_as.push(ShouldntBeAuditAsError {
                package: package.name.clone(),
                version: package.version.clone(),
            });
        }
    }

    if !needs_audit_as_entry.is_empty() || !shouldnt_be_audit_as.is_empty() {
        let mut errors = vec![];
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
        return Err(AuditAsErrors { errors });
    }

    Ok(())
}
