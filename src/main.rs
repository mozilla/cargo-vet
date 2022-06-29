use std::collections::HashMap;
use std::ops::Deref;
use std::panic::panic_any;
use std::time::Duration;
use std::{fs::File, io, mem, panic, path::PathBuf};

use cargo_metadata::{Metadata, Package, Version};
use clap::{CommandFactory, Parser};
use console::Term;
use errors::{
    AuditAsError, AuditAsErrors, CacheAcquireError, CertifyError, MinimizeUnauditedError,
    NeedsAuditAsError, NeedsAuditAsErrors, ShouldntBeAuditAsError, ShouldntBeAuditAsErrors,
    UserInfoError,
};
use format::{CriteriaName, CriteriaStr, PackageName, PolicyEntry};
use futures_util::future::join_all;
use miette::{miette, Context, IntoDiagnostic};
use network::Network;
use reqwest::Url;
use serde::de::Deserialize;
use tracing::{error, info, trace, warn};

use crate::cli::*;
use crate::errors::{CommandError, DownloadError};
use crate::format::{
    AuditEntry, AuditKind, AuditsFile, ConfigFile, CriteriaEntry, Delta, DependencyCriteria,
    FetchCommand, ImportsFile, MetaConfig, MetaConfigInstance, PackageStr, SortedMap, StoreInfo,
    UnauditedDependency,
};
use crate::out::Out;
use crate::resolver::{Conclusion, CriteriaMapper, DepGraph, ResolveDepth, SuggestItem};
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

/// Similar to the above, but allows us to exec a new command
/// as our final act.
struct ExecPanic(std::process::Command);

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
        Err(mut e) => {
            if let Some(ExitPanic(code)) = e.downcast_ref::<ExitPanic>() {
                // Exit panic, just silently exit with this status
                std::process::exit(*code);
            } else if let Some(ExecPanic(_command)) = e.downcast_mut::<ExecPanic>() {
                // Exit with an exec.
                #[cfg(target_family = "unix")]
                {
                    use std::os::unix::process::CommandExt;
                    _command.exec();
                }
                unreachable!("we only use ExecPanic for unix");
            } else {
                // Normal panic, let it ride
                std::panic::resume_unwind(e);
            }
        }
    };
    main_result.map_err(|e| {
        let out: &mut dyn Out = &mut Term::stderr();
        writeln!(out, "{:?}", e).unwrap();
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
            .with_writer(std::io::stderr)
            .init();
    }

    // Set a panic hook to redirect to the logger
    panic::set_hook(Box::new(|panic_info| {
        if panic_info.payload().is::<ExitPanic>() || panic_info.payload().is::<ExecPanic>() {
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

    // FIXME: we should have separate configs for errors but this works for now
    let error_colors_enabled = cli.output_file.is_none() && console::colors_enabled_stderr();
    let output_json = cli.output_format == OutputFormat::Json;
    miette::set_hook(Box::new(move |_| {
        if output_json {
            let json_handler = miette::JSONReportHandler;
            Box::new(json_handler)
        } else {
            let graphical_theme = if error_colors_enabled {
                miette::GraphicalTheme::unicode()
            } else {
                miette::GraphicalTheme::unicode_nocolor()
            };
            Box::new(
                miette::MietteHandlerOpts::new()
                    .graphical_theme(graphical_theme)
                    .build(),
            )
        }
    }))
    .expect("Failed to initialize error handler");

    // Setup our output stream
    let mut stdout;
    let mut output_f;
    let out: &mut dyn Out = if let Some(output_path) = &cli.output_file {
        console::set_colors_enabled(false);
        output_f = File::create(output_path).unwrap();
        &mut output_f
    } else {
        stdout = Term::stdout();
        &mut stdout
    };

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
        Some(HelpMarkdown(sub_args)) => return cmd_help_md(out, &partial_cfg, sub_args),
        Some(Gc(sub_args)) => return cmd_gc(out, &partial_cfg, sub_args),
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
        None => cmd_check(out, &cfg, &cfg.cli.check_args),
        Some(Check(sub_args)) => cmd_check(out, &cfg, sub_args),
        Some(Init(sub_args)) => cmd_init(out, &cfg, sub_args),
        Some(Certify(sub_args)) => cmd_certify(out, &cfg, sub_args),
        Some(AddExemption(sub_args)) => cmd_add_unaudited(out, &cfg, sub_args),
        Some(RecordViolation(sub_args)) => cmd_record_violation(out, &cfg, sub_args),
        Some(Suggest(sub_args)) => cmd_suggest(out, &cfg, sub_args),
        Some(Fmt(sub_args)) => cmd_fmt(out, &cfg, sub_args),
        Some(FetchImports(sub_args)) => cmd_fetch_imports(out, &cfg, sub_args),
        Some(DumpGraph(sub_args)) => cmd_dump_graph(out, &cfg, sub_args),
        Some(Inspect(sub_args)) => cmd_inspect(out, &cfg, sub_args),
        Some(Diff(sub_args)) => cmd_diff(out, &cfg, sub_args),
        Some(HelpMarkdown(_)) | Some(Gc(_)) => unreachable!("handled earlier"),
        Some(Regenerate(Imports(sub_args))) => cmd_regenerate_imports(out, &cfg, sub_args),
        Some(Regenerate(Exemptions(sub_args))) => cmd_regenerate_exemptions(out, &cfg, sub_args),
        Some(Regenerate(AuditAsCratesIo(sub_args))) => cmd_regenerate_audit_as(out, &cfg, sub_args),
    }
}

fn cmd_init(_out: &mut dyn Out, cfg: &Config, _sub_args: &InitArgs) -> Result<(), miette::Report> {
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

    (config, audits, imports)
}

fn cmd_inspect(
    out: &mut dyn Out,
    cfg: &Config,
    sub_args: &InspectArgs,
) -> Result<(), miette::Report> {
    let store = Store::acquire(cfg)?;
    let cache = Cache::acquire(cfg)?;
    let network = Network::acquire(cfg);

    let version = &sub_args.version;
    let package = &*sub_args.package;

    // Record this command for magic in `vet certify`
    cache.set_last_fetch(FetchCommand::Inspect {
        package: package.to_owned(),
        version: version.clone(),
    });

    let fetched = tokio::runtime::Handle::current().block_on(async {
        let (pkg, eulas) = tokio::join!(
            cache.fetch_package(network.as_ref(), package, version),
            prompt_criteria_eulas(out, cfg, network.as_ref(), &store, package, None, version),
        );
        eulas.into_diagnostic()?;
        pkg.into_diagnostic()
    })?;

    #[cfg(target_family = "unix")]
    {
        // Loosely borrowed from cargo crev.
        let shell = std::env::var_os("SHELL").unwrap();
        writeln!(out, "Opening nested shell in: {:#?}", fetched).into_diagnostic()?;
        writeln!(out, "Use `exit` or Ctrl-D to finish.",).into_diagnostic()?;
        let mut command = std::process::Command::new(shell);
        command.current_dir(fetched.clone()).env("PWD", fetched);
        panic_any(ExecPanic(command));
    }

    #[cfg(not(target_family = "unix"))]
    {
        writeln!(out, "  fetched to {:#?}", fetched).into_diagnostic()?;
        Ok(())
    }
}

fn cmd_certify(
    out: &mut dyn Out,
    cfg: &Config,
    sub_args: &CertifyArgs,
) -> Result<(), miette::Report> {
    // Certify that you have reviewed a crate's source for some version / delta
    let mut store = Store::acquire(cfg)?;
    let network = Network::acquire(cfg);

    // Grab the last fetch and immediately drop the cache
    let last_fetch = Cache::acquire(cfg)?.get_last_fetch();

    do_cmd_certify(out, cfg, sub_args, &mut store, network.as_ref(), last_fetch)?;

    store.commit()?;
    Ok(())
}

fn do_cmd_certify(
    out: &mut dyn Out,
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
    if !foreign_packages(&cfg.metadata, &store.config).any(|pkg| pkg.name == *package) {
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

    let criteria_mapper = CriteriaMapper::new(&store.audits.criteria);

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
                        out.style().green().apply_to(criteria_name)
                    )?;
                } else if implied_criteria.has_criteria(criteria_idx) {
                    writeln!(
                        out,
                        "  {}. {}",
                        criteria_idx + 1,
                        out.style().yellow().apply_to(criteria_name)
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
                writeln!(out, "error: not a valid integer")?;
                continue;
            };
            if answer == 0 {
                chosen_criteria.clear();
                continue;
            }
            if answer > criteria_mapper.list.len() {
                // ERRORS: immediate error print to output for feedback, non-fatal
                writeln!(out, "error: not a valid criteria")?;
                continue;
            }
            chosen_criteria.push(criteria_mapper.list[answer - 1].0.clone());
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
            "Please read the following criteria and uncomment the statement below:",
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
        editor.add_comments("STATEMENT:")?;
        editor.add_text("")?;
        editor.add_comments(&statement)?;
        editor.add_text("")?;
        editor.add_comments("NOTES:")?;
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
    };

    store
        .audits
        .audits
        .entry(package.clone())
        .or_insert(vec![])
        .push(new_entry);

    // If we're submitting a full audit, look for a matching unaudited entry to remove
    if let AuditKind::Full { version, .. } = &kind {
        if let Some(unaudited_list) = store.config.unaudited.get_mut(&package) {
            let cur_criteria_set = criteria_mapper.criteria_from_list(criteria_names);
            // Iterate backwards so that we can delete while iterating
            // (will only affect indices that we've already visited!)
            for idx in (0..unaudited_list.len()).rev() {
                let entry = &unaudited_list[idx];
                let entry_criteria_set = criteria_mapper.criteria_from_list(&entry.criteria);
                if &entry.version == version && cur_criteria_set.contains(&entry_criteria_set) {
                    unaudited_list.remove(idx);
                }
            }
            if unaudited_list.is_empty() {
                store.config.unaudited.remove(&package);
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
async fn prompt_criteria_eulas(
    out: &mut dyn Out,
    cfg: &Config,
    network: Option<&Network>,
    store: &Store,
    package: PackageStr<'_>,
    from: Option<&Version>,
    to: &Version,
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
        writeln!(out, "{}", out.style().bold().apply_to(description))?;
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
            )?;
        }

        writeln!(
            out,
            "{}",
            out.style().bold().apply_to(
                "Please read the above criteria and consider them when performing the audit."
            )
        )?;
    }

    writeln!(
        out,
        "{}",
        out.style().bold().apply_to(
            "Other software projects may rely on this audit. Ask for help if you're not sure."
        )
    )?;
    out.read_line_with_prompt_async("(press ENTER to continue...)")
        .await?;
    Ok(())
}

fn cmd_record_violation(
    out: &mut dyn Out,
    cfg: &Config,
    sub_args: &RecordViolationArgs,
) -> Result<(), miette::Report> {
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
    if !foreign_packages(&cfg.metadata, &store.config).any(|pkg| pkg.name == sub_args.package) {
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
    };

    store
        .audits
        .audits
        .entry(sub_args.package.clone())
        .or_insert(vec![])
        .push(new_entry);

    store.commit()?;

    writeln!(out, "If you've identified a security vulnerability in {} please report it at https://github.com/rustsec/advisory-db#reporting-vulnerabilities", sub_args.package).unwrap();

    Ok(())
}

fn cmd_add_unaudited(
    _out: &mut dyn Out,
    cfg: &Config,
    sub_args: &AddExemptionArgs,
) -> Result<(), miette::Report> {
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
    if !foreign_packages(&cfg.metadata, &store.config).any(|pkg| pkg.name == sub_args.package) {
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

fn cmd_suggest(
    out: &mut dyn Out,
    cfg: &Config,
    sub_args: &SuggestArgs,
) -> Result<(), miette::Report> {
    // Run the checker to validate that the current set of deps is covered by the current cargo vet store
    trace!("suggesting...");
    let suggest_store = Store::acquire(cfg)?.clone_for_suggest();
    let network = Network::acquire(cfg);

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
    out: &mut dyn Out,
    cfg: &Config,
    _sub_args: &RegenerateImportsArgs,
) -> Result<(), miette::Report> {
    trace!("regenerating imports...");

    let mut store = Store::acquire(cfg)?;
    let network = Network::acquire(cfg);

    if let Some(network) = &network {
        if !cfg.cli.locked {
            // Literally the only difference between this command and fetch-imports
            // is that we pass `accept_changes = true`
            tokio::runtime::Handle::current()
                .block_on(store.fetch_foreign_audits(network, true))?;
            store.commit()?;
            return Ok(());
        }
    }

    // ERRORS: just a warning that you're holding it wrong, unclear if immediate or buffered,
    // or if this should be a hard error, or if we should ignore the --locked flag and
    // just do it anyway
    writeln!(
        out,
        "warning: ran `regenerate imports` with --locked, this won't do anything!"
    )
    .into_diagnostic()?;

    Ok(())
}

fn cmd_regenerate_audit_as(
    _out: &mut dyn Out,
    cfg: &Config,
    _sub_args: &RegenerateAuditAsCratesIoArgs,
) -> Result<(), miette::Report> {
    trace!("regenerating unaudited...");
    let mut store = Store::acquire(cfg)?;

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
    _out: &mut dyn Out,
    cfg: &Config,
    _sub_args: &RegenerateExemptionsArgs,
) -> Result<(), miette::Report> {
    trace!("regenerating exemptions...");
    let mut store = Store::acquire(cfg)?;
    let network = Network::acquire(cfg);

    minimize_unaudited(cfg, &mut store, network.as_ref())?;

    // We were successful, commit the store
    store.commit()?;

    Ok(())
}

pub fn minimize_unaudited(
    cfg: &Config,
    store: &mut Store,
    network: Option<&Network>,
) -> Result<(), MinimizeUnauditedError> {
    // Set the unaudited entries to nothing
    let old_unaudited = mem::take(&mut store.config.unaudited);

    // Try to vet
    let report = resolver::resolve(
        &cfg.metadata,
        cfg.cli.filter_graph.as_ref(),
        store,
        ResolveDepth::Deep,
    );

    trace!("minimizing unaudited...");
    let new_unaudited = if let Some(suggest) = report.compute_suggest(cfg, network, false)? {
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
                        let old_criteria = report
                            .criteria_mapper
                            .criteria_from_list(&old_entry.criteria);
                        if new_item.suggested_diff.to == old_entry.version
                            && new_item.suggested_criteria.all.contains(&old_criteria)
                        {
                            new_item.suggested_criteria.clear_criteria(&old_criteria);

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
                let criteria_names = report
                    .criteria_mapper
                    .all_criteria_names(&item.suggested_criteria)
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>();
                new_unaudited
                    .entry(package_name.to_string())
                    .or_insert(Vec::new())
                    .push(UnauditedDependency {
                        version: item.suggested_diff.to.clone(),
                        criteria: criteria_names.iter().map(|s| s.to_owned().into()).collect(),
                        dependency_criteria: DependencyCriteria::new(),
                        notes: None,
                        suggest: true,
                    })
            }
        }

        new_unaudited
    } else if let Conclusion::Success(_) = report.conclusion {
        SortedMap::new()
    } else {
        return Err(MinimizeUnauditedError::Unknown);
    };

    // Alright there's the new unaudited
    store.config.unaudited = new_unaudited;

    Ok(())
}

fn cmd_diff(out: &mut dyn Out, cfg: &Config, sub_args: &DiffArgs) -> Result<(), miette::Report> {
    let store = Store::acquire(cfg)?;
    let cache = Cache::acquire(cfg)?;
    let network = Network::acquire(cfg);

    let version1 = &sub_args.version1;
    let version2 = &sub_args.version2;
    let package = &*sub_args.package;

    // Record this command for magic in `vet certify`
    cache.set_last_fetch(FetchCommand::Diff {
        package: package.to_owned(),
        version1: version1.clone(),
        version2: version2.clone(),
    });

    let (fetched1, fetched2) = tokio::runtime::Handle::current().block_on(async {
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
            )
        );
        eulas.into_diagnostic()?;
        pkgs.into_diagnostic()
    })?;

    writeln!(out).into_diagnostic()?;

    // FIXME: mask out .cargo_vcs_info.json

    std::process::Command::new("git")
        .arg("diff")
        .arg("--no-index")
        .arg(&fetched1)
        .arg(&fetched2)
        .status()
        .map_err(CommandError::CommandFailed)
        .into_diagnostic()?;

    Ok(())
}

fn cmd_check(out: &mut dyn Out, cfg: &Config, sub_args: &CheckArgs) -> Result<(), miette::Report> {
    // Run the checker to validate that the current set of deps is covered by the current cargo vet store
    trace!("vetting...");

    let mut store = Store::acquire(cfg)?;
    let network = Network::acquire(cfg);

    if !cfg.cli.locked {
        // Try to update the foreign audits (imports)
        if let Some(network) = &network {
            tokio::runtime::Handle::current()
                .block_on(store.fetch_foreign_audits(network, false))?;
        }

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
        store.commit()?;
    }

    Ok(())
}

fn cmd_fetch_imports(
    out: &mut dyn Out,
    cfg: &Config,
    _sub_args: &FetchImportsArgs,
) -> Result<(), miette::Report> {
    trace!("fetching imports...");

    let mut store = Store::acquire(cfg)?;
    let network = Network::acquire(cfg);

    if let Some(network) = &network {
        if !cfg.cli.locked {
            tokio::runtime::Handle::current()
                .block_on(store.fetch_foreign_audits(network, false))?;
            store.commit()?;
            return Ok(());
        }
    }

    // ERRORS: just a warning that you're holding it wrong, unclear if immediate or buffered,
    // or if this should be a hard error, or if we should ignore the --locked flag and
    // just do it anyway
    writeln!(
        out,
        "warning: ran fetch-imports with --locked, this won't do anything!"
    )
    .into_diagnostic()?;

    Ok(())
}

fn cmd_dump_graph(
    out: &mut dyn Out,
    cfg: &Config,
    sub_args: &DumpGraphArgs,
) -> Result<(), miette::Report> {
    // Dump a mermaid-js graph
    trace!("dumping...");

    let graph = resolver::DepGraph::new(&cfg.metadata, cfg.cli.filter_graph.as_ref(), None);
    match cfg.cli.output_format {
        OutputFormat::Human => graph.print_mermaid(out, sub_args).into_diagnostic()?,
        OutputFormat::Json => serde_json::to_writer_pretty(out, &graph.nodes).into_diagnostic()?,
    }

    Ok(())
}

fn cmd_fmt(_out: &mut dyn Out, cfg: &Config, _sub_args: &FmtArgs) -> Result<(), miette::Report> {
    // Reformat all the files (just load and store them, formatting is implicit).
    trace!("formatting...");
    let store = Store::acquire(cfg)?;
    store.commit()?;
    Ok(())
}

/// Perform crimes on clap long_help to generate markdown docs
fn cmd_help_md(
    out: &mut dyn Out,
    _cfg: &PartialConfig,
    _sub_args: &HelpMarkdownArgs,
) -> Result<(), miette::Report> {
    let app_name = "cargo-vet";
    let pretty_app_name = "cargo vet";
    // Make a new App to get the help message this time.

    writeln!(out, "# {pretty_app_name} CLI manual").into_diagnostic()?;
    writeln!(out).into_diagnostic()?;
    writeln!(
        out,
        "> This manual can be regenerated with `{pretty_app_name} help-markdown`"
    )
    .into_diagnostic()?;
    writeln!(out).into_diagnostic()?;

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
            writeln!(out, "Version: `{version_line}`").into_diagnostic()?;
            writeln!(out).into_diagnostic()?;
        } else {
            // Give subcommands some breathing room
            writeln!(out, "<br><br><br>").into_diagnostic()?;
            writeln!(out, "## {pretty_app_name} {subcommand_name}").into_diagnostic()?;
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

                        writeln!(out, "### {heading}").into_diagnostic()?;

                        if in_global_options && !is_full_command {
                            writeln!(
                                out,
                                "This subcommand accepts all the [global options](#global-options)"
                            )
                            .into_diagnostic()?;
                        }
                    } else {
                        writeln!(out, "### {heading}").into_diagnostic()?;
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
                )
                .into_diagnostic()?;
                continue;
            }
            // The rest is indented, get rid of that
            let line = line.trim();

            // Usage strings get wrapped in full code blocks
            if in_usage && line.starts_with(pretty_app_name) {
                writeln!(out, "```").into_diagnostic()?;
                writeln!(out, "{line}").into_diagnostic()?;
                writeln!(out, "```").into_diagnostic()?;
                continue;
            }

            // argument names are subheadings
            if line.starts_with('-') || line.starts_with('<') {
                writeln!(out, "#### `{line}`").into_diagnostic()?;
                continue;
            }

            // escape default/value strings
            if line.starts_with('[') {
                writeln!(out, "\\{line}  ").into_diagnostic()?;
                continue;
            }

            // Normal paragraph text
            writeln!(out, "{line}").into_diagnostic()?;
        }
        writeln!(out).into_diagnostic()?;

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

fn cmd_gc(out: &mut dyn Out, cfg: &PartialConfig, sub_args: &GcArgs) -> Result<(), miette::Report> {
    let cache = Cache::acquire(cfg)?;

    if sub_args.clean {
        writeln!(
            out,
            "cleaning entire contents of cache directory: {}",
            cfg.cache_dir.display()
        )
        .into_diagnostic()?;
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
    let builtin = builtin_eulas.get(&*criteria).map(|s| s.to_string());
    if let Some(eula) = builtin {
        return eula;
    }

    // ERRORS: the caller should have verified this entry already!
    let criteria_entry = criteria_map
        .get(&*criteria)
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
