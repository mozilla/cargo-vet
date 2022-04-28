use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::fs::OpenOptions;
use std::io::{BufReader, Read};
use std::ops::Deref;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::{fs::File, io::Write, panic, path::PathBuf};

use cargo_metadata::{Metadata, Package, Version};
use clap::{ArgEnum, CommandFactory, Parser, Subcommand};
use format::{AuditEntry, AuditKind, Delta, MetaConfig};
use log::{error, info, trace, warn};
use reqwest::blocking as req;
use serde::{de::Deserialize, ser::Serialize};
use simplelog::{
    ColorChoice, ConfigBuilder, Level, LevelFilter, TermLogger, TerminalMode, WriteLogger,
};

use crate::format::{
    AuditsFile, ConfigFile, CriteriaEntry, DependencyCriteria, ImportsFile, MetaConfigInstance,
    StableMap, Store, UnauditedDependency,
};

pub mod format;
mod resolver;
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
    features: clap_cargo::Features,

    // Top-level flags
    /// Do not pull in new "audits".
    #[clap(long)]
    locked: bool,

    /// How verbose logging should be (log level).
    #[clap(long, arg_enum)]
    #[clap(default_value_t = Verbose::Warn)]
    verbose: Verbose,

    /// Instead of stdout, write output to this file.
    #[clap(long)]
    output_file: Option<PathBuf>,

    /// Instead of stderr, write logs to this file (only used after successful CLI parsing).
    #[clap(long)]
    log_file: Option<PathBuf>,
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

    /// Yield a diff against the last reviewed version.
    #[clap(disable_version_flag = true)]
    Diff(DiffArgs),

    /// Mark `$package $version` as reviewed with `$message`
    #[clap(disable_version_flag = true)]
    Certify(CertifyArgs),

    /// Suggest some low-hanging fruit to review
    #[clap(disable_version_flag = true)]
    Suggest(SuggestArgs),

    /// Reformat all of vet's files (in case you hand-edited them)
    #[clap(disable_version_flag = true)]
    Fmt(FmtArgs),

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
    package: String,
    version: String,
}

/// Emits a diff of the two versions
#[derive(clap::Args)]
struct DiffArgs {
    package: String,
    version1: String,
    version2: String,
}

/// Cerifies the given version
#[derive(clap::Args)]
struct CertifyArgs {
    package: String,
    version1: String,
    version2: Option<String>,
}

#[derive(clap::Args)]
struct SuggestArgs {}

#[derive(clap::Args)]
struct FmtArgs {}

#[derive(clap::Args)]
struct AcceptCriteriaChangeArgs {}

#[derive(clap::Args)]
struct HelpMarkdownArgs {}

/// Logging verbosity levels
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
enum Verbose {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Cli {
    #[cfg(test)]
    pub fn mock() -> Self {
        use clap_cargo::{Features, Manifest, Workspace};

        Self {
            command: None,
            manifest: Manifest::default(),
            workspace: Workspace::default(),
            features: Features::default(),
            locked: true,
            verbose: Verbose::Off,
            output_file: None,
            log_file: None,
        }
    }
}

/// Absolutely All The Global Configurations
pub struct Config {
    // file: ConfigFile,
    metacfg: MetaConfig,
    metadata: Metadata,
    cli: Cli,
    cargo: OsString,
    tmp: PathBuf,
    registry_src: Option<PathBuf>,
}

static EMPTY_PACKAGE: &str = "empty";
static TEMP_DIR_SUFFIX: &str = "cargo-vet-checkout";
static CARGO_ENV: &str = "CARGO";
static CARGO_REGISTRY_SRC: &str = "registry/src/";
static DEFAULT_STORE: &str = "supply-chain";
// package.metadata.vet
static PACKAGE_VET_CONFIG: &str = "vet";
// workspace.metadata.vet
static WORKSPACE_VET_CONFIG: &str = "vet";

static AUDITS_TOML: &str = "audits.toml";
static CONFIG_TOML: &str = "config.toml";
static IMPORTS_LOCK: &str = "imports.lock";

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

fn main() -> Result<(), VetError> {
    let fake_cli = FakeCli::parse();
    let FakeCli::Vet(cli) = fake_cli;

    //////////////////////////////////////////////////////
    // Setup logging / output
    //////////////////////////////////////////////////////

    // Configure our output formats / logging
    let verbosity = match cli.verbose {
        Verbose::Off => LevelFilter::Off,
        Verbose::Warn => LevelFilter::Warn,
        Verbose::Info => LevelFilter::Info,
        Verbose::Debug => LevelFilter::Debug,
        Verbose::Trace => LevelFilter::Trace,
        Verbose::Error => LevelFilter::Error,
    };

    // Init the logger (and make trace logging less noisy)
    if let Some(log_path) = &cli.log_file {
        let log_file = File::create(log_path).unwrap();
        let _ = WriteLogger::init(
            verbosity,
            ConfigBuilder::new()
                .set_location_level(LevelFilter::Off)
                .set_time_level(LevelFilter::Off)
                .set_thread_level(LevelFilter::Off)
                .set_target_level(LevelFilter::Off)
                .build(),
            log_file,
        )
        .unwrap();
    } else {
        let _ = TermLogger::init(
            verbosity,
            ConfigBuilder::new()
                .set_location_level(LevelFilter::Off)
                .set_time_level(LevelFilter::Off)
                .set_thread_level(LevelFilter::Off)
                .set_target_level(LevelFilter::Off)
                .set_level_color(Level::Trace, None)
                .build(),
            TerminalMode::Stderr,
            ColorChoice::Auto,
        );
    }

    // Set a panic hook to redirect to the logger
    panic::set_hook(Box::new(|panic_info| {
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

    ///////////////////////////////////////////////////
    // Fetch cargo metadata
    ///////////////////////////////////////////////////

    let cargo = std::env::var_os(CARGO_ENV).expect("Cargo failed to set $CARGO, how?");
    let mut cmd = cargo_metadata::MetadataCommand::new();
    cmd.cargo_path(&cargo);
    if let Some(manifest_path) = &cli.manifest.manifest_path {
        cmd.manifest_path(manifest_path);
    }
    if cli.features.all_features {
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
    cmd.other_options(other_options);

    info!("Running: {:#?}", cmd.cargo_command());

    let metadata = match cmd.exec() {
        Ok(metadata) => metadata,
        Err(e) => {
            error!("'cargo metadata' failed: {}", e);
            std::process::exit(-1);
        }
    };

    trace!("Got Metadata! {:#?}", metadata);

    //////////////////////////////////////////////////////
    // Parse out our own configuration
    //////////////////////////////////////////////////////

    let default_config = MetaConfigInstance {
        version: Some(1),
        store: Some(Store {
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
                std::process::exit(-1);
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
                std::process::exit(-1);
            })
            .ok()
    }();

    if workspace_metacfg.is_some() && package_metacfg.is_some() {
        error!("Both a workspace and a package defined [metadata.vet]! We don't know what that means, if you do, let us know!");
        std::process::exit(-1);
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

    // These commands don't need an instance and can be run anywhere
    let command_is_freestanding = matches!(
        cli.command,
        Some(Commands::HelpMarkdown { .. })
            | Some(Commands::Inspect { .. })
            | Some(Commands::Diff { .. })
    );

    let init = is_init(&metacfg);
    if matches!(cli.command, Some(Commands::Init { .. })) {
        if init {
            error!(
                "'cargo vet' already initialized (store found at {:#?})",
                metacfg.store_path()
            );
            std::process::exit(-1);
        }
    } else if !init && !command_is_freestanding {
        error!(
            "You must run 'cargo vet init' (store not found at {:#?})",
            metacfg.store_path()
        );
        std::process::exit(-1);
    }

    // TODO: make this configurable
    // TODO: maybe this wants to be actually totally random to allow multi-vets?
    let tmp = std::env::temp_dir().join(TEMP_DIR_SUFFIX);
    let registry_src = home::cargo_home()
        .ok()
        .map(|path| path.join(CARGO_REGISTRY_SRC));
    let cfg = Config {
        metacfg,
        metadata,
        cli,
        cargo,
        tmp,
        registry_src,
    };

    use Commands::*;
    match &cfg.cli.command {
        None => cmd_vet(out, &cfg),
        Some(Init(sub_args)) => cmd_init(out, &cfg, sub_args),
        Some(AcceptCriteriaChange(sub_args)) => cmd_accept_criteria_change(out, &cfg, sub_args),
        Some(Inspect(sub_args)) => cmd_inspect(out, &cfg, sub_args),
        Some(Certify(sub_args)) => cmd_certify(out, &cfg, sub_args),
        Some(Suggest(sub_args)) => cmd_suggest(out, &cfg, sub_args),
        Some(Diff(sub_args)) => cmd_diff(out, &cfg, sub_args),
        Some(Fmt(sub_args)) => cmd_fmt(out, &cfg, sub_args),
        Some(HelpMarkdown(sub_args)) => cmd_help_md(out, &cfg, sub_args),
    }
}

fn cmd_init(_out: &mut dyn Write, cfg: &Config, _sub_args: &InitArgs) -> Result<(), VetError> {
    // Initialize vet

    // Create store_path
    // - audits.toml (empty, sample criteria)
    // - imports.lock (empty)
    // - config.toml (populated with defaults and full list of third-party crates)
    trace!("initializing...");

    let store_path = cfg.metacfg.store_path();

    let (config, audits, imports) = init_files(&cfg.metadata)?;

    // In theory we don't need `all` here, but this allows them to specify
    // the store as some arbitrarily nested subdir for whatever reason
    // (maybe multiple parallel instances?)
    std::fs::create_dir_all(store_path)?;
    store_audits(store_path, audits)?;
    store_imports(store_path, imports)?;
    store_config(store_path, config)?;

    Ok(())
}

pub fn init_files(metadata: &Metadata) -> Result<(ConfigFile, AuditsFile, ImportsFile), VetError> {
    // Default audits file is empty
    let audits = AuditsFile {
        criteria: StableMap::new(),
        audits: StableMap::new(),
    };

    // Default imports file is empty
    let imports = ImportsFile {
        audits: StableMap::new(),
    };

    // This is the hard one
    let config = {
        let mut dependencies = StableMap::new();
        for package in foreign_packages(metadata) {
            // NOTE: May have multiple copies of a package!
            let item = UnauditedDependency {
                version: package.version.clone(),
                notes: Some("automatically imported by 'cargo vet init'".to_string()),
                suggest: true,
                // TODO: use whether this is a build_and_dev to make this weaker
                criteria: format::DEFAULT_CRITERIA.to_string(),
            };
            dependencies
                .entry(package.name.clone())
                .or_insert(vec![])
                .push(item);
        }
        ConfigFile {
            default_criteria: format::get_default_criteria(),
            imports: StableMap::new(),
            unaudited: dependencies,
            policy: StableMap::new(),
        }
    };

    Ok((config, audits, imports))
}

fn cmd_inspect(out: &mut dyn Write, cfg: &Config, sub_args: &InspectArgs) -> Result<(), VetError> {
    // Download a crate's source to a temp location for review
    let tmp = &cfg.tmp;
    clean_tmp(tmp)?;

    let version = Version::from_str(&sub_args.version).expect("could not parse version");
    let to_fetch = &[(&*sub_args.package, &version)];
    let fetch_dir = fetch_crates(cfg, tmp, "fetch", to_fetch)?;
    let fetched = fetched_pkg(&fetch_dir, &sub_args.package, &version);

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

fn cmd_certify(_out: &mut dyn Write, cfg: &Config, sub_args: &CertifyArgs) -> Result<(), VetError> {
    // Certify that you have reviewed a crate's source for some version / delta
    let store_path = cfg.metacfg.store_path();
    let mut audits = load_audits(store_path)?;
    let config = load_config(store_path)?;

    let dependency_criteria = DependencyCriteria::new();

    // FIXME: better error when this goes bad
    let version1 = Version::parse(&sub_args.version1).expect("version1 wasn't a valid Version");
    let version2 = sub_args
        .version2
        .as_ref()
        .map(|v| Version::parse(v).expect("version2 wasn't a valid Version"));

    let kind = if let Some(version2) = version2 {
        // This is a delta audit
        AuditKind::Delta {
            delta: Delta {
                from: version1,
                to: version2,
            },
            dependency_criteria,
        }
    } else {
        AuditKind::Full {
            version: version1,
            dependency_criteria,
        }
    };

    let criteria = config.default_criteria;

    // TODO: source this from git
    let who = Some("?TODO?".to_string());
    // TODO: start an interactive prompt
    let notes = Some("?TODO?".to_string());

    let new_entry = AuditEntry {
        kind,
        criteria,
        who,
        notes,
    };

    // TODO: check if the version makes sense..?
    if !foreign_packages(&cfg.metadata).any(|pkg| pkg.name == sub_args.package) {
        error!("'{}' isn't one of your foreign packages", sub_args.package);
        std::process::exit(-1);
    }

    audits
        .audits
        .entry(sub_args.package.clone())
        .or_insert(vec![])
        .push(new_entry);
    store_audits(store_path, audits)?;

    Ok(())
}

fn cmd_suggest(out: &mut dyn Write, cfg: &Config, _sub_args: &SuggestArgs) -> Result<(), VetError> {
    // * download the current (saved?) lockfile's packages
    // * download the current audited packages
    // * diff each package (if there is any audit)
    // * sort by the line count of the diff
    // * emit the sorted list
    let tmp = &cfg.tmp;
    clean_tmp(tmp)?;

    let store_path = cfg.metacfg.store_path();
    let audits = load_audits(store_path)?;

    // TODO: skip packages with suggest=false

    // FIXME: in theory we can avoid fetching any file with an up to date audit
    writeln!(out, "fetching current packages...")?;
    let fetched_saved = {
        let to_fetch: Vec<_> = foreign_packages(&cfg.metadata)
            .map(|pkg| (&*pkg.name, &pkg.version))
            .collect();
        fetch_crates(cfg, tmp, "current", &to_fetch)?
    };
    writeln!(out, "fetched to {:#?}", fetched_saved)?;

    writeln!(out, "fetching audited packages...")?;
    let fetched_audited = {
        // TODO: do this
        warn!("fetching audited packages not yet implemented!");
        let to_fetch: Vec<_> = foreign_packages(&cfg.metadata)
            .map(|pkg| (&*pkg.name, &pkg.version))
            .collect();
        fetch_crates(cfg, tmp, "audited", &to_fetch)?
    };
    writeln!(out, "fetched to {:#?}", fetched_audited)?;

    writeln!(out, "gathering diffstats...")?;

    let mut diffstats = vec![];
    for package in foreign_packages(&cfg.metadata) {
        // If there are no audits, then diff from an empty dir
        let (base, base_ver) = if audits.audits.contains_key(&package.name) {
            // TODO: find the closest audited version <= sub_args.version!
            (
                fetched_pkg(&fetched_audited, &package.name, &package.version),
                "TODO?".to_string(),
            )
        } else {
            (tmp.join(EMPTY_PACKAGE), "0.0.0".to_string())
        };
        let current = fetched_pkg(&fetched_saved, &package.name, &package.version);
        let stat = diffstat_crate(cfg, &base, &current)?;

        // Ignore things that didn't change
        if stat.count > 0 {
            diffstats.push((stat, &package.name, base_ver, package.version.to_string()));
        }
    }

    // If we got no diffstats then we're fully audited!
    if diffstats.is_empty() {
        writeln!(out, "Wow, everything is completely audited! You did it!!!")?;
        return Ok(());
    }

    // Ok, now sort the diffstats by change count and print them:
    diffstats.sort_by_key(|(stat, ..)| stat.count);
    writeln!(out, "{} audits to perform:", diffstats.len())?;
    let max_len = diffstats
        .iter()
        .map(|(_, package_name, ..)| package_name.len())
        .max()
        .unwrap();
    for (stat, package, v1, v2) in diffstats.iter() {
        // Try to align things better...
        let heading = format!("{package}:{v1}->{v2}");
        writeln!(
            out,
            "  {heading:width$}{}",
            stat.raw.trim(),
            width = max_len + 15
        )?;
    }
    Ok(())
}
fn cmd_diff(out: &mut dyn Write, cfg: &Config, sub_args: &DiffArgs) -> Result<(), VetError> {
    // * download version1 of the package
    // * download version2 of the package
    // * diff the two
    // * emit the diff
    let tmp = &cfg.tmp;
    clean_tmp(tmp)?;

    writeln!(
        out,
        "fetching {} {}...",
        sub_args.package, sub_args.version1
    )?;
    let version1 = sub_args
        .version1
        .parse()
        .expect("Failed to parse first version");
    let version2 = sub_args
        .version2
        .parse()
        .expect("Failed to parse second version");
    let to_fetch1 = &[(&*sub_args.package, &version1)];
    let fetch_dir1 = fetch_crates(cfg, tmp, "first", to_fetch1)?;
    let fetched1 = fetched_pkg(&fetch_dir1, &sub_args.package, &version1);
    writeln!(
        out,
        "fetched {} {} to {:#?}",
        sub_args.package, sub_args.version1, fetched1
    )?;

    writeln!(
        out,
        "fetching {} {}...",
        sub_args.package, sub_args.version2
    )?;
    let to_fetch2 = &[(&*sub_args.package, &version2)];
    let fetch_dir2 = fetch_crates(cfg, tmp, "second", to_fetch2)?;
    let fetched2 = fetched_pkg(&fetch_dir2, &sub_args.package, &version2);
    writeln!(
        out,
        "fetched {} {} to {:#?}",
        sub_args.package, sub_args.version2, fetched2
    )?;

    writeln!(out)?;

    diff_crate(out, cfg, &fetched1, &fetched2)?;

    Ok(())
}

fn cmd_vet(out: &mut dyn Write, cfg: &Config) -> Result<(), VetError> {
    // Run the checker to validate that the current set of deps is covered by the current cargo vet store
    trace!("vetting...");

    let store_path = cfg.metacfg.store_path();

    let audits = load_audits(store_path)?;
    let config = load_config(store_path)?;

    // FIXME: We should probably check in --locked vets if the config has changed its
    // imports and warn if the imports.lock is inconsistent with that..?
    //
    // TODO: error out if the foreign audits changed their criteria (compare to imports.lock)
    let imports = if !cfg.cli.locked {
        fetch_foreign_audits(out, cfg, &config)?
    } else {
        load_imports(store_path)?
    };

    // DO THE THING!!!!
    let report = resolver::resolve(&cfg.metadata, &config, &audits, &imports);
    report.print_report(out, cfg)?;

    // Only save imports if we succeeded, to avoid any modifications on error.
    if !report.has_errors() {
        trace!("Saving imports.lock...");
        store_imports(store_path, imports)?;
    }

    Ok(())
}

fn cmd_fmt(_out: &mut dyn Write, cfg: &Config, _sub_args: &FmtArgs) -> Result<(), VetError> {
    // Reformat all the files (just load and store them, formatting is implict).
    trace!("formatting...");

    let store_path = cfg.metacfg.store_path();

    store_audits(store_path, load_audits(store_path)?)?;
    store_config(store_path, load_config(store_path)?)?;
    store_imports(store_path, load_imports(store_path)?)?;

    Ok(())
}

fn cmd_accept_criteria_change(
    _out: &mut dyn Write,
    _cfg: &Config,
    _sub_args: &AcceptCriteriaChangeArgs,
) -> Result<(), VetError> {
    // Accept changes that a foreign audits.toml made to their criteria.
    trace!("accepting...");

    error!("TODO: unimplemented feature!");

    Ok(())
}

/// Perform crimes on clap long_help to generate markdown docs
fn cmd_help_md(
    out: &mut dyn Write,
    _cfg: &Config,
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
            if in_usage && line.starts_with(&subcommand_name) {
                writeln!(out, "```")?;
                if is_full_command {
                    writeln!(out, "{line}")?;
                } else {
                    writeln!(out, "{pretty_app_name} {line}")?;
                }

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

fn load_audits(store_path: &Path) -> Result<AuditsFile, VetError> {
    // TODO: do integrity checks? (for things like criteria keys being valid)
    let path = store_path.join(AUDITS_TOML);
    let file: AuditsFile = load_toml(&path)?;
    file.validate()?;
    Ok(file)
}

fn load_config(store_path: &Path) -> Result<ConfigFile, VetError> {
    // TODO: do integrity checks?
    let path = store_path.join(CONFIG_TOML);
    let file: ConfigFile = load_toml(&path)?;
    file.validate()?;
    Ok(file)
}

fn load_imports(store_path: &Path) -> Result<ImportsFile, VetError> {
    // TODO: do integrity checks?
    let path = store_path.join(IMPORTS_LOCK);
    let file: ImportsFile = load_toml(&path)?;
    file.validate()?;
    Ok(file)
}

fn store_audits(store_path: &Path, audits: AuditsFile) -> Result<(), VetError> {
    let heading = r###"
# cargo-vet audits file
"###;

    let path = store_path.join(AUDITS_TOML);
    store_toml(&path, heading, audits)?;
    Ok(())
}
fn store_config(store_path: &Path, config: ConfigFile) -> Result<(), VetError> {
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

fn clean_tmp(tmp: &Path) -> Result<(), VetError> {
    // Wipe out and remake tmp my making sure it exists, destroying it, and then remaking it.
    fs::create_dir_all(tmp)?;
    fs::remove_dir_all(tmp)?;
    fs::create_dir_all(tmp)?;
    fs::create_dir_all(tmp.join(EMPTY_PACKAGE))?;
    Ok(())
}

fn fetch_crates(
    cfg: &Config,
    tmp: &Path,
    fetch_dir: &str,
    crates: &[(&str, &Version)],
) -> Result<PathBuf, VetError> {
    // Create a tempdir with a Cargo.toml referring to each package,
    // then run 'cargo fetch' on it to ensure the cargo cache is populated.
    // FIXME: maybe we should actually just check if we have all the packages
    // first, to avoid doing a bunch of faffing around we don't need..?
    {
        let out = Command::new(&cfg.cargo)
            .current_dir(tmp)
            .arg("new")
            .arg("--bin")
            .arg(fetch_dir)
            .output()?;

        if !out.status.success() {
            panic!(
                "command failed!\nout:\n{}\nstderr:\n{}",
                String::from_utf8(out.stdout).unwrap(),
                String::from_utf8(out.stderr).unwrap()
            )
        }
    }

    trace!("init to: {:#?}", tmp);
    let fetch_dir = tmp.join(fetch_dir);
    let fetch_toml = fetch_dir.join("Cargo.toml");

    {
        // FIXME: properly parse the toml instead of assuming structure
        let mut toml = OpenOptions::new().append(true).open(&fetch_toml)?;

        for (krate, version) in crates {
            // Mangle names so that cargo doesn't complain about multiple versions.
            // FIXME: probably want more reliable escaping...
            let rename = format!("{}_{}", krate, version);
            let rename = rename.replace('.', "_");
            let rename = rename.replace('+', "_");
            writeln!(
                toml,
                r#""{}" = {{ version = "={}", package = "{}" }}"#,
                rename, version, krate
            )?;
        }
    }

    trace!("updated: {:#?}", fetch_toml);

    {
        let out = Command::new(&cfg.cargo)
            .current_dir(&fetch_dir)
            .arg("fetch")
            .output()?;

        if !out.status.success() {
            panic!(
                "command failed!\nout:\n{}\nstderr:\n{}",
                String::from_utf8(out.stdout).unwrap(),
                String::from_utf8(out.stderr).unwrap()
            )
        }
    }

    trace!("fetched");

    if cfg.registry_src.is_none() {
        error!("Could not resolve CARGO_HOME!?");
        std::process::exit(-1);
    }

    let registry_src = cfg.registry_src.as_ref().unwrap();
    if !registry_src.exists() {
        error!("Cargo registry src cache doesn't exist!?");
        std::process::exit(-1);
    }

    {
        // TODO: we need to be smarter about this and tell fetch what we actually need.
        // This is currently both overbroad and insufficent, but might work well enough
        // for the MVP. What exactly we should do here depends on what packages we actually
        // want to compare in practice (how much we can just copy an existing lockfile).
        let out = Command::new(&cfg.cargo).arg("fetch").output()?;

        if !out.status.success() {
            panic!(
                "command failed!\nout:\n{}\nstderr:\n{}",
                String::from_utf8(out.stdout).unwrap(),
                String::from_utf8(out.stderr).unwrap()
            )
        }
    }

    // This is all unstable nonsense so being a bit paranoid here so that we can notice
    // when things get weird and understand corner cases better...
    let mut real_src_dir = None;
    for entry in std::fs::read_dir(registry_src)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if real_src_dir.is_some() {
                warn!("Found multiple subdirectories in CARGO_HOME/registry/src");
                warn!("  Preferring any named github.com-*");
                if path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("github.com-")
                {
                    real_src_dir = Some(path);
                }
            } else {
                real_src_dir = Some(path);
            }
        }
    }
    if real_src_dir.is_none() {
        error!("failed to find cargo package sources");
        std::process::exit(-1);
    }
    let real_src_dir = real_src_dir.unwrap();

    // FIXME: we probably shouldn't do this, but better to fail-fast when hacky.
    for (krate, version) in crates {
        if !fetched_pkg(&real_src_dir, krate, version).exists() {
            error!("failed to fetch {}:{}", krate, version);
            std::process::exit(-1);
        }
    }

    Ok(real_src_dir)
}

fn diff_crate(
    _out: &mut dyn Write,
    _cfg: &Config,
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

    // TODO: pretty sure this is wrong, should use --exit-code and copy diffstat_crate's logic
    // (not actually sure what the default exit status logic is!)
    if !status.success() {
        todo!()
    }

    Ok(())
}

struct DiffStat {
    raw: String,
    count: u64,
}

pub struct DiffRecommendation<'a> {
    from: &'a Version,
    to: &'a Version,
    diffstat: DiffStat,
}

pub fn fetch_and_diffstat_all<'a>(
    cfg: &Config,
    package: &str,
    diffs: BTreeSet<(&'a Version, &'a Version)>,
) -> Result<DiffRecommendation<'a>, VetError> {
    let mut all_versions = BTreeSet::new();
    for (from, to) in &diffs {
        all_versions.insert(*from);
        all_versions.insert(*to);
    }

    let mut best_rec: Option<DiffRecommendation> = None;
    if cfg.registry_src.is_some() {
        let to_fetch = all_versions
            .iter()
            .map(|v| (package, *v))
            .collect::<Vec<_>>();
        let fetch_dir = fetch_crates(cfg, &cfg.tmp, "diff", &to_fetch)?;
        let fetches = all_versions
            .iter()
            .map(|v| (*v, fetched_pkg(&fetch_dir, package, v)))
            .collect::<BTreeMap<_, _>>();

        for (from_ver, to_ver) in diffs {
            let from = &fetches[from_ver];
            let to = &fetches[to_ver];
            let diffstat = diffstat_crate(cfg, &from, &to)?;
            let rec = DiffRecommendation {
                from: from_ver,
                to: to_ver,
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
    } else {
        warn!("assuming we're in tests and mocking");
        for (from, to) in &diffs {
            let from_len = from.major * from.major;
            let to_len: u64 = to.major * to.major;
            let delta = to_len as i64 - from_len as i64;
            let count = delta.unsigned_abs();
            let raw = if delta < 0 {
                format!("-{}", count)
            } else {
                format!("+{}", count)
            };
            let diffstat = DiffStat { raw, count };
            let rec = DiffRecommendation { from, to, diffstat };

            if let Some(best) = best_rec.as_ref() {
                if best.diffstat.count > rec.diffstat.count {
                    best_rec = Some(rec);
                }
            } else {
                best_rec = Some(rec);
            }
        }
    }

    Ok(best_rec.unwrap())
}

fn diffstat_crate(_cfg: &Config, version1: &Path, version2: &Path) -> Result<DiffStat, VetError> {
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
        panic!(
            "command failed!\nout:\n{}\nstderr:\n{}",
            String::from_utf8(out.stdout).unwrap(),
            String::from_utf8(out.stderr).unwrap()
        )
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

fn fetch_foreign_audits(
    _out: &mut dyn Write,
    _cfg: &Config,
    config: &ConfigFile,
) -> Result<ImportsFile, VetError> {
    // Download all the foreign audits.toml files that we trust
    let mut audits = StableMap::new();
    for (name, import) in &config.imports {
        let url = &import.url;
        // FIXME: this should probably be async but that's a Whole Thing and these files are small.
        let audit_txt = req::get(url).and_then(|r| r.text());
        if let Err(e) = audit_txt {
            error!("Could not load {name} @ {url} - {e}");
            std::process::exit(-1);
        }
        let audit_file: Result<AuditsFile, _> = toml::from_str(&audit_txt.unwrap());
        if let Err(e) = audit_file {
            error!("Could not parse {name} @ {url} - {e}");
            std::process::exit(-1);
        }

        // TODO: do integrity checks? (share code with load_audits/load_imports here...)

        audits.insert(name.clone(), audit_file.unwrap());
    }

    Ok(ImportsFile { audits })
}

fn fetched_pkg(fetch_dir: &Path, name: &str, version: &Version) -> PathBuf {
    let dir_name = format!("{}-{}", name, version);
    fetch_dir.join(dir_name)
}
