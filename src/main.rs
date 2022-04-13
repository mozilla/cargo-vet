use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io::{BufReader, Read};
use std::ops::Deref;
use std::path::Path;
use std::process::Command;
use std::{fmt, fs};
use std::{fs::File, io::Write, panic, path::PathBuf};

use cargo_metadata::{Metadata, Package, Version, VersionReq};
use clap::{ArgEnum, CommandFactory, Parser, Subcommand};
use log::{error, info, trace, warn};
use reqwest::blocking as req;
use serde::de::Visitor;
use serde::{de, de::Deserialize, ser::Serialize};
use serde::{Deserializer, Serializer};
use simplelog::{
    ColorChoice, ConfigBuilder, Level, LevelFilter, TermLogger, TerminalMode, WriteLogger,
};

type StableMap<K, V> = linked_hash_map::LinkedHashMap<K, V>;
type VetError = eyre::Report;

#[derive(Parser)]
#[clap(version, about, long_about = None)]
#[clap(propagate_version = true)]
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
    Fetch(FetchArgs),

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

/// Fetches the crate to a temp location
#[derive(clap::Args)]
struct FetchArgs {
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

/// Absolutely All The Global Configurations
struct Config {
    // file: ConfigFile,
    metacfg: MetaConfig,
    metadata: Metadata,
    cli: Cli,
    cargo: OsString,
    tmp: PathBuf,
    registry_src: Option<PathBuf>,
}

/// A `[*.metadata.vet]` table in a Cargo.toml, configuring our behaviour
#[derive(serde::Deserialize)]
struct MetaConfigInstance {
    // Reserved for future use, if not present version=1 assumed.
    // (not sure whether this versions the format, or semantics, or...
    // for now assuming this species global semantics of some kind.
    version: Option<u64>,
    store: Option<Store>,
}
#[derive(serde::Deserialize)]
struct Store {
    path: Option<PathBuf>,
}

// FIXME: It's *possible* for someone to have a workspace but not have a
// global `vet` instance for the whole workspace. In this case they *could*
// have individual `vet` instances for each subcrate they care about.
// This is... Weird, and it's unclear what that *means*... but maybe it's valid?
// Either way, we definitely don't support it right now!

/// All available configuration files, overlaying eachother.
/// Generally contains: `[Default, Workspace, Package]`
struct MetaConfig(Vec<MetaConfigInstance>);

impl MetaConfig {
    fn store_path(&self) -> &Path {
        // Last config gets priority to set this
        for config in self.0.iter().rev() {
            if let Some(store) = &config.store {
                if let Some(path) = &store.path {
                    return path;
                }
            }
        }
        unreachable!("Default config didn't define store.path???");
    }
    fn version(&self) -> u64 {
        // Last config gets priority to set this
        for config in self.0.iter().rev() {
            if let Some(ver) = config.version {
                return ver;
            }
        }
        unreachable!("Default config didn't define version???");
    }
}

type AuditedDependencies = StableMap<String, Vec<AuditEntry>>;

/// audits.toml
#[derive(serde::Serialize, serde::Deserialize)]
struct AuditsFile {
    /// A map of criteria_name to details on that criteria.
    criteria: StableMap<String, CriteriaEntry>,
    /// Actual audits.
    audits: AuditedDependencies,
}

/// imports.lock, not sure what I want to put in here yet.
#[derive(serde::Serialize, serde::Deserialize)]
struct ImportsFile {
    audits: StableMap<String, AuditsFile>,
}

/// config.toml
#[derive(serde::Serialize, serde::Deserialize)]
struct ConfigFile {
    /// Remote audits.toml's that we trust and want to import.
    imports: StableMap<String, RemoteImport>,
    /// All of the "foreign" dependencies that we rely on but haven't audited yet.
    /// Foreign dependencies are just "things on crates.io", everything else
    /// (paths, git, etc) is assumed to be "under your control" and therefore implicitly trusted.
    unaudited: StableMap<String, Vec<UnauditedDependency>>,
    policy: PolicyTable,
}

/// Information on a Criteria
#[derive(serde::Serialize, serde::Deserialize)]
struct CriteriaEntry {
    /// Summary of how you evaluate something by this criteria.
    description: String,
    /// Whether this criteria is part of the "defaults"
    default: bool,
    /// Criteria that this one implies
    implies: Vec<String>,
}

/// Policies the tree must pass (TODO: understand this properly)
#[derive(serde::Serialize, serde::Deserialize)]
struct PolicyTable {
    criteria: Option<Vec<String>>,
    #[serde(rename = "build-and-dev-criteria")]
    build_and_dev_criteria: Option<Vec<String>>,
    targets: Option<Vec<String>>,
    #[serde(rename = "build-and-dev-targets")]
    build_and_dev_targets: Option<Vec<String>>,
}

/// A remote audits.toml that we trust the contents of (by virtue of trusting the maintainer).
#[derive(serde::Serialize, serde::Deserialize)]
struct RemoteImport {
    /// URL of the foreign audits.toml
    url: String,
    /// A list of criteria that are implied by foreign criteria
    criteria_map: Vec<CriteriaMapping>,
}

/// Translations of foreign criteria to local criteria.
#[derive(serde::Serialize, serde::Deserialize)]
struct CriteriaMapping {
    /// This local criteria is implied...
    ours: String,
    /// If all of these foreign criteria apply
    theirs: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct UnauditedDependency {
    /// The version(s) of the crate that we are currently "fine" with leaving unaudited.
    /// For the sake of consistency, I'm making this a proper Cargo VersionReq:
    /// https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html
    ///
    /// One significant implication of this is that x.y.z is *not* one version. It is
    /// ^x.y.z, per Cargo convention. You must use =x.y.z to be that specific. We will
    /// do this for you when we do `cargo vet init`, so this shouldn't be a big deal?
    version: Version,
    /// Freeform notes, put whatever you want here. Just more stable/reliable than comments.
    notes: Option<String>,
    /// Whether suggest should bother mentioning this (defaults true)
    suggest: bool,
}

/// This is just a big vague ball initially. It's up to the Audits/Unuadited/Trusted wrappers
/// to validate if it "makes sense" for their particular function.
#[derive(serde::Serialize, serde::Deserialize)]
struct AuditEntry {
    version: Option<Version>,
    delta: Option<Delta>,
    violation: Option<VersionReq>,
    who: Option<String>,
    notes: Option<String>,
    criteria: Option<Vec<String>>,
    /// A list of criteria that transitive dependencies must satisfy for this
    /// audit to continue to be considered valid.
    ///
    /// Example:
    ///
    /// ```toml
    /// dependency_criteria = { hmac: ['secure', 'crypto_reviewed'] }
    /// ```
    dependency_criteria: Option<Vec<StableMap<String, Vec<String>>>>,
}

/// A "VERSION -> VERSION"
struct Delta {
    from: Version,
    to: Version,
}

impl<'de> Deserialize<'de> for Delta {
    fn deserialize<D>(deserializer: D) -> Result<Delta, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DeltaVisitor;
        impl<'de> Visitor<'de> for DeltaVisitor {
            type Value = Delta;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a delta of the form 'VERSION -> VERSION'")
            }
            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if let Some((from, to)) = s.split_once("->") {
                    Ok(Delta {
                        from: Version::parse(from.trim()).map_err(de::Error::custom)?,
                        to: Version::parse(to.trim()).map_err(de::Error::custom)?,
                    })
                } else {
                    Err(de::Error::invalid_value(de::Unexpected::Str(s), &self))
                }
            }
        }

        deserializer.deserialize_str(DeltaVisitor)
    }
}

impl Serialize for Delta {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let output = format!("{} -> {}", self.from, self.to);
        serializer.serialize_str(&output)
    }
}

impl ConfigFile {
    fn validate(&self) -> Result<(), VetError> {
        // TODO
        Ok(())
    }
}
impl ImportsFile {
    fn validate(&self) -> Result<(), VetError> {
        // TODO
        Ok(())
    }
}
impl AuditsFile {
    fn validate(&self) -> Result<(), VetError> {
        // TODO
        Ok(())
    }
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
static VETTED_LOCK: &str = "Vetted.lock";

// store = { path = './supply-chain' }
// audits = [
//  "https://raw.githubusercontent.com/rust-lang/cargo-trust-store/audited.toml",
//  "https://hg.example.org/example/raw-file/tip/audited.toml"
// ]

// supply-chain
// - audited.toml
// - trusted.toml
// - unaudited.toml

fn main() -> Result<(), VetError> {
    let cli = Cli::parse();

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

    let init = is_init(&metacfg);
    if matches!(cli.command, Some(Commands::Init { .. })) {
        if init {
            error!(
                "'cargo vet' already initialized (store found at {:#?})",
                metacfg.store_path()
            );
            std::process::exit(-1);
        }
    } else if !init {
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
        Some(Fetch(sub_args)) => cmd_fetch(out, &cfg, sub_args),
        Some(Certify(sub_args)) => cmd_certify(out, &cfg, sub_args),
        Some(Suggest(sub_args)) => cmd_suggest(out, &cfg, sub_args),
        Some(Diff(sub_args)) => cmd_diff(out, &cfg, sub_args),
        Some(Fmt(sub_args)) => cmd_fmt(out, &cfg, sub_args),
        Some(HelpMarkdown(sub_args)) => cmd_help_md(out, &cfg, sub_args),
    }
}

fn cmd_init(_out: &mut dyn Write, cfg: &Config, _sub_args: &InitArgs) -> Result<(), VetError> {
    // Initialize vet
    trace!("initializing...");

    let store_path = cfg.metacfg.store_path();

    // Create store_path
    // - audits.toml (empty, sample criteria)
    // - imports.lock (empty)
    // - config.toml (populated with defaults and full list of third-party crates)

    // In theory we don't need `all` here, but this allows them to specify
    // the store as some arbitrarily nested subdir for whatever reason
    // (maybe multiple parallel instances?)
    std::fs::create_dir_all(store_path)?;

    {
        trace!("initializing {:#?}", AUDITS_TOML);

        let sample_criteria = CriteriaEntry {
            description: "you looked at it and it seems fine".to_string(),
            default: true,
            implies: vec![],
        };

        let audits = AuditsFile {
            criteria: [("reviewed".to_string(), sample_criteria)]
                .into_iter()
                .collect(),
            audits: StableMap::new(),
        };
        store_audits(store_path, audits)?;
    }

    {
        trace!("initializing {:#?}", IMPORTS_LOCK);
        let imports = ImportsFile {
            audits: StableMap::new(),
        };
        store_imports(store_path, imports)?;
    }

    {
        trace!("initializing {:#?}", CONFIG_TOML);

        let mut dependencies = StableMap::new();
        for package in foreign_packages(&cfg.metadata) {
            // NOTE: May have multiple copies of a package!
            let item = UnauditedDependency {
                version: package.version.clone(),
                notes: Some("automatically imported by 'cargo vet init'".to_string()),
                suggest: true,
            };
            dependencies
                .entry(package.name.clone())
                .or_insert(vec![])
                .push(item);
        }
        let config = ConfigFile {
            imports: StableMap::new(),
            unaudited: dependencies,
            policy: PolicyTable {
                criteria: None,
                build_and_dev_criteria: None,
                targets: None,
                build_and_dev_targets: None,
            },
        };
        store_config(store_path, config)?;
    }

    Ok(())
}

fn cmd_fetch(out: &mut dyn Write, cfg: &Config, sub_args: &FetchArgs) -> Result<(), VetError> {
    // Download a crate's source to a temp location for review
    let tmp = &cfg.tmp;
    clean_tmp(tmp)?;

    let to_fetch = &[(&*sub_args.package, &*sub_args.version)];
    let fetch_dir = fetch_crates(cfg, tmp, "fetch", to_fetch)?;
    let fetched = fetched_pkg(&fetch_dir, &sub_args.package, &sub_args.version);

    writeln!(out, "  fetched to {:#?}", fetched)?;
    Ok(())
}

fn cmd_certify(_out: &mut dyn Write, cfg: &Config, sub_args: &CertifyArgs) -> Result<(), VetError> {
    // Certify that you have reviewed a crate's source for some version / delta
    let store_path = cfg.metacfg.store_path();
    let mut audits = load_audits(store_path)?;

    // FIXME: better error when this goes bad
    let version1 = Version::parse(&sub_args.version1).expect("version1 wasn't a valid Version");
    let version2 = sub_args
        .version2
        .as_ref()
        .map(|v| Version::parse(v).expect("version2 wasn't a valid Version"));

    let mut version = None;
    let mut delta = None;
    if let Some(version2) = version2 {
        // This is a delta audit
        delta = Some(Delta {
            from: version1,
            to: version2,
        });
    } else {
        // This is an absolute audit
        version = Some(version1);
    }

    // TODO: source this from git or something?
    let who = Some("?TODO?".to_string());
    // TODO: start an interactive prompt? launch $EDITOR?
    let notes = Some("?TODO?".to_string());
    // TODO: No criteria is the default criteria? Does that make sense?
    // Shouldn't we actually snapshot the current default so the default can change
    // without changing the claims on old audits? Or do we in fact *want* that so
    // that audit criteria can be subdivided, and the defaults will pick that up..?
    //
    // Alternate impl?
    // audits.default_criteria.clone()
    //      .unwrap_or_else(|| audits.criteria.keys().cloned().collect());
    let criteria = None;
    // TODO: figure this out
    let dependency_criteria = None;

    let new_entry = AuditEntry {
        version,
        delta,
        violation: None,
        who,
        notes,
        criteria,
        dependency_criteria,
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
            .map(|pkg| (&*pkg.name, pkg.version.to_string()))
            .collect();
        let to_fetch: Vec<_> = to_fetch
            .iter()
            .map(|(krate, version)| (*krate, &**version))
            .collect();
        fetch_crates(cfg, tmp, "current", &to_fetch)?
    };
    writeln!(out, "fetched to {:#?}", fetched_saved)?;

    writeln!(out, "fetching audited packages...")?;
    let fetched_audited = {
        // TODO: do this
        warn!("fetching audited packages not yet implemented!");
        let to_fetch: Vec<_> = foreign_packages(&cfg.metadata)
            .map(|pkg| (&*pkg.name, pkg.version.to_string()))
            .collect();
        let to_fetch: Vec<_> = to_fetch
            .iter()
            .map(|(krate, version)| (*krate, &**version))
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
            let version = &package.version.to_string();
            (
                fetched_pkg(&fetched_audited, &package.name, version),
                "TODO?".to_string(),
            )
        } else {
            (tmp.join(EMPTY_PACKAGE), "0.0.0".to_string())
        };
        let current = fetched_pkg(&fetched_saved, &package.name, &package.version.to_string());
        let stat = diffstat_crate(out, cfg, &base, &current)?;

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
    let to_fetch1 = &[(&*sub_args.package, &*sub_args.version1)];
    let fetch_dir1 = fetch_crates(cfg, tmp, "first", to_fetch1)?;
    let fetched1 = fetched_pkg(&fetch_dir1, &sub_args.package, &sub_args.version1);
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
    let to_fetch2 = &[(&*sub_args.package, &*sub_args.version2)];
    let fetch_dir2 = fetch_crates(cfg, tmp, "second", to_fetch2)?;
    let fetched2 = fetched_pkg(&fetch_dir2, &sub_args.package, &sub_args.version2);
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

    // FIXME: fetch_foreign_audits may fail to download things, so we should really
    // be merging these two files somehow? Especially if we want to writeback the
    // results to our lockfile!
    //
    // FIXME: Do we actually want to hold on to historical foreign audits? Like
    // if someone we trust adds or removes an entry, do we forget about that entry
    // or do we want to still remember it existed?
    //
    // FIXME: We should probably check if the config has changed its imports and
    // mask out things in imports.lock that aren't there anymore?
    //
    // TODO: error out if the foreign audits changed their criteria (compare to imports.lock)
    let imports = if !cfg.cli.locked {
        fetch_foreign_audits(out, cfg, &config)?
    } else {
        load_imports(store_path)?
    };

    // Dummy values for corner cases
    let root_version = Version::new(0, 0, 0);
    let no_audits = Vec::new();

    let mut audited_count: u64 = 0;
    let mut unaudited_count: u64 = 0;
    let mut failed = vec![];
    let mut violation_failed = vec![];

    // Actually vet the dependencies
    'all_packages: for package in foreign_packages(&cfg.metadata) {
        let unaudited = config.unaudited.get(&package.name);

        // Just merge all the entries from the foreign audit files and our audit file.
        let foreign_audits = imports
            .audits
            .values()
            .flat_map(|audit_file| audit_file.audits.get(&package.name).unwrap_or(&no_audits));
        let own_audits = audits.audits.get(&package.name).unwrap_or(&no_audits);

        let mut violations = Vec::new();
        // Deltas are flipped so that we have a map of 'to: [froms]'. This lets
        // us start at the current version and look up all the deltas that *end* at that
        // version. By repeating this over and over, we can slowly walk back in time until
        // we run out of deltas or reach full audit or an unaudited entry.
        let mut deltas_to_from = HashMap::<&Version, HashSet<&Version>>::new();

        // Collect up all the deltas
        for entry in own_audits.iter().chain(foreign_audits) {
            // For uniformity, model a Full Audit as `0.0.0 -> x.y.z`
            if let Some(ver) = &entry.version {
                deltas_to_from.entry(ver).or_default().insert(&root_version);
            }
            if let Some(delta) = &entry.delta {
                deltas_to_from
                    .entry(&delta.to)
                    .or_default()
                    .insert(&delta.from);
            }
            if let Some(violation) = &entry.violation {
                violations.push(violation);
            }
        }

        // Reject forbidden packages
        //
        // TODO: should the "local" audit have a mechanism to override foreign forbids?
        // TODO: this should be stricter, and fail out completely if ANY audit entries match!
        for violation in &violations {
            if violation.matches(&package.version) {
                violation_failed.push(package);
                continue 'all_packages;
            }
        }

        // Now try to resolve the deltas
        let mut cur_versions: HashSet<&Version> = [&package.version].into_iter().collect();
        let mut next_versions: HashSet<&Version> = HashSet::new();
        loop {
            // If there's no versions left to check, we've failed
            if cur_versions.is_empty() {
                failed.push(package);
                // error!("could not cerify {} {}", package.name, package.version);
                continue 'all_packages;
            }

            // Check if we've succeeded
            for &version in &cur_versions {
                if let Some(allowed) = unaudited {
                    if allowed.iter().any(|a| a.version == *version) {
                        unaudited_count += 1;
                        // Reached an explicitly unaudited package, that's good enough

                        // TODO: register this unaudited entry as "used" so we can warn
                        // about any entries that weren't used (security hazard).
                        continue 'all_packages;
                    }
                    if version == &root_version {
                        audited_count += 1;
                        // Reached 0.0.0, which means we hit a Full Audit, that's perfect

                        // TODO: now verify policy
                        // TODO: now verify dependency_criteria
                        continue 'all_packages;
                    }
                }
            }

            // Apply deltas to move along the next "layer" of the search
            for version in &cur_versions {
                if let Some(versions) = deltas_to_from.get(version) {
                    next_versions.extend(versions);
                }
            }

            // Now swap the next versions to be the current versions
            core::mem::swap(&mut cur_versions, &mut next_versions);
            next_versions.clear();
        }
    }

    if !failed.is_empty() || !violation_failed.is_empty() {
        writeln!(out, "Vetting Failed!")?;
        writeln!(out)?;
        if !failed.is_empty() {
            writeln!(out, "{} unvetted dependencies:", failed.len())?;
            for package in failed {
                writeln!(out, "  {}:{}", package.name, package.version)?;
            }
            writeln!(out)?;
        }
        if !violation_failed.is_empty() {
            writeln!(out, "{} forbidden dependencies:", violation_failed.len())?;
            for package in violation_failed {
                writeln!(out, "  {}:{}", package.name, package.version)?;
            }
            writeln!(out)?;
        }
        {
            writeln!(out, "recommended audits:")?;
            writeln!(out, "  [TODO]")?;
            writeln!(out)?;
        }
        writeln!(out, "Use |cargo vet certify| to record the audits.")?;
        std::process::exit(-1);
    }

    // TODO: I remember convincing myself that we "need" to save the lockfile
    // but I can't remember the reason anymore... let's just do it for now.
    trace!("Saving vetting results...");
    let lockfile_path = cfg.metadata.workspace_root.join("Cargo.lock");
    if lockfile_path.exists() {
        fs::copy(lockfile_path, store_path.join(VETTED_LOCK))?;
    } else {
        warn!("Couldn't find Cargo.lock to save!");
    }
    // Save the imports file back, in case we downloaded anything new
    // FIXME: should this be done earlier to avoid repeated network traffic on failed audits?
    store_imports(store_path, imports)?;

    writeln!(
        out,
        "Vetting Succeeded ({audited_count} audited, {unaudited_count} unaudited)"
    )?;

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

    let mut full_command = Cli::command();
    let mut todo = vec![&mut full_command];
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
    metadata.packages.iter().filter(|package| {
        package
            .source
            .as_ref()
            .map(|s| s.is_crates_io())
            .unwrap_or(false)
    })
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
    let path = store_path.join(AUDITS_TOML);
    let file: AuditsFile = load_toml(&path)?;
    file.validate()?;
    Ok(file)
}

fn load_config(store_path: &Path) -> Result<ConfigFile, VetError> {
    let path = store_path.join(CONFIG_TOML);
    let file: ConfigFile = load_toml(&path)?;
    file.validate()?;
    Ok(file)
}

fn load_imports(store_path: &Path) -> Result<ImportsFile, VetError> {
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
    _tmp: &Path,
    _fetch_dir: &str,
    crates: &[(&str, &str)],
) -> Result<PathBuf, VetError> {
    /* OLD Approach, might need some version of this for fallback...?
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
               writeln!(toml, r#"{} = "={}""#, krate, version)?;
           }
       }

       trace!("updated: {:#?}", fetch_toml);

       {
           let out = Command::new(&cfg.cargo)
               .current_dir(&fetch_dir)
               .arg("vendor")
               .output()?;

           if !out.status.success() {
               panic!(
                   "command failed!\nout:\n{}\nstderr:\n{}",
                   String::from_utf8(out.stdout).unwrap(),
                   String::from_utf8(out.stderr).unwrap()
               )
           }
       }
       // FIXME: delete the .cargo-checksum.json files (don't want to diff them, not real)

       let fetched = fetch_dir.join("vendor");
    */

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

fn diffstat_crate(
    _out: &mut dyn Write,
    _cfg: &Config,
    version1: &Path,
    version2: &Path,
) -> Result<DiffStat, VetError> {
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
            warn!("Could not load {name} @ {url} - {e}");
            continue;
        }
        let audit_file: Result<AuditsFile, _> = toml::from_str(&audit_txt.unwrap());
        if let Err(e) = audit_file {
            warn!("Could not parse {name} @ {url} - {e}");
            continue;
        }

        audits.insert(name.clone(), audit_file.unwrap());
    }

    Ok(ImportsFile { audits })
}

fn fetched_pkg(fetch_dir: &Path, name: &str, version: &str) -> PathBuf {
    let dir_name = format!("{}-{}", name, version);
    fetch_dir.join(dir_name)
}
