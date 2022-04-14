use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::io::{BufReader, Read};
use std::ops::Deref;
use std::path::Path;
use std::process::Command;
use std::{fmt, fs};
use std::{fs::File, io::Write, panic, path::PathBuf};

use cargo_metadata::{Metadata, Package, PackageId, Version, VersionReq};
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
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct AuditEntry {
    version: Option<Version>,
    delta: Option<Delta>,
    violation: Option<VersionReq>,
    who: Option<String>,
    notes: Option<String>,
    criteria: Option<Vec<String>>,
    dependency_criteria: Option<DependencyCriteria>,
}

/// A list of criteria that transitive dependencies must satisfy for this
/// audit to continue to be considered valid.
///
/// Example:
///
/// ```toml
/// dependency_criteria = { hmac: ['secure', 'crypto_reviewed'] }
/// ```
type DependencyCriteria = StableMap<String, Vec<String>>;

/// A "VERSION -> VERSION"
#[derive(Debug)]
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

/////////////////////////////////////////////////////////////////////////////////////////
/// Resolver Algorithm And Types (Probably Gonna Be Its Own File Later)
/////////////////////////////////////////////////////////////////////////////////////////

/// Set of booleans, 64 should be Enough For Anyone (but abstracting in case not).
#[derive(Clone)]
struct CriteriaSet(u64);
const MAX_CRITERIA: usize = u64::BITS as usize; // funnier this way

struct CriteriaMapper<'a> {
    list: Vec<(&'a str, &'a CriteriaEntry)>,
    index: HashMap<&'a str, usize>,
    default_criteria: CriteriaSet,
    implied_criteria: Vec<CriteriaSet>,
}

/// The dependency graph in a form we can use more easily.
pub struct DepGraph<'a> {
    pub package_list: &'a [Package],
    pub resolve_list: &'a [cargo_metadata::Node],
    pub package_index_by_pkgid: BTreeMap<&'a PackageId, usize>,
    pub resolve_index_by_pkgid: BTreeMap<&'a PackageId, usize>,
    pub pkgid_by_name_and_ver: HashMap<&'a str, HashMap<&'a Version, &'a PackageId>>,
    /// Toplogical sorting of the dependencies (linear iteration will do things in dependency order)
    pub topo_index: Vec<&'a PackageId>,
}

impl<'a> CriteriaMapper<'a> {
    fn new(criteria: &'a StableMap<String, CriteriaEntry>) -> CriteriaMapper<'a> {
        let list = criteria.iter().map(|(k, v)| (&**k, v)).collect::<Vec<_>>();
        let index = criteria
            .keys()
            .enumerate()
            .map(|(idx, v)| (&**v, idx))
            .collect();

        let mut default_criteria = CriteriaSet::none(list.len());
        let mut implied_criteria = Vec::with_capacity(list.len());
        for (idx, (_name, entry)) in list.iter().enumerate() {
            if entry.default {
                default_criteria.set_criteria(idx);
            }

            // Precompute implied criteria (doing it later is genuinely a typesystem headache)
            let mut implied = CriteriaSet::none(list.len());
            recursive_implies(&mut implied, &entry.implies, &index, &list);
            implied_criteria.push(implied);

            fn recursive_implies(
                result: &mut CriteriaSet,
                implies: &[String],
                index: &HashMap<&str, usize>,
                list: &[(&str, &CriteriaEntry)],
            ) {
                for implied in implies {
                    let idx = index[&**implied];
                    result.set_criteria(idx);

                    // FIXME: we should detect infinite implies loops?
                    let further_implies = &list[idx].1.implies[..];
                    recursive_implies(result, further_implies, index, list);
                }
            }
        }

        Self {
            list,
            index,
            default_criteria,
            implied_criteria,
        }
    }
    fn criteria_from_entry(&self, entry: &AuditEntry) -> CriteriaSet {
        if let Some(criteria_list) = entry.criteria.as_ref() {
            self.criteria_from_list(criteria_list.iter().map(|s| &**s))
        } else {
            self.default_criteria().clone()
        }
    }
    fn criteria_from_list<'b>(&self, list: impl IntoIterator<Item = &'b str>) -> CriteriaSet {
        let mut result = self.no_criteria();
        for criteria in list {
            let idx = self.index[criteria];
            result.set_criteria(idx);
            result.unioned_with(&self.implied_criteria[idx]);
        }
        result
    }
    fn set_criteria(&self, set: &mut CriteriaSet, criteria: &str) {
        set.set_criteria(self.index[criteria])
    }

    fn _criteria<'b>(
        &'b self,
        set: &'b CriteriaSet,
    ) -> impl Iterator<Item = (&'a str, &'a CriteriaEntry)> + 'b {
        self.list
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(idx, payload)| {
                if set._has_criteria(idx) {
                    Some(payload)
                } else {
                    None
                }
            })
    }
    fn len(&self) -> usize {
        self.list.len()
    }
    fn default_criteria(&self) -> &CriteriaSet {
        &self.default_criteria
    }
    fn no_criteria(&self) -> CriteriaSet {
        CriteriaSet::none(self.len())
    }
    fn all_criteria(&self) -> CriteriaSet {
        CriteriaSet::all(self.len())
    }
}

impl CriteriaSet {
    fn none(count: usize) -> Self {
        assert!(
            count <= MAX_CRITERIA,
            "{MAX_CRITERIA} was not Enough For Everyone ({count} criteria)"
        );
        CriteriaSet(0)
    }
    fn all(count: usize) -> Self {
        assert!(
            count <= MAX_CRITERIA,
            "{MAX_CRITERIA} was not Enough For Everyone ({count} criteria)"
        );
        if count == MAX_CRITERIA {
            CriteriaSet(!0)
        } else {
            // Bit Magic to get 'count' 1's
            CriteriaSet((1 << count) - 1)
        }
    }
    fn set_criteria(&mut self, idx: usize) {
        self.0 |= 1 << idx;
    }
    fn _has_criteria(&self, idx: usize) -> bool {
        (self.0 & (1 << idx)) != 0
    }
    fn intersected_with(&mut self, other: &CriteriaSet) {
        self.0 &= other.0;
    }
    fn unioned_with(&mut self, other: &CriteriaSet) {
        self.0 |= other.0;
    }
    fn contains(&self, other: &CriteriaSet) -> bool {
        (self.0 & other.0) == other.0
    }
    fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

impl<'a> DepGraph<'a> {
    pub fn new(metadata: &'a Metadata) -> Self {
        // FIXME: study the nature of the 'resolve' field more carefully.
        // In particular how resolver version 2 describes normal vs build/dev-deps.
        // Worst case we might need to invoke 'cargo metadata' multiple times to get
        // the proper description of both situations.

        let package_list = &*metadata.packages;
        let resolve_list = &*metadata
            .resolve
            .as_ref()
            .expect("cargo metadata did not yield resolve!")
            .nodes;
        let package_index_by_pkgid = package_list
            .iter()
            .enumerate()
            .map(|(idx, pkg)| (&pkg.id, idx))
            .collect();
        let resolve_index_by_pkgid = resolve_list
            .iter()
            .enumerate()
            .map(|(idx, pkg)| (&pkg.id, idx))
            .collect();
        let mut pkgid_by_name_and_ver = HashMap::<&str, HashMap<&Version, &PackageId>>::new();
        for pkg in package_list {
            pkgid_by_name_and_ver
                .entry(&*pkg.name)
                .or_default()
                .insert(&pkg.version, &pkg.id);
        }

        // Do topological sort: just recursively visit all of a node's children, and only add it
        // to the node *after* visiting the children. In this way we have trivially already added
        // all of the dependencies of a node by the time we have
        let mut topo_index = Vec::with_capacity(package_list.len());
        {
            // FIXME: cargo uses BTreeSet, PackageIds are long strings, so maybe this makes sense?
            let mut visited = BTreeMap::new();
            // All of the roots can be found in the workspace_members.
            // It's fine if some aren't roots, toplogical sort works even if do all nodes.
            // FIXME: is it better to actually use resolve.root? Seems like it won't
            // work right for workspaces with multiple roots!
            for pkgid in &metadata.workspace_members {
                visit_node(
                    &mut topo_index,
                    &mut visited,
                    &resolve_index_by_pkgid,
                    resolve_list,
                    pkgid,
                );
            }
            fn visit_node<'a>(
                topo_index: &mut Vec<&'a PackageId>,
                visited: &mut BTreeMap<&'a PackageId, ()>,
                resolve_index_by_pkgid: &BTreeMap<&'a PackageId, usize>,
                resolve_list: &'a [cargo_metadata::Node],
                pkgid: &'a PackageId,
            ) {
                // Don't revisit a node (fine for correctness, wasteful for perf)
                let query = visited.entry(pkgid);
                if matches!(query, std::collections::btree_map::Entry::Vacant(..)) {
                    query.or_insert(());
                    let node = &resolve_list[resolve_index_by_pkgid[pkgid]];
                    for child in &node.dependencies {
                        visit_node(
                            topo_index,
                            visited,
                            resolve_index_by_pkgid,
                            resolve_list,
                            child,
                        );
                    }
                    topo_index.push(pkgid);
                }
            }
        }

        Self {
            package_list,
            resolve_list,
            package_index_by_pkgid,
            resolve_index_by_pkgid,
            pkgid_by_name_and_ver,
            topo_index,
        }
    }
}

fn cmd_vet(out: &mut dyn Write, cfg: &Config) -> Result<(), VetError> {
    // Not sure which we want, so make it configurable to test.
    // Determines whether a delta must be == unaudited or just <=
    let unaudited_matching_is_strict = true;

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

    // Dummy values for corner cases
    let root_version = Version::new(0, 0, 0);
    let no_audits = Vec::new();
    let no_custom_dep_criteria = DependencyCriteria::new();

    let mut audited_count: u64 = 0;
    let mut unaudited_count: u64 = 0;
    let mut failed = vec![];
    let mut violation_failed = vec![];

    // A large part of our algorithm is unioning and intersecting criteria, so we map all
    // the criteria into indexed boolean sets (*whispers* an integer with lots of bits).
    let graph = DepGraph::new(&cfg.metadata);
    let criteria_mapper = CriteriaMapper::new(&audits.criteria);
    let all_criteria = criteria_mapper.all_criteria();
    let no_criteria = criteria_mapper.no_criteria();
    let mut via_audited = false;
    let mut via_unaudited = false;

    // This uses the same indexing pattern as graph.resolve_index_by_pkgid
    let mut vet_resolve_results = vec![no_criteria.clone(); graph.resolve_list.len()];

    // Actually vet the dependencies
    'all_packages: for pkgid in &graph.topo_index {
        let resolve_idx = graph.resolve_index_by_pkgid[pkgid];
        let resolve = &graph.resolve_list[resolve_idx];
        let package = &graph.package_list[graph.package_index_by_pkgid[pkgid]];

        // Implicitly trust non-third-parties
        let is_third_party = package
            .source
            .as_ref()
            .map(|s| s.is_crates_io())
            .unwrap_or(false);
        if !is_third_party {
            vet_resolve_results[resolve_idx].unioned_with(&all_criteria);
            continue;
        }
        let unaudited = config.unaudited.get(&package.name);

        // Just merge all the entries from the foreign audit files and our audit file.
        let foreign_audits = imports
            .audits
            .values()
            .flat_map(|audit_file| audit_file.audits.get(&package.name).unwrap_or(&no_audits));
        let own_audits = audits.audits.get(&package.name).unwrap_or(&no_audits);

        // Deltas are flipped so that we have a map of 'to: [froms]'. This lets
        // us start at the current version and look up all the deltas that *end* at that
        // version. By repeating this over and over, we can loslowly walk back in time until
        // we run out of deltas or reach full audit or an unaudited entry.
        let mut deltas_to =
            HashMap::<&Version, Vec<(&Version, CriteriaSet, HashMap<&str, CriteriaSet>)>>::new();
        let mut violations = Vec::new();

        // Collect up all the deltas, their criteria, and dependency_criteria
        for entry in own_audits.iter() {
            let criteria = criteria_mapper.criteria_from_entry(entry);
            // Convert all the custom criteria to CriteriaSets
            let dep_criteria: HashMap<_, _> = entry
                .dependency_criteria
                .as_ref()
                .unwrap_or(&no_custom_dep_criteria)
                .iter()
                .map(|(pkg_name, criteria)| {
                    (
                        &**pkg_name,
                        criteria_mapper.criteria_from_list(criteria.iter().map(|s| &**s)),
                    )
                })
                .collect();
            // For uniformity, model a Full Audit as `0.0.0 -> x.y.z`
            if let Some(ver) = &entry.version {
                deltas_to
                    .entry(ver)
                    .or_default()
                    .push((&root_version, criteria, dep_criteria));
            } else if let Some(delta) = &entry.delta {
                deltas_to
                    .entry(&delta.to)
                    .or_default()
                    .push((&delta.from, criteria, dep_criteria));
            } else if entry.violation.is_some() {
                violations.push(entry);
            }
        }

        // Try to map foreign audits into our worldview
        for (foreign_name, foreign_audits) in &imports.audits {
            // Prep CriteriaSet machinery for comparing requirements
            let foreign_criteria_mapper = CriteriaMapper::new(&foreign_audits.criteria);
            let criteria_map = &config
                .imports
                .get(foreign_name)
                .expect("Foreign Import isn't in config file (imports.lock outdated?)")
                .criteria_map;
            let criteria_map: Vec<(&str, CriteriaSet)> = criteria_map
                .iter()
                .map(|mapping| {
                    let set = foreign_criteria_mapper
                        .criteria_from_list(mapping.theirs.iter().map(|s| &**s));
                    (&*mapping.ours, set)
                })
                .collect();

            for entry in foreign_audits
                .audits
                .get(&package.name)
                .unwrap_or(&no_audits)
            {
                // TODO: figure out a reasonable way to map foreign dependency_criteria
                if entry.dependency_criteria.is_some() {
                    // Just discard this entry for now
                    warn!("discarding foreign audit with dependency_criteria (TODO)");
                    continue;
                }

                // Map this entry's criteria into our worldview
                let mut local_criteria = no_criteria.clone();
                let foreign_criteria = foreign_criteria_mapper.criteria_from_entry(entry);
                for (local_implied, foreign_required) in &criteria_map {
                    if foreign_criteria.contains(foreign_required) {
                        criteria_mapper.set_criteria(&mut local_criteria, local_implied);
                    }
                }

                // Now process it as normal
                if let Some(ver) = &entry.version {
                    deltas_to.entry(ver).or_default().push((
                        &root_version,
                        local_criteria,
                        Default::default(),
                    ));
                } else if let Some(delta) = &entry.delta {
                    deltas_to.entry(&delta.to).or_default().push((
                        &delta.from,
                        local_criteria,
                        Default::default(),
                    ));
                } else if entry.violation.is_some() {
                    violations.push(entry);
                }
            }
        }

        // Reject forbidden packages (violations)
        //
        // FIXME: should the "local" audit have a mechanism to override foreign forbids?
        for violation_entry in &violations {
            let violation_range = violation_entry.violation.as_ref().unwrap();
            // Hard error out if anything in our audits overlaps with a forbid entry!
            // (This clone isn't a big deal, it's just iterator adaptors for by-ref iteration)
            for entry in own_audits.iter().chain(foreign_audits.clone()) {
                if let Some(ver) = &entry.version {
                    if violation_range.matches(ver) {
                        error!(
                            "Integrity Failure! Audit and Violation Overlap for {}:",
                            package.name
                        );
                        error!("  audit: {:#?}", entry);
                        error!("  violation: {:#?}", violation_entry);
                        std::process::exit(-1);
                    }
                }
                if let Some(delta) = &entry.delta {
                    if violation_range.matches(&delta.from) || violation_range.matches(&delta.to) {
                        error!(
                            "Integrity Failure! Delta Audit and Violation Overlap for {}:",
                            package.name
                        );
                        error!("  audit: {:#?}", entry);
                        error!("  violation: {:#?}", violation_entry);
                        std::process::exit(-1);
                    }
                }
            }
            // Having current versions overlap with a violations is less horrifyingly bad,
            // so just gather them up as part of the normal report.
            if violation_range.matches(&package.version) {
                violation_failed.push(package);
                continue 'all_packages;
            }
        }

        // Now try to resolve the deltas
        let mut working_queue = vec![(&package.version, all_criteria.clone())];
        let mut validated_criteria = no_criteria.clone();

        while let Some((cur_version, cur_criteria)) = working_queue.pop() {
            // Check if we've succeeded
            if let Some(allowed) = unaudited {
                // Check if we've reached an 'unaudited' entry
                let reached_unaudited = allowed.iter().any(|allowed| {
                    if unaudited_matching_is_strict {
                        allowed.version == *cur_version
                    } else {
                        allowed.version >= *cur_version
                    }
                });
                if reached_unaudited {
                    // Reached an explicitly unaudited package, that's good enough
                    validated_criteria.unioned_with(&cur_criteria);
                    // FIXME: should this only be set if we followed no deltas?
                    via_unaudited = true;

                    // TODO: register this unaudited entry as "used" so we can warn
                    // about any entries that weren't used (security hazard).

                    // Just keep running the workqueue in case we find more criteria by other paths
                    continue;
                }
            }
            if cur_version == &root_version {
                // Reached 0.0.0, which means we hit a Full Audit, that's perfect
                validated_criteria.unioned_with(&cur_criteria);
                via_audited = true;

                // Just keep running the workqueue in case we find more criteria by other paths
                continue;
            }
            // Apply deltas to move along to the next "layer" of the search
            if let Some(deltas) = deltas_to.get(cur_version) {
                for (from_version, criteria, dep_criteria) in deltas {
                    let mut next_critera = cur_criteria.clone();
                    next_critera.intersected_with(criteria);

                    // Deltas should only apply if dependencies satisfy dep_criteria
                    let mut deps_satisfied = true;
                    for dependency in &resolve.dependencies {
                        let dep_resolve_idx = graph.resolve_index_by_pkgid[dependency];
                        let dep_package =
                            &graph.package_list[graph.package_index_by_pkgid[dependency]];
                        let dep_vet_result = &vet_resolve_results[dep_resolve_idx];

                        // If no custom criteria is specified, then require our dependency to match
                        // the same criteria that this delta claims to provide.
                        // e.g. a 'secure' audit requires all dependencies to be 'secure' by default.
                        let dep_req = dep_criteria.get(&*dep_package.name).unwrap_or(criteria);
                        if !dep_vet_result.contains(dep_req) {
                            deps_satisfied = false;
                            break;
                        }
                    }

                    if !next_critera.is_empty() && deps_satisfied {
                        working_queue.push((from_version, next_critera));
                    }
                }
            }
        }
        // TODO: now verify validated_criteria matches our policy
        let passed_policy = !validated_criteria.is_empty();

        if passed_policy {
            // hooray, we win! record the result in vet_resolve_results
            // so that our dependents can check what criteria we achieved.
            //
            // FIXME: this logic is going to cause cascading errors up the entire
            // dependency tree... do we really want that?
            vet_resolve_results[resolve_idx] = validated_criteria;

            // Log statistics
            if via_audited {
                audited_count += 1;
            } else if via_unaudited {
                unaudited_count += 1;
            } else {
                unreachable!("I have messed up the vet algorithm very badly...");
            }
        } else {
            failed.push(package);
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

    // Save the imports file back, in case we downloaded anything new
    // FIXME: should this be done earlier to avoid repeated network traffic on failed audits?
    trace!("Saving imports.lock...");
    store_imports(store_path, imports)?;

    writeln!(
        out,
        "Vetting Succeeded ({audited_count} audited, {unaudited_count} unaudited)"
    )?;

    Ok(())
}

////////////////////////////////////////////////////////////////////////////////////////////
/// End of Resolver
////////////////////////////////////////////////////////////////////////////////////////////

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

fn fetched_pkg(fetch_dir: &Path, name: &str, version: &str) -> PathBuf {
    let dir_name = format!("{}-{}", name, version);
    fetch_dir.join(dir_name)
}
