use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::io::{BufReader, Read};
use std::ops::Deref;
use std::path::Path;
use std::{fs::File, io::Write, panic, path::PathBuf};

use cargo_metadata::{Metadata, Package, Version, VersionReq};
use clap::{ArgEnum, CommandFactory, Parser, Subcommand};
use log::{error, info, trace};
use serde::de::Visitor;
use serde::{de, de::Deserialize, ser::Serialize};
use serde::{Deserializer, Serializer};
use simplelog::{
    ColorChoice, ConfigBuilder, Level, LevelFilter, TermLogger, TerminalMode, WriteLogger,
};

type StableMap<K, V> = linked_hash_map::LinkedHashMap<K, V>;
type VetError = Box<dyn Error>;

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

    /// Fetch the source of `$crate $version`
    #[clap(disable_version_flag = true)]
    Fetch(FetchArgs),

    /// Yield a diff against the last reviewed version.
    #[clap(disable_version_flag = true)]
    Diff(DiffArgs),

    /// Mark `$crate $version` as reviewed with `$message`
    #[clap(disable_version_flag = true)]
    Certify(CertifyArgs),

    /// Mark `$crate $version` as unacceptable with `$message`
    #[clap(disable_version_flag = true)]
    Forbid(ForbidArgs),

    /// Suggest some low-hanging fruit to review
    #[clap(disable_version_flag = true)]
    Suggest(SuggestArgs),

    /// ??? List audits mechanisms ???
    #[clap(disable_version_flag = true)]
    Audits(AuditsArgs),

    /// Print --help as markdown (for generating docs)
    #[clap(disable_version_flag = true)]
    #[clap(hide = true)]
    HelpMarkdown(HelpMarkdownArgs),
}

#[derive(clap::Args)]
struct InitArgs {}

#[derive(clap::Args)]
struct FetchArgs {
    krate: String,
    version: String,
}

#[derive(clap::Args)]
struct DiffArgs {}

#[derive(clap::Args)]
struct CertifyArgs {
    krate: String,
    version: String,
    message: String,
}

#[derive(clap::Args)]
struct ForbidArgs {
    krate: String,
    version: String,
    message: String,
}

#[derive(clap::Args)]
struct SuggestArgs {}

#[derive(clap::Args)]
struct AuditsArgs {}

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

#[derive(serde::Deserialize)]
struct Config {
    // Reserved for future use, if not present version=1 assumed.
    // (not sure whether this versions the format, or semantics, or...
    // for now assuming this species global semantics of some kind.
    version: Option<u64>,
    store: Option<Store>,
    audits: Option<Vec<String>>,
}
#[derive(serde::Deserialize)]
struct Store {
    path: Option<PathBuf>,
}

// FIXME: Probably want this to be a tree, and for queries to
// be keyed off the "current package" but unclear what that would *mean*
// so for now assume there is a linear chain of overrides. Possible
// that any "tree-like" situation wants to be an error...

/// All available configuration files, overlaying eachother.
/// Generally contains: `[Default, Workspace, Package]`
struct Configs(Vec<Config>);

impl Configs {
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
    fn audits(&self) -> Vec<&str> {
        self.0
            .iter()
            .flat_map(|cfg| cfg.audits.iter().flatten())
            .map(|a| &**a)
            .collect::<Vec<_>>()
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
    /// The assumed criteria for any audit that doesn't specify it.
    /// This key may be absent if there is only one criteria.
    #[serde(rename = "default-criteria")]
    default_criteria: Option<Vec<String>>,
    /// A map of criteria_name to criteria_description.
    criteria: StableMap<String, String>,
    /// Actual audits.
    audits: AuditedDependencies,
}

/// config.toml
#[derive(serde::Serialize, serde::Deserialize)]
struct ConfigFile {
    /// Remote audits.toml's that we trust and want to import.
    imports: StableMap<String, RemoteImport>,
    /// All of the "foreign" dependencies that we rely on but haven't audited yet.
    /// Foreign dependencies are just "things on crates.io", everything else
    /// (paths, git, etc) is assumed to be "under your control" and therefore implicitly trusted.
    unaudited: StableMap<String, UnauditedDependency>,
}

/// imports.lock, not sure what I want to put in here yet.
#[derive(serde::Serialize, serde::Deserialize)]
struct ImportsFile {
    audits: StableMap<String, AuditsFile>,
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
    version: VersionReq,
    /// Freeform notes, put whatever you want here. Just more stable/reliable than comments.
    notes: Option<String>,
}

/// This is just a big vague ball initially. It's up to the Audits/Unuadited/Trusted wrappers
/// to validate if it "makes sense" for their particular function.
#[derive(serde::Serialize, serde::Deserialize)]
struct AuditEntry {
    version: Option<Version>,
    delta: Option<Delta>,
    forbidden: Option<VersionReq>,
    who: Option<String>,
    notes: Option<String>,
    extra: Option<String>,
    criteria: Option<Vec<String>>,
    dependency_rules: Option<Vec<DependencyRule>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DependencyRule {
    /// ???
    require_criteria: Option<()>,
    /// ???
    pin_version: Option<()>,
    /// ???
    fold_audit: Option<()>,
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

static CARGO_ENV: &str = "CARGO";
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

    let cargo = std::env::var_os(CARGO_ENV);
    let mut cmd = cargo_metadata::MetadataCommand::new();
    if let Some(cargo) = cargo {
        cmd.cargo_path(cargo);
    }
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

    let default_config = Config {
        version: Some(1),
        store: Some(Store {
            path: Some(
                metadata
                    .workspace_root
                    .join(DEFAULT_STORE)
                    .into_std_path_buf(),
            ),
        }),
        audits: None,
    };

    let workspace_config = || -> Option<Config> {
        // FIXME: what is `store.path` relative to here?
        Config::deserialize(metadata.workspace_metadata.get(WORKSPACE_VET_CONFIG)?)
            .map_err(|e| {
                error!(
                    "Workspace had [{WORKSPACE_VET_CONFIG}] but it was malformed: {}",
                    e
                );
                std::process::exit(-1);
            })
            .ok()
    }();

    let package_config = || -> Option<Config> {
        // FIXME: what is `store.path` relative to here?
        Config::deserialize(metadata.root_package()?.metadata.get(PACKAGE_VET_CONFIG)?)
            .map_err(|e| {
                error!(
                    "Root package had [{PACKAGE_VET_CONFIG}] but it was malformed: {}",
                    e
                );
                std::process::exit(-1);
            })
            .ok()
    }();

    if workspace_config.is_some() && package_config.is_some() {
        error!("Both a workspace and a package defined [metadata.vet]! We don't know what that means, if you do, let us know!");
        std::process::exit(-1);
    }

    let mut configs = vec![default_config];
    if let Some(cfg) = workspace_config {
        configs.push(cfg);
    }
    if let Some(cfg) = package_config {
        configs.push(cfg);
    }
    let config = Configs(configs);

    info!("Final Config: ");
    info!("  - version: {}", config.version());
    info!("  - store.path: {:#?}", config.store_path());
    info!("  - audits: {:#?}", config.audits());

    //////////////////////////////////////////////////////
    // Run the actual command
    //////////////////////////////////////////////////////

    let init = is_init(&config);
    if matches!(cli.command, Some(Commands::Init { .. })) {
        if init {
            error!(
                "'cargo vet' already initialized (store found at {:#?})",
                config.store_path()
            );
            std::process::exit(-1);
        }
    } else if !init {
        error!(
            "You must run 'cargo vet init' (store not found at {:#?})",
            config.store_path()
        );
        std::process::exit(-1);
    }

    match &cli.command {
        Some(Commands::Init(sub_args)) => cmd_init(out, &cli, &config, &metadata, sub_args),
        Some(Commands::Fetch(sub_args)) => cmd_fetch(out, &cli, &config, &metadata, sub_args),
        Some(Commands::Certify(sub_args)) => cmd_certify(out, &cli, &config, &metadata, sub_args),
        Some(Commands::Forbid(sub_args)) => cmd_forbid(out, &cli, &config, &metadata, sub_args),
        Some(Commands::Suggest(sub_args)) => cmd_suggest(out, &cli, &config, &metadata, sub_args),
        Some(Commands::Diff(sub_args)) => cmd_diff(out, &cli, &config, &metadata, sub_args),
        Some(Commands::Audits(sub_args)) => cmd_audits(out, &cli, &config, &metadata, sub_args),
        Some(Commands::HelpMarkdown(sub_args)) => {
            cmd_help_markdown(out, &cli, &config, &metadata, sub_args)
        }
        None => cmd_vet(out, &cli, &config, &metadata),
    }
}

fn cmd_init(
    _out: &mut dyn Write,
    _cli: &Cli,
    config: &Configs,
    metadata: &Metadata,
    _sub_args: &InitArgs,
) -> Result<(), Box<dyn Error>> {
    // Initialize vet
    trace!("initializing...");

    let store_path = config.store_path();

    let audits_path = store_path.join(AUDITS_TOML);
    let config_path = store_path.join(CONFIG_TOML);
    let imports_path = store_path.join(IMPORTS_LOCK);

    // Create store_path
    // - audited.toml (empty)
    // - trusted.toml (skeleton?)
    // - unaudited.toml (populated with the full list of third-party crates)

    // In theory we don't need `all` here, but this allows them to specify
    // the store as some arbitrarily nested subdir for whatever reason
    // (maybe multiple parallel instances?)
    std::fs::create_dir_all(store_path)?;

    {
        trace!("initializing {:#?}", audits_path);

        let audits_struct = AuditsFile {
            default_criteria: None,
            criteria: [("reviewed".to_string(), "the code was reviewed".to_string())]
                .into_iter()
                .collect(),
            audits: StableMap::new(),
        };
        let audits_toml = toml::to_string_pretty(&audits_struct)?;

        let mut audits = File::create(&audits_path)?;

        writeln!(
            audits,
            r####"
# cargo-vet audited code
#
# Helpful Comment Explaining Format

{audits_toml}
"####
        )?;
    }

    {
        trace!("initializing {:#?}", imports_path);
        let imports_struct = ImportsFile {
            audits: StableMap::new(),
        };
        let imports_toml = toml::to_string_pretty(&imports_struct)?;
        let mut imports = File::create(&imports_path)?;
        writeln!(
            imports,
            r####"
# cargo-vet imports lockfile
#
# Helpful Comment Explaining Format

{imports_toml}
"####
        )?;
    }

    {
        trace!("initializing {:#?}", config_path);

        let mut dependencies = StableMap::new();
        for package in foreign_packages(metadata) {
            dependencies.insert(
                package.name.clone(),
                UnauditedDependency {
                    version: VersionReq::parse(&format!("={}", package.version))
                        .expect("Version wasn't a valid VersionReq??"),
                    notes: Some("automatically imported by 'cargo vet init'".to_string()),
                },
            );
        }
        // FIXME: probably shouldn't recycle this type, but just getting things working.
        let config_struct = ConfigFile {
            imports: StableMap::new(),
            unaudited: dependencies,
        };
        let config_toml = toml::to_string_pretty(&config_struct).unwrap();

        let mut config = File::create(&config_path)?;
        writeln!(
            config,
            r####"
# cargo-vet config.toml
#
# Helpful Comment Explaining Format

{config_toml}
"####
        )?;
    }

    Ok(())
}

fn cmd_fetch(
    _out: &mut dyn Write,
    _cli: &Cli,
    _config: &Configs,
    _metadata: &Metadata,
    __sub_args: &FetchArgs,
) -> Result<(), Box<dyn Error>> {
    // Download a crate's source to a temp location for review
    unimplemented!()
}

fn cmd_certify(
    _out: &mut dyn Write,
    _cli: &Cli,
    _config: &Configs,
    _metadata: &Metadata,
    _sub_args: &CertifyArgs,
) -> Result<(), Box<dyn Error>> {
    // Certify that you have reviewed a crate's source for some version / delta
    unimplemented!()
}

fn cmd_forbid(
    _out: &mut dyn Write,
    _cli: &Cli,
    _config: &Configs,
    _metadata: &Metadata,
    _sub_args: &ForbidArgs,
) -> Result<(), Box<dyn Error>> {
    // Forbid a crate's source for some version
    unimplemented!()
}

fn cmd_audits(
    _out: &mut dyn Write,
    _cli: &Cli,
    _config: &Configs,
    _metadata: &Metadata,
    _sub_args: &AuditsArgs,
) -> Result<(), Box<dyn Error>> {
    // ??? list audits? update audits?
    unimplemented!()
}
fn cmd_suggest(
    _out: &mut dyn Write,
    _cli: &Cli,
    _config: &Configs,
    _metadata: &Metadata,
    _sub_args: &SuggestArgs,
) -> Result<(), Box<dyn Error>> {
    // Suggest low-hanging-fruit reviews
    unimplemented!()
}
fn cmd_diff(
    _out: &mut dyn Write,
    _cli: &Cli,
    _config: &Configs,
    _metadata: &Metadata,
    _sub_args: &DiffArgs,
) -> Result<(), Box<dyn Error>> {
    // ??? diff something
    unimplemented!()
}

fn cmd_vet(
    out: &mut dyn Write,
    cli: &Cli,
    config: &Configs,
    metadata: &Metadata,
) -> Result<(), Box<dyn Error>> {
    // Run the checker to validate that the current set of deps is covered by the current cargo vet store
    trace!("vetting...");

    let store_path = config.store_path();
    let audit_inputs = config.audits();

    let audits = load_audits(store_path)?;
    let config = load_config(store_path)?;
    let imports = load_imports(store_path)?;

    // Update audits (trusted.toml)
    if !cli.locked && !audit_inputs.is_empty() {
        unimplemented!("fetching audits not yet implemented!");
    }

    let root_version = Version::new(0, 0, 0);
    let no_audits = Vec::new();

    let mut all_good = true;
    // Actually vet the dependencies
    'all_packages: for package in foreign_packages(metadata) {
        let unaudited = config.unaudited.get(&package.name);

        // Just merge all the entries from the foreign audit files and our audit file.
        let foreign_audits = imports
            .audits
            .values()
            .flat_map(|audit_file| audit_file.audits.get(&package.name).unwrap_or(&no_audits));
        let own_audits = audits.audits.get(&package.name).unwrap_or(&no_audits);

        let mut forbids = Vec::new();
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
            if let Some(forbid) = &entry.forbidden {
                forbids.push(forbid);
            }
        }

        // Reject forbidden packages
        //
        // TODO: should the "local" audit have a mechanism to override foreign forbids?
        // TODO: should forbids be applied during delta resolution, invalidating deltas?
        for forbid in &forbids {
            if forbid.matches(&package.version) {
                error!("forbidden package: {} {}", package.name, package.version);
            }
        }

        // Now try to resolve the deltas
        let mut cur_versions: HashSet<&Version> = [&package.version].into_iter().collect();
        let mut next_versions: HashSet<&Version> = HashSet::new();
        loop {
            // If there's no versions left to check, we've failed
            if cur_versions.is_empty() {
                error!("could not cerify {} {}", package.name, package.version);
                all_good = false;
            }

            // Check if we've succeeded
            for &version in &cur_versions {
                if let Some(allowed) = unaudited {
                    if allowed.version.matches(version) {
                        // Reached an explicitly unaudited package, that's good enough
                        continue 'all_packages;
                    }
                    if version == &root_version {
                        // Reached 0.0.0, which means we hit a Full Audit, that's perfect
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

    if !all_good {
        error!("some crates failed to vet");
        std::process::exit(-1);
    }

    // Fetch audits
    writeln!(out, "All crates vetted!")?;

    Ok(())
}

/// Perform crimes on clap long_help to generate markdown docs
fn cmd_help_markdown(
    out: &mut dyn Write,
    _cli: &Cli,
    _config: &Configs,
    _metadata: &Metadata,
    _sub_args: &HelpMarkdownArgs,
) -> Result<(), Box<dyn Error>> {
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

fn is_init(config: &Configs) -> bool {
    // Probably want to do more here later...
    config.store_path().exists()
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
