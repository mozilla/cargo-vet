use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io::{BufReader, Read};
use std::ops::Deref;
use std::path::Path;
use std::{fs::File, io::Write, panic, path::PathBuf};

use cargo_metadata::{Metadata, Package};
use clap::{ArgEnum, CommandFactory, Parser, Subcommand};
use log::{error, info, trace};
use serde::de::Visitor;
use serde::{de, de::Deserialize, ser::Serialize};
use serde::{Deserializer, Serializer};
use simplelog::{
    ColorChoice, ConfigBuilder, Level, LevelFilter, TermLogger, TerminalMode, WriteLogger,
};

type Version = cargo_metadata::Version;

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
    #[clap(short, long, arg_enum)]
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
    Init(InitArgs),
    /// Fetch the source of `$crate $version`
    Fetch(FetchArgs),
    /// Yield a diff against the last reviewed version.
    Diff(DiffArgs),
    /// Mark `$crate $version` as reviewed with `$message`
    Certify(CertifyArgs),
    /// Mark `$crate $version` as unacceptable with `$message`
    Forbid(ForbidArgs),
    /// Suggest some low-hanging fruit to review
    Suggest(SuggestArgs),
    /// ??? List audits mechanisms ???
    Audits(AuditsArgs),
    /// Print --help as markdown (for generating docs)
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

type Dependencies = BTreeMap<String, Vec<DependencyEntry>>;

#[derive(serde::Serialize, serde::Deserialize)]
struct Audited(Dependencies);

#[derive(serde::Serialize, serde::Deserialize)]
struct Unaudited(Dependencies);

#[derive(serde::Serialize, serde::Deserialize)]
struct Trusted(Dependencies);

/// This is just a big vague ball initially. It's up to the Audits/Unuadited/Trusted wrappers
/// to validate if it "makes sense" for their particular function.
#[derive(serde::Serialize, serde::Deserialize)]
struct DependencyEntry {
    forbidden: Option<Version>,
    version: Option<Version>,
    delta: Option<Delta>,
    who: Option<String>,
}

/// A "VERSION -> VERSION"
struct Delta {
    from: Version,
    to: Version,
}

impl Audited {
    fn new(deps: Dependencies) -> Self {
        // FIXME: produce errors for invalid DependencyEntries
        Self(deps)
    }
}
impl Unaudited {
    fn new(deps: Dependencies) -> Self {
        // FIXME: produce errors for invalid DependencyEntries
        Self(deps)
    }
}
impl Trusted {
    fn new(deps: Dependencies) -> Self {
        // FIXME: produce errors for invalid DependencyEntries
        Self(deps)
    }
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

static CARGO_ENV: &str = "CARGO";
static DEFAULT_STORE: &str = "supply-chain";
// package.metadata.vet
static PACKAGE_VET_CONFIG: &str = "vet";
// workspace.metadata.vet
static WORKSPACE_VET_CONFIG: &str = "vet";

static AUDITED_TOML: &str = "audited.toml";
static UNAUDITED_TOML: &str = "unaudited.toml";
static TRUSTED_TOML: &str = "trusted.toml";

// store = { path = './supply-chain' }
// audits = [
//  "https://raw.githubusercontent.com/rust-lang/cargo-trust-store/audited.toml",
//  "https://hg.example.org/example/raw-file/tip/audited.toml"
// ]

// supply-chain
// - audited.toml
// - trusted.toml
// - unaudited.toml

fn main() -> Result<(), Box<dyn Error>> {
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
        Some(Commands::HelpMarkdown(sub_args)) => cmd_help_markdown(out, &cli, &config, &metadata, sub_args),
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

    let audited_path = store_path.join(AUDITED_TOML);
    let trusted_path = store_path.join(TRUSTED_TOML);
    let unaudited_path = store_path.join(UNAUDITED_TOML);

    // Create store_path
    // - audited.toml (empty)
    // - trusted.toml (skeleton?)
    // - unaudited.toml (populated with the full list of third-party crates)

    // In theory we don't need `all` here, but this allows them to specify
    // the store as some arbitrarily nested subdir for whatever reason
    // (maybe multiple parallel instances?)
    std::fs::create_dir_all(store_path)?;

    {
        trace!("initializing {:#?}", audited_path);
        let mut audited = File::create(&audited_path)?;
        writeln!(
            audited,
            r####"
# cargo-vet audited code
#
# Helpful Comment Explaining Format                
"####
        )?;
    }

    {
        trace!("initializing {:#?}", trusted_path);
        let mut trusted = File::create(&trusted_path)?;
        writeln!(
            trusted,
            r####"
# cargo-vet trusted code
#
# Helpful Comment Explaining Format                
"####
        )?;
    }

    {
        trace!("initializing {:#?}", unaudited_path);

        let mut dependencies = BTreeMap::new();
        for package in foreign_packages(&metadata) {
            dependencies.insert(
                package.name.clone(),
                vec![DependencyEntry {
                    version: Some(package.version.clone()),
                    who: None,
                    forbidden: None,
                    delta: None,
                }],
            );
        }
        // FIXME: probably shouldn't recycle this type, but just getting things working.
        let dependencies = Audited::new(dependencies);
        let output = toml::to_string(&dependencies).unwrap();

        let mut unaudited = File::create(&unaudited_path)?;
        writeln!(
            unaudited,
            r####"
# cargo-vet unaudited code
#
# Helpful Comment Explaining Format                
"####
        )?;
        writeln!(unaudited, "{output}")?;
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

    let audited_path = store_path.join(AUDITED_TOML);
    let trusted_path = store_path.join(TRUSTED_TOML);
    let unaudited_path = store_path.join(UNAUDITED_TOML);

    let _audited = Audited::new(load_deps_toml(&audited_path)?);
    let unaudited = Unaudited::new(load_deps_toml(&unaudited_path)?);
    let _trusted = Trusted::new(load_deps_toml(&trusted_path)?);

    // Update audits (trusted.toml)
    if !cli.locked && !audit_inputs.is_empty() {
        unimplemented!("fetching audits not yet implemented!");
    }

    // TODO: do proper resolution on the 3 inputs.
    //
    // Relevant entries:
    // * unaudited.version: this entire version is unaudited, but implicitly trusted
    // * audited.forbid: this version is bad, do not use
    // * audited.version: this entire version has been reviewed
    // * audited.delta(x -> y): the changes from x to y 
    // * trusted.*: I think the same as audited.* but separate for logistics
    //   probably audited "overrides" trusted if they disagree? (via forbid?)
    //
    // If not for deltas, resolving packages would be fairly trivial.
    // *With* deltas I think we want to have some DAG-like analysis where you start
    // at the current version and look for a 'delta.to' that matches that version,
    // and then recursively check `delta.from'
    //
    // One thing that's unclear is what should happen if 'delta' hops *over* a version
    // i.e. if we have `audited.version = 5` and `audited.delta = 3 -> 7', does that
    // allow us to accept version 7? This is kind of an incoherent state but it seems
    // plausible with 'trusted' inputs imported from elsewhere!

    let mut all_good = true;
    // Actually vet the dependencies
    'all_packages: for package in foreign_packages(metadata) {
        if let Some(entries) = unaudited.0.get(&package.name) {
            for entry in entries {
                if entry.version.is_some() && entry.version.as_ref().unwrap() == &package.version {
                    continue 'all_packages;
                }
            }
        }

        all_good = false;
        error!(
            "Unregistered Package Version: {} {}",
            package.name, package.version
        );
    }

    if !all_good {
        std::process::exit(-1);
    }

    // Fetch audits
    writeln!(out, "All crates vetted!")?;

    Ok(())
}


fn cmd_help_markdown(
    out: &mut dyn Write,
    _cli: &Cli,
    _config: &Configs,
    _metadata: &Metadata,
    _sub_args: &HelpMarkdownArgs,
) -> Result<(), Box<dyn Error>> {

    // Make a new App to get the help message this time.


    writeln!(out, "# cargo-vet CLI manual")?;
    writeln!(out)?;
    writeln!(out, "> This manual can be regenerated with `cargo vet help-markdown`")?;
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
        let mut subcommand_name = format!("cargo vet {} ", command.get_name());

        if is_full_command {
            writeln!(out, "Version: `{version_line}`")?;
            writeln!(out)?;
            subcommand_name = String::new();
        } else {
            writeln!(out, "## {}", subcommand_name)?;
        }

        let mut in_subcommands_listing = false;
        for line in lines {
            // Use a trailing colon to indicate a heading
            if let Some(heading) = line.strip_suffix(':') {
                if !line.starts_with(' ') {
                    // SCREAMING headers are Main headings
                    if heading.to_ascii_uppercase() == heading {
                        if heading == "SUBCOMMANDS" {
                            in_subcommands_listing = true;
                        }
                        writeln!(out, "### {subcommand_name}{heading}")?;
                    } else {
                        writeln!(out, "### {heading}")?;
                    }
                    continue;
                }
            }

            // Usage strings get wrapped in full code blocks
            if line.starts_with("cargo-vet ") {
                writeln!(out, "```")?;
                writeln!(out, "{}", line)?;
                writeln!(out, "```")?;
                continue;
            }

            if in_subcommands_listing {
                if !line.starts_with("     ") {
                    // subcommand names are subheadings
                    let own_subcommand_name = line.trim();
                    write!(out, "* [{own_subcommand_name}](#cargo-vet-{own_subcommand_name}): ")?;
                    continue;
                }
            }
            // The rest is indented, get rid of that
            let line = line.trim();

            // argument names are subheadings
            if line.starts_with('-') || line.starts_with('<') {
                writeln!(out, "#### `{}`", line)?;
                continue;
            }

            // escape default/value strings
            if line.starts_with('[') {
                writeln!(out, "\\{}", line)?;
                continue;
            }

            // Normal paragraph text
            writeln!(out, "{}", line)?;
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

fn load_deps_toml(path: &Path) -> Result<Dependencies, Box<dyn Error>> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut string = String::new();
    reader.read_to_string(&mut string)?;
    let toml = toml::from_str(&string)?;
    Ok(toml)
}
