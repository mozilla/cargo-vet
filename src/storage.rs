use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Seek, Write},
    mem,
    path::{Path, PathBuf},
};

use cargo_metadata::Version;
use eyre::Context;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use tar::Archive;
use tracing::{log::warn, trace, trace_span};

use crate::{
    format::{
        AuditsFile, CommandHistory, ConfigFile, Delta, DiffCache, DiffStat, ImportsFile,
        MetaConfig, PackageStr, SortedMap, SortedSet,
    },
    resolver::{self, DiffRecommendation},
    Config, PartialConfig, VetError,
};

// tmp cache for various shenanigans
static TEMP_DIFF_CACHE: &str = "diff-cache.toml";
static TEMP_COMMAND_HISTORY: &str = "command-history.json";
static TEMP_EMPTY_PACKAGE: &str = "empty";
static TEMP_REGISTRY_SRC: &str = "packages";
static TEMP_LOCKFILE: &str = "lockfile";

// Various cargo values
static CARGO_REGISTRY: &str = "registry";
static CARGO_REGISTRY_SRC: &str = "src";
static CARGO_REGISTRY_CACHE: &str = "cache";
static CARGO_OK_FILE: &str = ".cargo-ok";
static CARGO_OK_BODY: &str = "ok";

pub static DEFAULT_STORE: &str = "supply-chain";

static AUDITS_TOML: &str = "audits.toml";
static CONFIG_TOML: &str = "config.toml";
static IMPORTS_LOCK: &str = "imports.lock";
static STORE_LOCKFILE: &str = "lockfile";

pub struct FileLock {
    path: PathBuf,
}

impl FileLock {
    pub fn acquire(path: impl Into<PathBuf>) -> Result<Self, VetError> {
        // TODO: learn how to do this more robustly
        // TODO: should we hold onto the file to avoid anyone deleting it?
        // Or drop it right away to make it easier to cleanup if something goes wrong?
        let path = path.into();
        // ERRORS: arguably this is totally recoverable... maybe
        //
        // For Cache you can theoretically do some things without it (it's just "nice to have")
        // but that kind of logic isn't yet implemented.
        //
        // For Store this would be basically immediately fatal (but that's the store's problem).
        let _lock = File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("Could not acquire lockfile at {}", path.display()))?;

        Ok(Self { path })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // Try to clean up the lock
        std::fs::remove_file(&self.path)
            .unwrap_or_else(|_| panic!("Couldn't delete file lock!? {}", self.path.display()));
    }
}

/// The store (typically `supply-chain/`)
///
/// All access to this directory should be managed by this type to avoid races.
/// By default, modifications to this type will not be written back to the store
/// because we don't generally want to write back any results unless everything
/// goes perfectly.
///
/// To write back this value, use [`Store::commit`][].
pub struct Store {
    /// Repo-global lock over the store, will be None if we're mocking.
    _lock: Option<FileLock>,
    /// Path to the root of the store
    root: Option<PathBuf>,

    // Contents of the store, eagerly loaded and already validated.
    pub config: ConfigFile,
    pub imports: ImportsFile,
    pub audits: AuditsFile,
}

impl Store {
    /// Create a new store (files will be completely empty, must be committed for files to be created)
    pub fn create(cfg: &Config) -> Result<Self, VetError> {
        let root = cfg.metacfg.store_path();
        std::fs::create_dir(&root).with_context(|| {
            format!(
                "Couldn't create cargo-vet Store because it already exists at {}",
                root.display()
            )
        })?;

        let lock = if cfg.cli.readonly_lockless {
            None
        } else {
            Some(FileLock::acquire(root.join(STORE_LOCKFILE))?)
        };

        Ok(Self {
            _lock: lock,
            root: Some(root.to_owned()),

            config: ConfigFile {
                default_criteria: String::new(),
                imports: SortedMap::new(),
                policy: SortedMap::new(),
                unaudited: SortedMap::new(),
            },
            imports: ImportsFile {
                audits: SortedMap::new(),
            },
            audits: AuditsFile {
                criteria: SortedMap::new(),
                audits: SortedMap::new(),
            },
        })
    }

    pub fn is_init(metacfg: &MetaConfig) -> bool {
        // Probably want to do more here later...
        metacfg.store_path().exists()
    }

    /// Acquire an existing store
    pub fn acquire(cfg: &Config) -> Result<Self, VetError> {
        let root = cfg.metacfg.store_path().to_owned();
        // Before we do anything, acquire the lockfile to get exclusive access
        let lock = if cfg.cli.readonly_lockless {
            None
        } else {
            Some(FileLock::acquire(root.join(STORE_LOCKFILE))?)
        };

        let config = load_config(&root)?;
        let audits = load_audits(&root)?;
        let imports = load_imports(&root)?;

        let root = if cfg.cli.readonly_lockless {
            None
        } else {
            Some(root)
        };

        let store = Self {
            _lock: lock,
            root,

            config,
            audits,
            imports,
        };

        // Check that the store isn't corrupt
        store.validate()?;

        Ok(store)
    }

    /// Create a mock store
    #[cfg(test)]
    pub fn mock(config: ConfigFile, audits: AuditsFile, imports: ImportsFile) -> Self {
        Self {
            _lock: None,
            root: None,

            config,
            imports,
            audits,
        }
    }

    /// Commit the store's contents back to disk
    pub fn commit(self) -> Result<(), VetError> {
        // TODO: make this truly transactional?
        // (With a dir rename? Does that work with the _lock? Fine because it's already closed?)
        if let Some(root) = self.root {
            store_audits(&root, self.audits)?;
            store_config(&root, self.config)?;
            store_imports(&root, self.imports)?;
        }
        Ok(())
    }

    /// Validate the store's integrity
    pub fn validate(&self) -> Result<(), VetError> {
        // ERRORS: ideally these are all gathered diagnostics, want to report as many errors
        // at once as possible!

        // TODO(#66): implement validation
        //
        // * check that policy entries are only first-party
        // * check that unaudited entries are for things that exist?
        // * check that lockfile and imports aren't desync'd (catch new/removed import urls)
        //
        // * check that each CriteriaEntry has 'description' or 'description_url'
        // * check that no one is trying to shadow builtin criteria (safe-to-run, safe-to-deploy)
        // * check that all criteria are valid in:
        //   * CriteriaEntry::implies
        //   * AuditEntry::criteria
        //   * DependencyCriteria
        // * check that all 'audits' entries are well-formed
        // * check that all package names are valid (with crates.io...?)
        // * check that all reviews have a 'who' (currently an Option to stub it out)
        // * catch no-op deltas?
        Ok(())
    }

    /// Fetch foreign audits, only call this is we're not --locked
    pub fn fetch_foreign_audits(&mut self) -> Result<(), VetError> {
        let mut audits = SortedMap::new();
        for (name, import) in &self.config.imports {
            let url = &import.url;
            // FIXME: this should probably be async but that's a Whole Thing and these files are small.
            let audit_txt = reqwest::blocking::get(url).and_then(|r| r.text());
            if let Err(e) = audit_txt {
                // ERRORS: gathered diagnostic, we should find all the fetch errors at once
                return Err(eyre::eyre!("Could not load {name} @ {url} - {e}"));
            }
            let audit_file: Result<AuditsFile, _> = toml::from_str(&audit_txt.unwrap());
            if let Err(e) = audit_file {
                // ERRORS: gathered diagnostic, we should find all the fetch errors at once
                return Err(eyre::eyre!("Could not parse {name} @ {url} - {e}"));
            }
            audits.insert(name.clone(), audit_file.unwrap());
        }

        let new_imports = ImportsFile { audits };
        // TODO(#68): error out if the criteria changed

        // Accept the new imports. These will only be committed if the current command succeeds.
        self.imports = new_imports;

        // Now do one last validation to catch corrupt imports
        self.validate()?;
        Ok(())
    }
}

/// The cache where we store globally shared artifacts like fetched packages and diffstats
///
/// All access to this directory should be managed by this type to avoid races.
pub struct Cache {
    /// System-global lock over the cache, will be None if we're mocking.
    _lock: Option<FileLock>,
    /// Path to the root of the cache
    root: Option<PathBuf>,
    /// Cargo's crates.io package registry (in CARGO_HOME) for us to query opportunistically
    cargo_registry: Option<CargoRegistry>,
    /// Path to the DiffCache (for when we want to save it back)
    diff_cache_path: Option<PathBuf>,
    /// The loaded DiffCache, will be written back on Drop
    pub diff_cache: DiffCache,
    /// Path to the CommandHistory (for when we want to save it back)
    command_history_path: Option<PathBuf>,
    /// Command history to provide some persistent magic smarts
    pub command_history: CommandHistory,
}

/// A Registry in CARGO_HOME (usually the crates.io one)
pub struct CargoRegistry {
    /// The base path all registries share
    base_dir: PathBuf,
    /// The name of the registry
    registry: OsString,
}

impl CargoRegistry {
    /// Get the src dir of this registry (unpacked fetches)
    pub fn src(&self) -> PathBuf {
        self.base_dir.join(CARGO_REGISTRY_SRC).join(&self.registry)
    }
    /// Get the cache dir of the registry (.crate packed fetches)
    pub fn cache(&self) -> PathBuf {
        self.base_dir
            .join(CARGO_REGISTRY_CACHE)
            .join(&self.registry)
    }
    // Could also include the index, not reason to do that yet
}

impl Drop for Cache {
    fn drop(&mut self) {
        if let Some(diff_cache_path) = &self.diff_cache_path {
            // Write back the diff_cache
            store_diff_cache(diff_cache_path, mem::take(&mut self.diff_cache)).unwrap();
        }
        if let Some(command_history_path) = &self.command_history_path {
            // Write back the command_history
            store_command_history(command_history_path, mem::take(&mut self.command_history))
                .unwrap();
        }
        // `_lock: FileLock` implicitly released here
    }
}

impl Cache {
    /// Acquire the cache
    pub fn acquire(cfg: &PartialConfig) -> Result<Self, VetError> {
        if cfg.cargo_home.is_none() {
            // If the registry_src isn't set, then assume we're running in tests and mocked.
            // In that case, don't read/write disk for the DiffCache
            return Ok(Cache {
                _lock: None,
                root: None,
                cargo_registry: None,
                diff_cache_path: None,
                diff_cache: DiffCache::new(),
                command_history_path: None,
                command_history: CommandHistory::default(),
            });
        }

        let root = cfg.tmp.clone();
        let empty = root.join(TEMP_EMPTY_PACKAGE);
        let packages: PathBuf = root.join(TEMP_REGISTRY_SRC);

        // Make sure our cache exists
        if !root.exists() {
            fs::create_dir_all(&root)?;
        }
        // Now acquire the lockfile
        let lock = if cfg.cli.readonly_lockless {
            None
        } else {
            Some(FileLock::acquire(root.join(TEMP_LOCKFILE))?)
        };

        // Make sure everything else exists
        if !empty.exists() {
            fs::create_dir_all(&empty)?;
        }
        if !packages.exists() {
            fs::create_dir_all(&packages)?;
        }

        // Setup the diff_cache.
        let diff_cache_path = cfg
            .cli
            .diff_cache
            .clone()
            .unwrap_or_else(|| root.join(TEMP_DIFF_CACHE));
        let diff_cache = if let Ok(cache) = load_diff_cache(&diff_cache_path) {
            cache
        } else {
            // Might be our first run, create a fresh diff-cache that we'll write back at the end
            DiffCache::new()
        };

        // Setup the command_history.
        let command_history_path = root.join(TEMP_COMMAND_HISTORY);
        let command_history =
            if let Ok(command_history) = load_command_history(&command_history_path) {
                command_history
            } else {
                // Might be our first run, create a fresh command_history that we'll write back at the end
                CommandHistory::default()
            };

        // Try to get the cargo registry
        let cargo_registry = find_cargo_registry(cfg);
        if let Err(e) = &cargo_registry {
            // ERRORS: this warning really rides the line, I'm not sure if the user can/should care
            warn!("Couldn't find cargo registry: {e}");
        }

        Ok(Self {
            _lock: lock,
            root: Some(root),
            diff_cache_path: Some(diff_cache_path),
            diff_cache,
            command_history_path: Some(command_history_path),
            command_history,
            cargo_registry: cargo_registry.ok(),
        })
    }

    pub fn fetch_packages<'a>(
        &mut self,
        packages: &[(PackageStr<'a>, &'a Version)],
    ) -> Result<SortedMap<PackageStr<'a>, SortedMap<&'a Version, PathBuf>>, VetError> {
        let _span = trace_span!("fetch-packages").entered();
        // Don't do anything if we're mocked, or there is no work to do
        if self.root.is_none() || packages.is_empty() {
            return Ok(SortedMap::new());
        }

        let root = self.root.as_ref().unwrap();
        let fetch_dir = root.join(TEMP_REGISTRY_SRC);
        let cargo_registry = self.cargo_registry.as_ref();

        let mut paths = SortedMap::<PackageStr, SortedMap<&Version, PathBuf>>::new();
        let mut to_download = Vec::new();

        // Get all the cached things / find out what needs to be downloaded.
        for (name, version) in packages {
            let path = if **version == resolver::ROOT_VERSION {
                // Empty package
                root.join(TEMP_EMPTY_PACKAGE)
            } else {
                // First try to get a cached copy from cargo's register or our own
                let dir_name = format!("{}-{}", name, version);

                let cached = cargo_registry
                    .map(|reg| reg.src().join(&dir_name))
                    .filter(|path| fetch_is_ok(path))
                    .unwrap_or_else(|| fetch_dir.join(&dir_name));

                if !fetch_is_ok(&cached) {
                    // If we don't have a cached copy, push this to the download queue
                    to_download.push((name, version, cached.clone()));
                }

                // Either this path exists or we'll download it, either way, it's right
                cached
            };

            paths.entry(name).or_default().insert(version, path);
        }

        if !to_download.is_empty() {
            trace!("downloading {} packages", to_download.len());
        }
        // If there is anything to download, do it
        for (name, version, to_dir) in to_download {
            trace!("  downloading {}:{} to {}", name, version, to_dir.display());
            // FIXME: make this all async instead of blocking
            self.download_package(name, version, &to_dir)?;
        }

        trace!("all fetched!");

        Ok(paths)
    }

    pub fn fetch_and_diffstat_all(
        &mut self,
        package: PackageStr,
        diffs: &SortedSet<Delta>,
    ) -> Result<DiffRecommendation, VetError> {
        let _span = trace_span!("diffstat-all").entered();
        // If there's no registry path setup, assume we're in tests and mocking.
        let mut all_versions = SortedSet::new();

        for delta in diffs {
            let is_cached = self
                .diff_cache
                .get(package)
                .and_then(|cache| cache.get(delta))
                .is_some();
            if !is_cached {
                all_versions.insert(&delta.from);
                all_versions.insert(&delta.to);
            }
        }

        let mut best_rec: Option<DiffRecommendation> = None;
        let to_fetch = all_versions
            .iter()
            .map(|v| (package, *v))
            .collect::<Vec<_>>();
        let fetches = self.fetch_packages(&to_fetch)?;

        for delta in diffs {
            let cached = self
                .diff_cache
                .get(package)
                .and_then(|cache| cache.get(delta))
                .cloned();

            let diffstat = if let Some(cached) = cached {
                // Hooray, we have the cached result!
                cached
            } else {
                let from = fetches.get(package).and_then(|m| m.get(&delta.from));
                let to = fetches.get(package).and_then(|m| m.get(&delta.to));

                if let (Some(from), Some(to)) = (from, to) {
                    // Have fetches, do a real diffstat
                    let diffstat = crate::diffstat_crate(from, to)?;
                    self.diff_cache
                        .entry(package.to_string())
                        .or_insert(SortedMap::new())
                        .insert(delta.clone(), diffstat.clone());
                    diffstat
                } else {
                    // If we don't have fetches, assume we want mocked results
                    // ERRORS: this warning really rides the line, I'm not sure if the user can/should care
                    warn!("Missing fetches, assuming we're in tests and mocking");

                    let from_len = delta.from.major * delta.from.major;
                    let to_len: u64 = delta.to.major * delta.to.major;
                    let diff = to_len as i64 - from_len as i64;
                    let count = diff.unsigned_abs();
                    let raw = if diff < 0 {
                        format!("-{}", count)
                    } else {
                        format!("+{}", count)
                    };
                    DiffStat { raw, count }
                }
            };

            let rec = DiffRecommendation {
                from: delta.from.clone(),
                to: delta.to.clone(),
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

        Ok(best_rec.unwrap())
    }

    fn download_package(
        &mut self,
        package: PackageStr,
        version: &Version,
        to_dir: &Path,
    ) -> Result<(), VetError> {
        // Download to an anonymous temp file
        let url = format!("https://crates.io/api/v1/crates/{package}/{version}/download");
        let mut tempfile = tempfile::tempfile()?;
        let bytes = reqwest::blocking::get(url).and_then(|r| r.bytes())?;
        tempfile.write_all(&bytes[..])?;
        tempfile.rewind()?;

        // Now unpack it
        self.unpack_package(&tempfile, to_dir)?;

        Ok(())
    }

    fn unpack_package(&mut self, tarball: &File, unpack_dir: &Path) -> Result<(), VetError> {
        // If we get here and the unpack_dir exists, this implies we had a previously failed fetch,
        // blast it away so we can have a clean slate!
        if unpack_dir.exists() {
            fs::remove_dir_all(unpack_dir)?;
        }
        fs::create_dir(unpack_dir)?;
        let lockfile = unpack_dir.join(CARGO_OK_FILE);
        let gz = GzDecoder::new(tarball);
        let mut tar = Archive::new(gz);
        let prefix = unpack_dir.file_name().unwrap();
        let parent = unpack_dir.parent().unwrap();
        for entry in tar.entries()? {
            let mut entry = entry.wrap_err("failed to iterate over archive")?;
            let entry_path = entry
                .path()
                .wrap_err("failed to read entry path")?
                .into_owned();

            // We're going to unpack this tarball into the global source
            // directory, but we want to make sure that it doesn't accidentally
            // (or maliciously) overwrite source code from other crates. Cargo
            // itself should never generate a tarball that hits this error, and
            // crates.io should also block uploads with these sorts of tarballs,
            // but be extra sure by adding a check here as well.
            if !entry_path.starts_with(prefix) {
                return Err(eyre::eyre!(
                    "invalid tarball downloaded, contains \
                        a file at {} which isn't under {}",
                    entry_path.display(),
                    prefix.to_string_lossy()
                ));
            }
            // Unpacking failed
            let result = entry.unpack_in(parent).map_err(VetError::from);
            result.wrap_err_with(|| {
                format!("failed to unpack entry at `{}`", entry_path.display())
            })?;
        }

        // The lock file is created after unpacking so we overwrite a lock file
        // which may have been extracted from the package.
        let mut ok = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lockfile)
            .wrap_err_with(|| format!("failed to open `{}`", lockfile.display()))?;

        // Write to the lock file to indicate that unpacking was successful.
        write!(ok, "ok")?;

        Ok(())
    }
}

fn fetch_is_ok(fetch: &Path) -> bool {
    if !fetch.exists() || !fetch.is_dir() {
        return false;
    }

    let ok_contents = || -> Result<String, std::io::Error> {
        let mut ok_file = File::open(fetch.join(CARGO_OK_FILE))?;
        let mut contents = String::new();
        ok_file.read_to_string(&mut contents)?;
        Ok(contents)
    };

    if let Ok(ok) = ok_contents() {
        ok == CARGO_OK_BODY
    } else {
        false
    }
}

fn find_cargo_registry(cfg: &PartialConfig) -> Result<CargoRegistry, VetError> {
    // ERRORS: all of this is genuinely fallible internal workings

    // Find the cargo registry
    //
    // This is all unstable nonsense so being a bit paranoid here so that we can notice
    // when things get weird and understand corner cases better...
    if cfg.cargo_home.is_none() {
        return Err(eyre::eyre!("Could not resolve CARGO_HOME!?"));
    }

    let base_dir = cfg.cargo_home.as_ref().unwrap().join(CARGO_REGISTRY);
    let registry_src = base_dir.join(CARGO_REGISTRY_SRC);
    if !registry_src.exists() {
        return Err(eyre::eyre!("Cargo registry src cache doesn't exist!?"));
    }

    // There's some weird opaque directory name here, so no hardcoding of the path
    let mut registry = None;
    for entry in std::fs::read_dir(registry_src)? {
        let entry = entry?;
        let path = entry.path();
        let dir_name = path.file_name().unwrap().to_owned();
        if path.is_dir() {
            if registry.is_some() {
                // ERRORS: these warnings really ride the line, not sure the user can/should care
                warn!("Found multiple subdirectories in CARGO_HOME/registry/src");
                warn!("  Preferring any named github.com-*");
                if dir_name.to_string_lossy().starts_with("github.com-") {
                    registry = Some(dir_name);
                }
            } else {
                registry = Some(dir_name);
            }
        }
    }

    if let Some(registry) = registry {
        Ok(CargoRegistry { base_dir, registry })
    } else {
        Err(eyre::eyre!("failed to find cargo package sources"))
    }
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
fn load_json<T>(path: &Path) -> Result<T, VetError>
where
    T: for<'a> Deserialize<'a>,
{
    let mut reader = BufReader::new(File::open(path)?);
    let mut string = String::new();
    reader.read_to_string(&mut string)?;
    let json = serde_json::from_str(&string)?;
    Ok(json)
}
fn store_json<T>(path: &Path, val: T) -> Result<(), VetError>
where
    T: Serialize,
{
    // FIXME: do this in a temp file and swap it into place to avoid corruption?
    let json_string = serde_json::to_string(&val)?;
    let mut output = File::create(path)?;
    writeln!(&mut output, "{}", json_string)?;
    Ok(())
}

fn load_audits(store_path: &Path) -> Result<AuditsFile, VetError> {
    // TODO: do integrity checks? (for things like criteria keys being valid)
    let path = store_path.join(AUDITS_TOML);
    let file: AuditsFile = load_toml(&path)?;
    Ok(file)
}

fn load_config(store_path: &Path) -> Result<ConfigFile, VetError> {
    // TODO: do integrity checks?
    let path = store_path.join(CONFIG_TOML);
    let file: ConfigFile = load_toml(&path)?;
    Ok(file)
}

fn load_imports(store_path: &Path) -> Result<ImportsFile, VetError> {
    // TODO: do integrity checks?
    let path = store_path.join(IMPORTS_LOCK);
    let file: ImportsFile = load_toml(&path)?;
    Ok(file)
}

fn load_diff_cache(diff_cache_path: &Path) -> Result<DiffCache, VetError> {
    let file: DiffCache = load_toml(diff_cache_path)?;
    Ok(file)
}
fn load_command_history(command_history_path: &Path) -> Result<CommandHistory, VetError> {
    let file: CommandHistory = load_json(command_history_path)?;
    Ok(file)
}

fn store_audits(store_path: &Path, mut audits: AuditsFile) -> Result<(), VetError> {
    let heading = r###"
# cargo-vet audits file
"###;
    audits
        .audits
        .values_mut()
        .for_each(|entries| entries.sort());

    let path = store_path.join(AUDITS_TOML);
    store_toml(&path, heading, audits)?;
    Ok(())
}
fn store_config(store_path: &Path, mut config: ConfigFile) -> Result<(), VetError> {
    config
        .unaudited
        .values_mut()
        .for_each(|entries| entries.sort());

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
fn store_diff_cache(diff_cache_path: &Path, diff_cache: DiffCache) -> Result<(), VetError> {
    let heading = "";

    store_toml(diff_cache_path, heading, diff_cache)?;
    Ok(())
}
fn store_command_history(
    command_history_path: &Path,
    command_history: CommandHistory,
) -> Result<(), VetError> {
    store_json(command_history_path, command_history)?;
    Ok(())
}
