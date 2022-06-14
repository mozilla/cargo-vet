use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Read, Seek, Write},
    mem,
    path::{Path, PathBuf},
    sync::Arc,
};

use cargo_metadata::Version;
use crates_index::Index;
use eyre::Context;
use flate2::read::GzDecoder;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use tar::Archive;
use tracing::{error, log::warn, trace, trace_span};

use crate::{
    flock::{FileLock, Filesystem},
    format::{
        AuditsFile, CommandHistory, ConfigFile, Delta, DiffCache, DiffStat, ImportsFile,
        MetaConfig, PackageName, PackageStr, SortedMap, SortedSet,
    },
    network::Network,
    resolver::{self, DiffRecommendation},
    serialization::to_formatted_toml,
    Config, PartialConfig, VetError,
};

// tmp cache for various shenanigans
static TEMP_DIFF_CACHE: &str = "diff-cache.toml";
static TEMP_COMMAND_HISTORY: &str = "command-history.json";
static TEMP_EMPTY_PACKAGE: &str = "empty";
static TEMP_REGISTRY_SRC: &str = "src";
static TEMP_REGISTRY_CACHE: &str = "cache";
static TEMP_VET_LOCK: &str = ".vet-lock";

// Various cargo values
static CARGO_REGISTRY_SRC: &str = "src";
static CARGO_REGISTRY_CACHE: &str = "cache";
static CARGO_OK_FILE: &str = ".cargo-ok";
static CARGO_OK_BODY: &str = "ok";

pub static DEFAULT_STORE: &str = "supply-chain";

static AUDITS_TOML: &str = "audits.toml";
static CONFIG_TOML: &str = "config.toml";
static IMPORTS_LOCK: &str = "imports.lock";

struct StoreLock {
    config: FileLock,
}

impl StoreLock {
    fn new(store: &Filesystem) -> Result<Self, VetError> {
        Ok(StoreLock {
            config: store.open_rw(CONFIG_TOML, "vet store")?,
        })
    }
    fn read_config(&self) -> io::Result<impl Read + '_> {
        let mut file = self.config.file();
        file.rewind()?;
        Ok(file)
    }
    fn write_config(&self) -> io::Result<impl Write + '_> {
        let mut file = self.config.file();
        file.rewind()?;
        file.set_len(0)?;
        Ok(file)
    }
    fn read_audits(&self) -> io::Result<impl Read> {
        File::open(self.config.parent().join(AUDITS_TOML))
    }
    fn write_audits(&self) -> io::Result<impl Write> {
        File::create(self.config.parent().join(AUDITS_TOML))
    }
    fn read_imports(&self) -> io::Result<impl Read> {
        File::open(self.config.parent().join(IMPORTS_LOCK))
    }
    fn write_imports(&self) -> io::Result<impl Write> {
        File::create(self.config.parent().join(IMPORTS_LOCK))
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
    // Exclusive file lock held for the config file
    lock: Option<StoreLock>,

    // Contents of the store, eagerly loaded and already validated.
    pub config: ConfigFile,
    pub imports: ImportsFile,
    pub audits: AuditsFile,
}

impl Store {
    /// Create a new store (files will be completely empty, must be committed for files to be created)
    pub fn create(cfg: &Config) -> Result<Self, VetError> {
        let root = cfg.metacfg.store_path();
        root.create_dir()?;

        let lock = StoreLock::new(&root)?;

        Ok(Self {
            lock: Some(lock),
            config: ConfigFile {
                default_criteria: String::new(),
                imports: SortedMap::new(),
                policy: SortedMap::new(),
                unaudited: SortedMap::new(),
                audit_as_crates_io: SortedMap::new(),
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
        metacfg.store_path().as_path_unlocked().exists()
    }

    /// Acquire an existing store
    pub fn acquire(cfg: &Config) -> Result<Self, VetError> {
        let root = cfg.metacfg.store_path();

        // Before we do anything else, acquire an exclusive lock on the
        // config.toml file in the store.
        // XXX: Consider acquiring a non-exclusive lock in cases where an
        // exclusive one isn't needed.
        let lock = StoreLock::new(&root)?;

        let config: ConfigFile = load_toml(lock.read_config()?)?;
        let audits: AuditsFile = load_toml(lock.read_audits()?)?;
        let imports: ImportsFile = load_toml(lock.read_imports()?)?;

        let store = Self {
            lock: Some(lock),
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
            lock: None,
            config,
            imports,
            audits,
        }
    }

    /// Commit the store's contents back to disk
    pub fn commit(self) -> Result<(), VetError> {
        // TODO: make this truly transactional?
        // (With a dir rename? Does that work with the lock? Fine because it's already closed?)
        if let Some(lock) = self.lock {
            let audits = lock.write_audits()?;
            let config = lock.write_config()?;
            let imports = lock.write_imports()?;
            store_audits(audits, self.audits)?;
            store_config(config, self.config)?;
            store_imports(imports, self.imports)?;
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
    pub fn fetch_foreign_audits(&mut self, network: Arc<Network>) -> Result<(), VetError> {
        let mut audits = SortedMap::new();
        let mut to_fetch = SortedMap::new();
        let runtime = tokio::runtime::Handle::current();

        for (name, import) in &self.config.imports {
            let url = Url::parse(&import.url).unwrap();
            let handle = runtime.spawn(fetch_foreign_audit(network.clone(), name.clone(), url));
            to_fetch.insert(name, handle);
        }
        for (name, handle) in to_fetch {
            let audit_file: Result<AuditsFile, VetError> = runtime.block_on(handle)?;
            let audit_file: AuditsFile = audit_file?;
            audits.insert(name.to_string(), audit_file);
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

async fn fetch_foreign_audit(
    network: Arc<Network>,
    name: String,
    url: Url,
) -> Result<AuditsFile, VetError> {
    let audit_bytes = network
        .download(url.clone())
        .await
        .wrap_err_with(|| format!("Could not import audit {name} @ {url}"))?;
    let audit_file: AuditsFile = toml_edit::de::from_slice(&audit_bytes)
        .wrap_err_with(|| format!("Could not parse {name} @ {url}"))?;
    Ok(audit_file)
}

/// A Registry in CARGO_HOME (usually the crates.io one)
pub struct CargoRegistry {
    /// The queryable index
    index: Index,
    /// The base path all registries share (`$CARGO_HOME/registry`)
    base_dir: PathBuf,
    /// The name of the registry (`github.com-1ecc6299db9ec823`)
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

impl Drop for Cache {
    fn drop(&mut self) {
        if let Some(diff_cache_path) = &self.diff_cache_path {
            // Write back the diff_cache
            if let Err(err) = || -> Result<(), VetError> {
                store_diff_cache(
                    File::create(diff_cache_path)?,
                    mem::take(&mut self.diff_cache),
                )?;
                Ok(())
            }() {
                error!("error writing back changes to diff-cache: {:?}", err);
            }
        }
        if let Some(command_history_path) = &self.command_history_path {
            // Write back the command_history
            if let Err(err) = || -> Result<(), VetError> {
                store_command_history(
                    File::create(command_history_path)?,
                    mem::take(&mut self.command_history),
                )?;
                Ok(())
            }() {
                error!("error writing back changes to diff-cache: {:?}", err);
            }
        }
        // `_lock: FileLock` implicitly released here
    }
}

impl Cache {
    /// Acquire the cache
    pub fn acquire(cfg: &PartialConfig) -> Result<Self, VetError> {
        if cfg.mock_cache {
            // We're in unit tests, everything should be mocked and not touch real caches
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

        // Make sure the cache directory exists, and acquire an exclusive lock on it.
        let root = cfg.tmp.clone();
        fs::create_dir_all(&root)
            .wrap_err_with(|| format!("failed to create cache directory `{}`", root.display()))?;

        let lock = Filesystem::new(root.clone()).open_rw(TEMP_VET_LOCK, "cache lock")?;

        let empty = root.join(TEMP_EMPTY_PACKAGE);
        fs::create_dir_all(&empty).wrap_err_with(|| {
            format!(
                "failed to create cache empty directory `{}`",
                empty.display()
            )
        })?;
        let packages_src = root.join(TEMP_REGISTRY_SRC);
        fs::create_dir_all(&packages_src).wrap_err_with(|| {
            format!(
                "failed to create package src directory `{}`",
                packages_src.display()
            )
        })?;
        let packages_cache = root.join(TEMP_REGISTRY_CACHE);
        fs::create_dir_all(&packages_cache).wrap_err_with(|| {
            format!(
                "failed to create package cache directory `{}`",
                packages_cache.display()
            )
        })?;

        // Setup the diff_cache.
        let diff_cache_path = cfg
            .cli
            .diff_cache
            .clone()
            .unwrap_or_else(|| root.join(TEMP_DIFF_CACHE));
        let diff_cache: DiffCache = File::open(&diff_cache_path)
            .ok()
            .and_then(|f| load_toml(f).ok())
            .unwrap_or_default();

        // Setup the command_history.
        let command_history_path = root.join(TEMP_COMMAND_HISTORY);
        let command_history: CommandHistory = File::open(&command_history_path)
            .ok()
            .and_then(|f| load_json(f).ok())
            .unwrap_or_default();

        // Try to get the cargo registry
        let cargo_registry = find_cargo_registry();
        if let Err(e) = &cargo_registry {
            // ERRORS: this warning really rides the line, I'm not sure if the user can/should care
            warn!("Couldn't find cargo registry: {e}");
        }

        Ok(Self {
            _lock: Some(lock),
            root: Some(root),
            diff_cache_path: Some(diff_cache_path),
            diff_cache,
            command_history_path: Some(command_history_path),
            command_history,
            cargo_registry: cargo_registry.ok(),
        })
    }

    /// Gets any information the crates.io index has on this package, locally
    /// with no downloads. The fact that we invoke `cargo metadata` on startup
    /// means the index should be as populated as we're able to get it.
    ///
    /// However this may do some expensive disk i/o, so ideally we should do
    /// some bulk processing of this later. For now let's get it working...
    pub fn query_package_from_index(&self, name: PackageStr) -> Option<crates_index::Crate> {
        let reg = self.cargo_registry.as_ref()?;
        reg.index.crate_(name)
    }

    pub fn fetch_packages<'a>(
        &mut self,
        network: Option<Arc<Network>>,
        packages: &[(PackageStr<'a>, &'a Version)],
    ) -> Result<SortedMap<PackageStr<'a>, SortedMap<&'a Version, PathBuf>>, VetError> {
        let _span = trace_span!("fetch-packages").entered();
        // Don't do anything if we're mocked, or there is no work to do
        if self.root.is_none() || packages.is_empty() {
            return Ok(SortedMap::new());
        }

        let root = self.root.as_ref().unwrap();
        let package_src_dir = root.join(TEMP_REGISTRY_SRC);
        let package_cache_dir = root.join(TEMP_REGISTRY_CACHE);
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

                let fetched_src = cargo_registry
                    .map(|reg| reg.src().join(&dir_name))
                    .filter(|path| fetch_is_ok(path))
                    .unwrap_or_else(|| package_src_dir.join(&dir_name));

                if !fetch_is_ok(&fetched_src) {
                    // If we don't have a cached copy, push this to the download queue
                    let crate_name = format!("{}.crate", dir_name);
                    let fetched_package = package_cache_dir.join(crate_name);
                    to_download.push((name, version, fetched_package, fetched_src.clone()));
                }

                // Either this path exists or we'll download it, either way, it's right
                fetched_src
            };

            paths.entry(name).or_default().insert(version, path);
        }

        // If there is anything to download, do it
        if !to_download.is_empty() {
            // ERRORS: this could arguably be swallowed but this will mostly come up in tests
            let network = network.expect("running as --frozen but needed fetches!");
            trace!("downloading {} packages", to_download.len());
            let runtime = tokio::runtime::Handle::current();
            let mut handles = vec![];

            for (name, version, download_to, unpack_to) in to_download {
                trace!(
                    "  downloading {}:{} to {}",
                    name,
                    version,
                    download_to.display()
                );
                handles.push(runtime.spawn(download_package(
                    network.clone(),
                    name.to_string(),
                    (*version).clone(),
                    download_to,
                    unpack_to,
                )));
            }

            for handle in handles {
                let res = runtime.block_on(handle)?;
                res?;
            }
        }

        trace!("all fetched!");

        Ok(paths)
    }

    pub fn fetch_and_diffstat_all(
        &mut self,
        network: Option<Arc<Network>>,
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
        let fetches = self.fetch_packages(network, &to_fetch)?;

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
}

async fn download_package(
    network: Arc<Network>,
    package: PackageName,
    version: Version,
    download_to: PathBuf,
    unpack_to: PathBuf,
) -> Result<(), VetError> {
    // If we already have the downloaded .crate, then use it
    let file = if let Ok(file) = File::open(&download_to) {
        file
    } else {
        // We don't have it, so download it
        let url = Url::parse(&format!(
            "https://crates.io/api/v1/crates/{package}/{version}/download"
        ))?;
        let file = network.download_and_persist(url, &download_to).await?;
        // TODO(#116): take the SHA2 of the bytes and compare it to what the registry says
        file
    };

    // Now unpack it
    unpack_package(&file, &unpack_to)?;

    Ok(())
}

fn unpack_package(tarball: &File, unpack_dir: &Path) -> Result<(), VetError> {
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
        result.wrap_err_with(|| format!("failed to unpack entry at `{}`", entry_path.display()))?;
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

fn find_cargo_registry() -> Result<CargoRegistry, VetError> {
    // ERRORS: all of this is genuinely fallible internal workings
    // but if these path adjustments don't work then something is very fundamentally wrong

    let index = Index::new_cargo_default()?;

    let base_dir = index.path().parent().unwrap().parent().unwrap().to_owned();
    let registry = index.path().file_name().unwrap().to_owned();

    Ok(CargoRegistry {
        index,
        base_dir,
        registry,
    })
}

fn load_toml<T>(reader: impl Read) -> Result<T, VetError>
where
    T: for<'a> Deserialize<'a>,
{
    let mut reader = BufReader::new(reader);
    let mut string = String::new();
    reader.read_to_string(&mut string)?;
    let toml = toml_edit::de::from_str(&string)?;
    Ok(toml)
}
fn store_toml<T>(mut writer: impl Write, heading: &str, val: T) -> Result<(), VetError>
where
    T: Serialize,
{
    // FIXME: do this in a temp file and swap it into place to avoid corruption?
    let toml_document = to_formatted_toml(val)?;
    writeln!(writer, "{}{}", heading, toml_document)?;
    Ok(())
}
fn load_json<T>(reader: impl Read) -> Result<T, VetError>
where
    T: for<'a> Deserialize<'a>,
{
    let mut reader = BufReader::new(reader);
    let mut string = String::new();
    reader.read_to_string(&mut string)?;
    let json = serde_json::from_str(&string)?;
    Ok(json)
}
fn store_json<T>(mut writer: impl Write, val: T) -> Result<(), VetError>
where
    T: Serialize,
{
    // FIXME: do this in a temp file and swap it into place to avoid corruption?
    let json_string = serde_json::to_string(&val)?;
    writeln!(writer, "{}", json_string)?;
    Ok(())
}

fn store_audits(writer: impl Write, mut audits: AuditsFile) -> Result<(), VetError> {
    let heading = r###"
# cargo-vet audits file
"###;
    audits
        .audits
        .values_mut()
        .for_each(|entries| entries.sort());

    store_toml(writer, heading, audits)?;
    Ok(())
}
fn store_config(writer: impl Write, mut config: ConfigFile) -> Result<(), VetError> {
    config
        .unaudited
        .values_mut()
        .for_each(|entries| entries.sort());

    let heading = r###"
# cargo-vet config file
"###;

    store_toml(writer, heading, config)?;
    Ok(())
}
fn store_imports(writer: impl Write, imports: ImportsFile) -> Result<(), VetError> {
    let heading = r###"
# cargo-vet imports lock
"###;

    store_toml(writer, heading, imports)?;
    Ok(())
}
fn store_diff_cache(writer: impl Write, diff_cache: DiffCache) -> Result<(), VetError> {
    let heading = "";

    store_toml(writer, heading, diff_cache)?;
    Ok(())
}
fn store_command_history(
    writer: impl Write,
    command_history: CommandHistory,
) -> Result<(), VetError> {
    store_json(writer, command_history)?;
    Ok(())
}
