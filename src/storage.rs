use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Read, Seek, Write},
    mem,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use cargo_metadata::Version;
use crates_index::Index;
use flate2::read::GzDecoder;
use futures_util::future::try_join_all;
use miette::{NamedSource, SourceOffset};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use tar::Archive;
use tracing::{error, info, log::warn, trace};

use crate::{
    errors::{
        CacheAcquireError, CacheCommitError, CommandError, CriteriaChangeError,
        CriteriaChangeErrors, DiffError, DownloadError, FetchAndDiffError, FetchAuditError,
        FetchError, FlockError, InvalidCriteriaError, JsonParseError, LoadJsonError, LoadTomlError,
        SourceFile, StoreAcquireError, StoreCommitError, StoreCreateError, StoreJsonError,
        StoreTomlError, StoreValidateError, StoreValidateErrors, TomlParseError, UnpackError,
    },
    flock::{FileLock, Filesystem},
    format::{
        AuditKind, AuditsFile, CommandHistory, ConfigFile, CriteriaName, Delta, DiffCache,
        DiffStat, FastMap, FetchCommand, ImportName, ImportsFile, MetaConfig, PackageStr,
        SortedMap, SAFE_TO_DEPLOY, SAFE_TO_RUN,
    },
    network::Network,
    out::{progress_bar, IncProgressOnDrop},
    resolver::{self, Conclusion},
    serialization::{spanned::Spanned, to_formatted_toml},
    Config, PartialConfig,
};

// tmp cache for various shenanigans
const CACHE_DIFF_CACHE: &str = "diff-cache.toml";
const CACHE_COMMAND_HISTORY: &str = "command-history.json";
const CACHE_EMPTY_PACKAGE: &str = "empty";
const CACHE_REGISTRY_SRC: &str = "src";
const CACHE_REGISTRY_CACHE: &str = "cache";
const CACHE_VET_LOCK: &str = ".vet-lock";

// Files which are allowed to appear in the root of the cache directory, and
// will not be GC'd
const CACHE_ALLOWED_FILES: &[&str] = &[
    CACHE_DIFF_CACHE,
    CACHE_COMMAND_HISTORY,
    CACHE_EMPTY_PACKAGE,
    CACHE_REGISTRY_SRC,
    CACHE_REGISTRY_CACHE,
    CACHE_VET_LOCK,
];

// Various cargo values
const CARGO_REGISTRY_SRC: &str = "src";
const CARGO_REGISTRY_CACHE: &str = "cache";
const CARGO_OK_FILE: &str = ".cargo-ok";
const CARGO_OK_BODY: &str = "ok";

pub const DEFAULT_STORE: &str = "supply-chain";

const AUDITS_TOML: &str = "audits.toml";
const CONFIG_TOML: &str = "config.toml";
const IMPORTS_LOCK: &str = "imports.lock";

// FIXME: This is a completely arbitrary number, and may be too high or too low.
const MAX_CONCURRENT_DIFFS: usize = 40;

struct StoreLock {
    config: FileLock,
}

impl StoreLock {
    fn new(store: &Filesystem) -> Result<Self, FlockError> {
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

    // The complete live set of imports fetched from the network. Will be
    // initialized to `None` if `--locked` was passed.
    pub live_imports: Option<ImportsFile>,

    pub config_src: SourceFile,
    pub imports_src: SourceFile,
    pub audits_src: SourceFile,
}

impl Store {
    /// Create a new store (files will be completely empty, must be committed for files to be created)
    pub fn create(cfg: &Config) -> Result<Self, StoreCreateError> {
        let root = cfg.metacfg.store_path();
        root.create_dir().map_err(StoreCreateError::CouldntCreate)?;

        let lock = StoreLock::new(&root)?;

        Ok(Self {
            lock: Some(lock),
            config: ConfigFile {
                default_criteria: String::new(),
                imports: SortedMap::new(),
                policy: SortedMap::new(),
                exemptions: SortedMap::new(),
            },
            imports: ImportsFile {
                audits: SortedMap::new(),
            },
            audits: AuditsFile {
                criteria: SortedMap::new(),
                audits: SortedMap::new(),
            },
            live_imports: None,
            config_src: Arc::new(NamedSource::new(CONFIG_TOML, "")),
            audits_src: Arc::new(NamedSource::new(AUDITS_TOML, "")),
            imports_src: Arc::new(NamedSource::new(IMPORTS_LOCK, "")),
        })
    }

    pub fn is_init(metacfg: &MetaConfig) -> bool {
        // Probably want to do more here later...
        metacfg.store_path().as_path_unlocked().exists()
    }

    pub fn acquire_offline(cfg: &Config) -> Result<Self, StoreAcquireError> {
        Self::acquire(cfg, None, false)
    }

    /// Acquire an existing store
    ///
    /// If `network` is passed and `!cfg.cli.locked`, this will fetch remote
    /// imports to use for comparison purposes.
    pub fn acquire(
        cfg: &Config,
        network: Option<&Network>,
        allow_criteria_changes: bool,
    ) -> Result<Self, StoreAcquireError> {
        let root = cfg.metacfg.store_path();

        // Before we do anything else, acquire an exclusive lock on the
        // config.toml file in the store.
        // XXX: Consider acquiring a non-exclusive lock in cases where an
        // exclusive one isn't needed.
        let lock = StoreLock::new(&root)?;

        let (config_src, config): (_, ConfigFile) = load_toml(CONFIG_TOML, lock.read_config()?)?;
        let (audits_src, audits): (_, AuditsFile) = load_toml(AUDITS_TOML, lock.read_audits()?)?;
        let (imports_src, imports): (_, ImportsFile) =
            load_toml(IMPORTS_LOCK, lock.read_imports()?)?;

        // If this command isn't locked, and the network is available, fetch the
        // live state of imported audits.
        let live_imports = if let (false, Some(network)) = (cfg.cli.locked, network) {
            let fetched_audits = tokio::runtime::Handle::current()
                .block_on(fetch_imported_audits(network, &config))?;
            let live_imports =
                process_imported_audits(fetched_audits, &config, &imports, allow_criteria_changes)?;
            Some(live_imports)
        } else {
            None
        };

        let store = Self {
            lock: Some(lock),
            config,
            audits,
            imports,
            live_imports,
            config_src,
            audits_src,
            imports_src,
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
            live_imports: None,
            config_src: Arc::new(NamedSource::new(CONFIG_TOML, "")),
            audits_src: Arc::new(NamedSource::new(AUDITS_TOML, "")),
            imports_src: Arc::new(NamedSource::new(IMPORTS_LOCK, "")),
        }
    }

    /// Create a mock store, also mocking out the unlocked import fetching
    /// process by providing the live values of imported AuditsFiles.
    #[cfg(test)]
    pub fn mock_online(
        config: ConfigFile,
        audits: AuditsFile,
        imports: ImportsFile,
        fetched_audits: Vec<(ImportName, AuditsFile)>,
        allow_criteria_changes: bool,
    ) -> Result<Self, CriteriaChangeErrors> {
        let live_imports =
            process_imported_audits(fetched_audits, &config, &imports, allow_criteria_changes)?;
        Ok(Self {
            lock: None,
            config,
            imports,
            audits,
            live_imports: Some(live_imports),
            config_src: Arc::new(NamedSource::new(CONFIG_TOML, "")),
            audits_src: Arc::new(NamedSource::new(AUDITS_TOML, "")),
            imports_src: Arc::new(NamedSource::new(IMPORTS_LOCK, "")),
        })
    }

    #[cfg(test)]
    pub fn mock_acquire(
        config: &str,
        audits: &str,
        imports: &str,
    ) -> Result<Self, StoreAcquireError> {
        let (config_src, config): (_, ConfigFile) = load_toml(CONFIG_TOML, config.as_bytes())?;
        let (audits_src, audits): (_, AuditsFile) = load_toml(AUDITS_TOML, audits.as_bytes())?;
        let (imports_src, imports): (_, ImportsFile) = load_toml(IMPORTS_LOCK, imports.as_bytes())?;

        let store = Self {
            lock: None,
            config,
            imports,
            audits,
            live_imports: None,
            config_src,
            audits_src,
            imports_src,
        };

        store.validate()?;

        Ok(store)
    }

    /// Create a clone of the store for use to resolve `suggest`.
    ///
    /// This cloned store will not contain `exemptions` entries from the config,
    /// unless they're marked as `suggest = false`, such that the resolver will
    /// identify these missing audits when generating a report.
    ///
    /// Unlike the primary store created with `Store::acquire` or
    /// `Store::create`, this store will not hold the store lock, and cannot be
    /// committed to disk by calling `commit()`.
    pub fn clone_for_suggest(&self) -> Self {
        let mut clone = Self {
            lock: None,
            config: self.config.clone(),
            imports: self.imports.clone(),
            audits: self.audits.clone(),
            live_imports: self.live_imports.clone(),
            config_src: self.config_src.clone(),
            audits_src: self.audits_src.clone(),
            imports_src: self.imports_src.clone(),
        };
        // Delete all exemptions entries except those that are suggest=false
        for versions in &mut clone.config.exemptions.values_mut() {
            versions.retain(|e| !e.suggest);
        }
        clone
    }

    /// Returns the set of audits which should be operated upon.
    ///
    /// If the store was acquired unlocked, this will include audits which are
    /// not stored in imports.lock, otherwise it will only contain imports
    /// stored locally.
    pub fn imported_audits(&self) -> &SortedMap<ImportName, AuditsFile> {
        match &self.live_imports {
            Some(live_imports) => &live_imports.audits,
            None => &self.imports.audits,
        }
    }

    /// Commit the store's contents back to disk
    pub fn commit(self) -> Result<(), StoreCommitError> {
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

    /// Mock `commit`. Returns the serialized value for each file in the store.
    /// Doesn't take `self` by value so that it can continue to be used.
    #[cfg(test)]
    pub fn mock_commit(&self) -> SortedMap<String, String> {
        let mut audits = Vec::new();
        let mut config = Vec::new();
        let mut imports = Vec::new();
        store_audits(&mut audits, self.audits.clone()).unwrap();
        store_config(&mut config, self.config.clone()).unwrap();
        store_imports(&mut imports, self.imports.clone()).unwrap();

        [
            (AUDITS_TOML.to_owned(), String::from_utf8(audits).unwrap()),
            (CONFIG_TOML.to_owned(), String::from_utf8(config).unwrap()),
            (IMPORTS_LOCK.to_owned(), String::from_utf8(imports).unwrap()),
        ]
        .into_iter()
        .collect()
    }

    /// Validate the store's integrity
    #[allow(clippy::for_kv_map)]
    pub fn validate(&self) -> Result<(), StoreValidateErrors> {
        // ERRORS: ideally these are all gathered diagnostics, want to report as many errors
        // at once as possible!

        // TODO(#66): implement validation
        //
        // * check that policy entries are only first-party?
        //   * (we currently allow policy.criteria on third-parties for audit-as-crates-io)
        // * check that exemptions entries are for things that exist?
        // * check that lockfile and imports aren't desync'd (catch new/removed import urls)
        //
        // * check that each CriteriaEntry has 'description' or 'description_url'
        // * check that no one is trying to shadow builtin criteria (safe-to-run, safe-to-deploy)
        // * check that all 'audits' entries are well-formed
        // * check that all package names are valid (with crates.io...?)
        // * check that all reviews have a 'who' (currently an Option to stub it out)
        // * catch no-op deltas?
        // * nested check imports, complicated because of namespaces

        fn check_criteria(
            source_code: &SourceFile,
            valid: &Arc<Vec<CriteriaName>>,
            errors: &mut Vec<InvalidCriteriaError>,
            criteria: &[Spanned<CriteriaName>],
        ) {
            for criteria in criteria {
                if !valid.contains(criteria) {
                    errors.push(InvalidCriteriaError {
                        source_code: source_code.clone(),
                        span: Spanned::span(criteria),
                        invalid: criteria.to_string(),
                        valid_names: valid.clone(),
                    })
                }
            }
        }

        // Fixme: this should probably be a Map...? Sorted? Stable?
        let valid_criteria = Arc::new(
            self.audits
                .criteria
                .iter()
                .map(|(c, _)| &**c)
                .chain([SAFE_TO_RUN, SAFE_TO_DEPLOY])
                .map(|name| name.to_string())
                .collect::<Vec<_>>(),
        );
        let no_criteria = vec![];
        let mut invalid_criteria_errors = vec![];

        for (_package, entries) in &self.config.exemptions {
            for entry in entries {
                check_criteria(
                    &self.config_src,
                    &valid_criteria,
                    &mut invalid_criteria_errors,
                    &entry.criteria,
                );
                for (_dep_package, dep_criteria) in &entry.dependency_criteria {
                    check_criteria(
                        &self.config_src,
                        &valid_criteria,
                        &mut invalid_criteria_errors,
                        dep_criteria,
                    );
                }
            }
        }
        for (_package, policy) in &self.config.policy {
            check_criteria(
                &self.config_src,
                &valid_criteria,
                &mut invalid_criteria_errors,
                policy.criteria.as_ref().unwrap_or(&no_criteria),
            );
            check_criteria(
                &self.config_src,
                &valid_criteria,
                &mut invalid_criteria_errors,
                policy.dev_criteria.as_ref().unwrap_or(&no_criteria),
            );
            for (_dep_package, dep_criteria) in &policy.dependency_criteria {
                check_criteria(
                    &self.config_src,
                    &valid_criteria,
                    &mut invalid_criteria_errors,
                    dep_criteria,
                );
            }
        }
        for (_new_criteria, entry) in &self.audits.criteria {
            // TODO: check that new_criteria isn't shadowing a builtin criteria
            check_criteria(
                &self.audits_src,
                &valid_criteria,
                &mut invalid_criteria_errors,
                &entry.implies,
            );
        }
        for (_package, entries) in &self.audits.audits {
            for entry in entries {
                // TODO: check that new_criteria isn't shadowing a builtin criteria
                check_criteria(
                    &self.audits_src,
                    &valid_criteria,
                    &mut invalid_criteria_errors,
                    &entry.criteria,
                );
                match &entry.kind {
                    crate::format::AuditKind::Full {
                        dependency_criteria,
                        ..
                    } => {
                        for (_dep_package, dep_criteria) in dependency_criteria {
                            check_criteria(
                                &self.audits_src,
                                &valid_criteria,
                                &mut invalid_criteria_errors,
                                dep_criteria,
                            );
                        }
                    }
                    crate::format::AuditKind::Delta {
                        dependency_criteria,
                        ..
                    } => {
                        for (_dep_package, dep_criteria) in dependency_criteria {
                            check_criteria(
                                &self.audits_src,
                                &valid_criteria,
                                &mut invalid_criteria_errors,
                                dep_criteria,
                            );
                        }
                    }
                    crate::format::AuditKind::Violation { .. } => {}
                }
            }
        }

        // If we're locked, and therefore not fetching new live imports,
        // validate that our imports.lock is in sync with config.toml.
        let imports_lock_outdated = self
            .imports_lock_outdated()
            .then(|| StoreValidateError::ImportsLockOutdated);

        let errors = invalid_criteria_errors
            .into_iter()
            .map(StoreValidateError::InvalidCriteria)
            .chain(imports_lock_outdated)
            .collect::<Vec<_>>();
        if !errors.is_empty() {
            return Err(StoreValidateErrors { errors });
        }

        Ok(())
    }

    fn imports_lock_outdated(&self) -> bool {
        // If we have live imports, we're going to be updating imports.lock, so
        // it's OK if it's out-of-date with regard to the config.
        if self.live_imports.is_some() {
            return false;
        }

        // We must have the exact same set of imports, otherwise an import has
        // been added or removed and we're out of date.
        if self.config.imports.keys().ne(self.imports.audits.keys()) {
            return true;
        }

        for (import_name, config) in &self.config.imports {
            let audits_file = self.imports.audits.get(import_name).unwrap();
            // If we have any excluded crates in the imports.lock, it is out of
            // date and needs to be regenerated.
            for crate_name in &config.exclude {
                if audits_file.audits.contains_key(crate_name) {
                    return true;
                }
            }
        }

        false
    }

    /// Return an updated version of the `imports.lock` file taking into account
    /// the result of running the resolver, to pick which audits need to be
    /// vendored.
    ///
    /// If `force_update` is specified, audits for all crates will be updated,
    /// even if the currently vendored audits would be sufficient.
    #[must_use]
    pub fn get_updated_imports_file(
        &self,
        graph: &resolver::DepGraph<'_>,
        conclusion: &resolver::Conclusion,
        force_update: bool,
    ) -> ImportsFile {
        if self.live_imports.is_none() {
            // We're locked, so can't update anything.
            return self.imports.clone();
        }

        // Determine which packages were used.
        let mut used_packages = SortedMap::new();
        for package in graph.nodes.iter() {
            used_packages.insert(package.name, false);
        }

        // If we succeeded, also record which packages need fresh imports.
        if let Conclusion::Success(success) = conclusion {
            for &node_idx in &success.needed_fresh_imports {
                let package = &graph.nodes[node_idx];
                used_packages.insert(package.name, true);
            }
        }

        let mut new_imports = ImportsFile {
            audits: SortedMap::new(),
        };
        for import_name in self.config.imports.keys() {
            let live_audit_file = self
                .imported_audits()
                .get(import_name)
                .expect("Live audits missing for import?");

            // Is this the first time we're doing this import? If it is we'll
            // want to effectively force-update this peer.
            let first_import = !self.imports.audits.contains_key(import_name);

            // Create the new audits file, and copy criteria into it on a
            // per-package basis, only including used packages.
            // We always use the live version of criteria in the new file.
            let mut new_audits_file = AuditsFile {
                criteria: live_audit_file.criteria.clone(),
                audits: SortedMap::new(),
            };
            for (&package, &need_fresh_imports) in &used_packages {
                // Always pull audit entries from the live version to pull in
                // revocations, violations, updated notes, etc.
                // Filter out entries which are fresh unless we're updating
                // entries for this package or it's a violation.
                let update_package = first_import || need_fresh_imports || force_update;
                let audits = live_audit_file
                    .audits
                    .get(package)
                    .map(|v| &v[..])
                    .unwrap_or(&[])
                    .iter()
                    .filter(|audit| {
                        update_package
                            || !audit.is_fresh_import
                            || matches!(audit.kind, AuditKind::Violation { .. })
                    })
                    .cloned()
                    .map(|mut audit| {
                        audit.is_fresh_import = false;
                        audit
                    })
                    .collect::<Vec<_>>();

                // Record audits in the new audits file, if there are any.
                if !audits.is_empty() {
                    new_audits_file.audits.insert(package.to_owned(), audits);
                }
            }
            new_imports
                .audits
                .insert(import_name.to_owned(), new_audits_file);
        }

        new_imports
    }
}

/// Process imported audits from the network, generating a `LiveImports`
/// description of the live state of imported audits.
fn process_imported_audits(
    fetched_audits: Vec<(ImportName, AuditsFile)>,
    config_file: &ConfigFile,
    imports_lock: &ImportsFile,
    allow_criteria_changes: bool,
) -> Result<ImportsFile, CriteriaChangeErrors> {
    let mut new_imports = ImportsFile {
        audits: SortedMap::new(),
    };
    let mut changed_criteria = Vec::new();
    for (import_name, mut audits_file) in fetched_audits {
        let config = config_file
            .imports
            .get(&import_name)
            .expect("fetched audit without config?");

        // Remove any excluded audits from the live copy. We'll effectively
        // pretend they don't exist upstream.
        for excluded in &config.exclude {
            audits_file.audits.remove(excluded);
        }

        // By default all audits read from the network are fresh.
        for audit_entry in audits_file.audits.values_mut().flat_map(|v| v.iter_mut()) {
            audit_entry.is_fresh_import = true;
        }

        // If we have an existing audits file for these imports, compare against it.
        if let Some(existing_audits_file) = imports_lock.audits.get(&import_name) {
            if !allow_criteria_changes {
                // Compare the new criteria descriptions with existing criteria
                // descriptions. If the description already exists, record a
                // CriteriaChangeError.
                for (criteria_name, old_entry) in &existing_audits_file.criteria {
                    if let Some(new_entry) = audits_file.criteria.get(criteria_name) {
                        let old_desc = old_entry.description.as_ref().unwrap();
                        let new_desc = new_entry.description.as_ref().unwrap();
                        if old_desc != new_desc {
                            changed_criteria.push(CriteriaChangeError {
                                import_name: import_name.clone(),
                                criteria_name: criteria_name.to_owned(),
                                old_desc: old_desc.clone(),
                                new_desc: new_desc.clone(),
                            });
                        }
                    }
                }
            }

            // Compare the new audits with existing audits. If an audit already
            // existed in the existing audits file, mark it as non-fresh.
            for (package, existing_audits) in &existing_audits_file.audits {
                let new_audits = audits_file
                    .audits
                    .get_mut(package)
                    .map(|v| &mut v[..])
                    .unwrap_or(&mut []);
                for existing_audit in existing_audits {
                    for new_audit in &mut *new_audits {
                        // Ignore `who` and `notes` for comparison, as they
                        // are not relevant semantically and might have been
                        // updated uneventfully.
                        if new_audit.is_fresh_import
                            && new_audit.kind == existing_audit.kind
                            && new_audit.criteria == existing_audit.criteria
                        {
                            new_audit.is_fresh_import = false;
                            break;
                        }
                    }
                }
            }
        }

        // Now add the new import
        new_imports.audits.insert(import_name, audits_file);
    }

    if !changed_criteria.is_empty() {
        return Err(CriteriaChangeErrors {
            errors: changed_criteria,
        });
    }

    // FIXME: Consider doing some additional validation on these audits
    // before returning?

    Ok(new_imports)
}

/// Fetch all declared imports from the network, filling in any criteria
/// descriptions.
async fn fetch_imported_audits(
    network: &Network,
    config: &ConfigFile,
) -> Result<Vec<(ImportName, AuditsFile)>, FetchAuditError> {
    let progress_bar = progress_bar("Fetching", "imported audits", config.imports.len() as u64);
    try_join_all(config.imports.iter().map(|(name, import)| async {
        let _guard = IncProgressOnDrop(&progress_bar, 1);
        let audit_file = fetch_imported_audit(network, name, &import.url).await?;
        Ok::<_, FetchAuditError>((name.clone(), audit_file))
    }))
    .await
}

/// Fetch a single AuditsFile from the network, filling in any criteria
/// descriptions.
async fn fetch_imported_audit(
    network: &Network,
    name: &str,
    url: &str,
) -> Result<AuditsFile, FetchAuditError> {
    let parsed_url = Url::parse(url).map_err(|error| FetchAuditError::InvalidUrl {
        import_url: url.to_owned(),
        import_name: name.to_owned(),
        error,
    })?;
    let audit_bytes = network.download(parsed_url).await?;
    let audit_string = String::from_utf8(audit_bytes).map_err(LoadTomlError::from)?;
    let audit_source = Arc::new(NamedSource::new(name, audit_string.clone()));
    let mut audit_file: AuditsFile = toml::de::from_str(&audit_string)
        .map_err(|error| {
            let (line, col) = error.line_col().unwrap_or((0, 0));
            TomlParseError {
                source_code: audit_source,
                span: SourceOffset::from_location(&audit_string, line + 1, col + 1),
                error,
            }
        })
        .map_err(LoadTomlError::from)?;

    // Eagerly fetch all descriptions for criteria in the imported audits file,
    // and store them inline. We'll error out if any of these descriptions are
    // unavailable.
    try_join_all(
        audit_file
            .criteria
            .iter_mut()
            .map(|(criteria_name, criteria_entry)| async {
                if criteria_entry.description.is_some() {
                    return Ok(());
                }

                let url_string = criteria_entry.description_url.as_ref().ok_or_else(|| {
                    FetchAuditError::MissingCriteriaDescription {
                        import_name: name.to_owned(),
                        criteria_name: criteria_name.clone(),
                    }
                })?;
                let url = Url::parse(url_string).map_err(|error| {
                    FetchAuditError::InvalidCriteriaDescriptionUrl {
                        import_name: name.to_owned(),
                        criteria_name: criteria_name.clone(),
                        url: url_string.clone(),
                        error,
                    }
                })?;
                let bytes = network.download(url.clone()).await?;
                let description =
                    String::from_utf8(bytes).map_err(|error| DownloadError::InvalidText {
                        url: url.clone(),
                        error,
                    })?;

                criteria_entry.description = Some(description);
                Ok::<(), FetchAuditError>(())
            }),
    )
    .await?;

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

struct CacheState {
    /// The loaded DiffCache, will be written back on Drop
    diff_cache: DiffCache,
    /// Command history to provide some persistent magic smarts
    command_history: CommandHistory,
    /// Paths for unpacked packages from this version.
    fetched_packages: FastMap<(String, Version), Arc<tokio::sync::OnceCell<PathBuf>>>,
    /// Computed diffstats from this version.
    diffed: FastMap<(String, Delta), Arc<tokio::sync::OnceCell<DiffStat>>>,
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
    /// Path to the CommandHistory (for when we want to save it back)
    command_history_path: Option<PathBuf>,
    /// Semaphore preventing exceeding the maximum number of concurrent diffs.
    diff_semaphore: tokio::sync::Semaphore,
    /// Common mutable state for the cache which can be mutated concurrently
    /// from multiple tasks.
    state: Mutex<CacheState>,
}

impl Drop for Cache {
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap();
        if let Some(diff_cache_path) = &self.diff_cache_path {
            // Write back the diff_cache
            if let Err(err) = || -> Result<(), CacheCommitError> {
                store_diff_cache(
                    File::create(diff_cache_path)?,
                    mem::take(&mut state.diff_cache),
                )?;
                Ok(())
            }() {
                error!("error writing back changes to diff-cache: {:?}", err);
            }
        }
        if let Some(command_history_path) = &self.command_history_path {
            // Write back the command_history
            if let Err(err) = || -> Result<(), CacheCommitError> {
                store_command_history(
                    File::create(command_history_path)?,
                    mem::take(&mut state.command_history),
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
    pub fn acquire(cfg: &PartialConfig) -> Result<Self, CacheAcquireError> {
        if cfg.mock_cache {
            // We're in unit tests, everything should be mocked and not touch real caches
            return Ok(Cache {
                _lock: None,
                root: None,
                cargo_registry: None,
                diff_cache_path: None,
                command_history_path: None,
                diff_semaphore: tokio::sync::Semaphore::new(MAX_CONCURRENT_DIFFS),
                state: Mutex::new(CacheState {
                    diff_cache: DiffCache::default(),
                    command_history: CommandHistory::default(),
                    fetched_packages: FastMap::new(),
                    diffed: FastMap::new(),
                }),
            });
        }

        // Make sure the cache directory exists, and acquire an exclusive lock on it.
        let root = cfg.cache_dir.clone();
        fs::create_dir_all(&root).map_err(|error| CacheAcquireError::Root {
            target: root.clone(),
            error,
        })?;

        let lock = Filesystem::new(root.clone()).open_rw(CACHE_VET_LOCK, "cache lock")?;

        let empty = root.join(CACHE_EMPTY_PACKAGE);
        fs::create_dir_all(&empty).map_err(|error| CacheAcquireError::Empty {
            target: empty.clone(),
            error,
        })?;

        let packages_src = root.join(CACHE_REGISTRY_SRC);
        fs::create_dir_all(&packages_src).map_err(|error| CacheAcquireError::Src {
            target: empty.clone(),
            error,
        })?;

        let packages_cache = root.join(CACHE_REGISTRY_CACHE);
        fs::create_dir_all(&packages_cache).map_err(|error| CacheAcquireError::Cache {
            target: packages_cache.clone(),
            error,
        })?;

        // Setup the diff_cache.
        let diff_cache_path = cfg
            .cli
            .diff_cache
            .clone()
            .unwrap_or_else(|| root.join(CACHE_DIFF_CACHE));
        let diff_cache: DiffCache = File::open(&diff_cache_path)
            .ok()
            .and_then(|f| load_toml(CACHE_DIFF_CACHE, f).map(|v| v.1).ok())
            .unwrap_or_default();

        // Setup the command_history.
        let command_history_path = root.join(CACHE_COMMAND_HISTORY);
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
            command_history_path: Some(command_history_path),
            cargo_registry: cargo_registry.ok(),
            diff_semaphore: tokio::sync::Semaphore::new(MAX_CONCURRENT_DIFFS),
            state: Mutex::new(CacheState {
                diff_cache,
                command_history,
                fetched_packages: FastMap::new(),
                diffed: FastMap::new(),
            }),
        })
    }

    /// Gets any information the crates.io index has on this package, locally
    /// with no downloads. The fact that we invoke `cargo metadata` on startup
    /// means the index should be as populated as we're able to get it.
    ///
    /// However this may do some expensive disk i/o, so ideally we should do
    /// some bulk processing of this later. For now let's get it working...
    #[cfg(not(test))]
    pub fn query_package_from_index(&self, name: PackageStr) -> Option<crates_index::Crate> {
        let reg = self.cargo_registry.as_ref()?;
        reg.index.crate_(name)
    }

    #[cfg(test)]
    pub fn query_package_from_index(&self, name: PackageStr) -> Option<crates_index::Crate> {
        if let Some(reg) = self.cargo_registry.as_ref() {
            reg.index.crate_(name)
        } else {
            crate::tests::MockRegistry::testing_cinematic_universe().package(name)
        }
    }

    #[tracing::instrument(skip(self, network), err)]
    pub async fn fetch_package(
        &self,
        network: Option<&Network>,
        package: PackageStr<'_>,
        version: &Version,
    ) -> Result<PathBuf, FetchError> {
        // Lock the mutex to extract a reference to the OnceCell which we'll use
        // to asynchronously synchronize on and fetch the package only once in a
        // single execution.
        let once_cell = {
            // NOTE: Don't .await while this is held, or we might deadlock!
            let mut guard = self.state.lock().unwrap();
            guard
                .fetched_packages
                .entry((package.to_owned(), version.clone()))
                .or_default()
                .clone()
        };

        let path_res: Result<_, FetchError> = once_cell
            .get_or_try_init(|| async {
                let root = self.root.as_ref().unwrap();

                let dir_name = format!("{}-{}", package, version);

                // First try to get a cached copy from cargo's registry.
                if let Some(reg) = self.cargo_registry.as_ref() {
                    let fetched_src = reg.src().join(&dir_name);
                    if fetch_is_ok(&fetched_src).await {
                        return Ok(fetched_src);
                    }
                }

                // Paths for the fetched package and checkout in our local cache.
                let fetched_package = root
                    .join(CACHE_REGISTRY_CACHE)
                    .join(format!("{}.crate", dir_name));
                let fetched_src = root.join(CACHE_REGISTRY_SRC).join(&dir_name);

                // Check if the resource is already available in our local cache.
                let fetched_package_ = fetched_package.clone();
                let cached_file = tokio::task::spawn_blocking(move || {
                    File::open(&fetched_package_).map(|file| {
                        // Update the atime and mtime for this crate to ensure it isn't
                        // collected by the gc.
                        let now = filetime::FileTime::now();
                        if let Err(err) =
                            filetime::set_file_handle_times(&file, Some(now), Some(now))
                        {
                            warn!(
                                "failed to update mtime for {}, gc may not function correctly: {}",
                                fetched_package_.display(),
                                err
                            );
                        }
                        file
                    })
                })
                .await
                .expect("failed to join");

                // If the file isn't in our local cache, make sure to download it.
                let file = match cached_file {
                    Ok(file) => file,
                    Err(_) => {
                        let network = network.ok_or_else(|| FetchError::Frozen {
                            package: package.to_owned(),
                            version: version.clone(),
                        })?;

                        // We don't have it, so download it
                        let url =
                            format!("https://crates.io/api/v1/crates/{package}/{version}/download");
                        let url = Url::parse(&url).map_err(|error| FetchError::InvalidUrl {
                            url: url.clone(),
                            error,
                        })?;
                        info!(
                            "downloading package {}:{} from {} to {}",
                            package,
                            version,
                            url,
                            fetched_package.display()
                        );
                        network.download_and_persist(url, &fetched_package).await?;

                        let fetched_package_ = fetched_package.clone();
                        tokio::task::spawn_blocking(move || File::open(&fetched_package_))
                            .await
                            .expect("failed to join")
                            .map_err(|error| FetchError::OpenCached {
                                target: fetched_package.clone(),
                                error,
                            })?
                    }
                };

                // TODO(#116): take the SHA2 of the bytes and compare it to what the registry says

                if fetch_is_ok(&fetched_src).await {
                    Ok(fetched_src)
                } else {
                    info!(
                        "unpacking package {}:{} from {} to {}",
                        package,
                        version,
                        fetched_package.display(),
                        fetched_src.display()
                    );
                    // The tarball needs to be unpacked, so do so.
                    tokio::task::spawn_blocking(move || {
                        unpack_package(&file, &fetched_src)
                            .map(|_| fetched_src)
                            .map_err(|error| FetchError::Unpack {
                                src: fetched_package.clone(),
                                error,
                            })
                    })
                    .await
                    .expect("failed to join")
                }
            })
            .await;
        let path = path_res?;
        Ok(path.to_owned())
    }

    #[tracing::instrument(skip_all, err)]
    async fn diffstat_package(
        &self,
        version1: &Path,
        version2: &Path,
    ) -> Result<DiffStat, DiffError> {
        let _permit = self
            .diff_semaphore
            .acquire()
            .await
            .expect("Semaphore dropped?!");

        // ERRORS: all of this is properly fallible internal workings, we can fail
        // to diffstat some packages and still produce some useful output
        trace!("diffstating {version1:#?} {version2:#?}");
        // FIXME: mask out .cargo_vcs_info.json
        // FIXME: look into libgit2 vs just calling git

        let out = tokio::process::Command::new("git")
            .arg("diff")
            .arg("--no-index")
            .arg("--shortstat")
            .arg(version1)
            .arg(version2)
            .output()
            .await
            .map_err(CommandError::CommandFailed)?;

        let status = out.status.code().unwrap_or(-1);
        // 0 = empty
        // 1 = some diff
        if status != 0 && status != 1 {
            return Err(CommandError::BadStatus(status).into());
        }

        let diffstat = String::from_utf8(out.stdout).map_err(CommandError::BadOutput)?;

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

            // ERRORS: Arguably this should just be an error but it's more of a
            // "have I completely misunderstood this format, if so let me know"
            // panic, so the assert *is* what I want..?
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

    #[tracing::instrument(skip(self, network), err)]
    pub async fn fetch_and_diffstat_package(
        &self,
        network: Option<&Network>,
        package: PackageStr<'_>,
        delta: &Delta,
    ) -> Result<DiffStat, FetchAndDiffError> {
        // Lock the mutex to extract a reference to the OnceCell which we'll use
        // to asynchronously synchronize on and diff the package only once in a
        // single execution.
        //
        // While we have the mutex locked, we'll also check the DiffStat cache
        // to return without any async steps if possible.
        let once_cell = {
            // NOTE: Don't .await while this is held, or we might deadlock!
            let mut guard = self.state.lock().unwrap();

            // Check if the value has already been cached.
            let DiffCache::V1 { diffs } = &guard.diff_cache;
            if let Some(cached) = diffs
                .get(package)
                .and_then(|cache| cache.get(delta))
                .cloned()
            {
                return Ok(cached);
            }

            if self.root.is_none() {
                // If we don't have a root, assume we want mocked results
                // ERRORS: this warning really rides the line, I'm not sure if the user can/should care
                warn!("Missing root, assuming we're in tests and mocking");

                let from_len = match &delta.from {
                    Some(from) => from.major * from.major,
                    None => 0,
                };
                let to_len: u64 = delta.to.major * delta.to.major;
                let diff = to_len as i64 - from_len as i64;
                let count = diff.unsigned_abs();
                let raw = if diff < 0 {
                    format!("-{}", count)
                } else {
                    format!("+{}", count)
                };
                return Ok(DiffStat { raw, count });
            }

            guard
                .diffed
                .entry((package.to_owned(), delta.clone()))
                .or_default()
                .clone()
        };

        let diffstat = once_cell
            .get_or_try_init(|| async {
                let from = match &delta.from {
                    Some(from) => self.fetch_package(network, package, from).await?,
                    None => self.root.as_ref().unwrap().join(CACHE_EMPTY_PACKAGE),
                };
                let to = self.fetch_package(network, package, &delta.to).await?;

                // Have fetches, do a real diffstat
                let diffstat = self.diffstat_package(&from, &to).await?;

                // Record the cache result in the diffcache
                {
                    let mut guard = self.state.lock().unwrap();
                    let DiffCache::V1 { diffs } = &mut guard.diff_cache;
                    diffs
                        .entry(package.to_string())
                        .or_insert(SortedMap::new())
                        .insert(delta.clone(), diffstat.clone());
                }

                Ok::<_, FetchAndDiffError>(diffstat)
            })
            .await?;
        Ok(diffstat.clone())
    }

    /// Run a garbage-collection pass over the cache, removing any files which
    /// aren't supposed to be there, or which haven't been touched for an
    /// extended period of time.
    pub async fn gc(&self, max_package_age: Duration) {
        if self.root.is_none() {
            return;
        }

        let (root_rv, empty_rv, packages_rv) = tokio::join!(
            self.gc_root(),
            self.gc_empty(),
            self.gc_packages(max_package_age)
        );
        if let Err(err) = root_rv {
            error!("gc: performing gc on the cache root failed: {err}");
        }
        if let Err(err) = empty_rv {
            error!("gc: performing gc on the empty package failed: {err}");
        }
        if let Err(err) = packages_rv {
            error!("gc: performing gc on the package cache failed: {err}");
        }
    }

    /// Sync version of `gc`
    pub fn gc_sync(&self, max_package_age: Duration) {
        tokio::runtime::Handle::current().block_on(self.gc(max_package_age));
    }

    /// Remove any unrecognized files from the root of the cargo-vet cache
    /// directory.
    async fn gc_root(&self) -> Result<(), io::Error> {
        let root = self.root.as_ref().unwrap();
        let mut root_entries = tokio::fs::read_dir(root).await?;
        while let Some(entry) = root_entries.next_entry().await? {
            if !entry
                .file_name()
                .to_str()
                .map_or(false, |name| CACHE_ALLOWED_FILES.contains(&name))
            {
                remove_dir_entry(&entry).await?;
            }
        }
        Ok(())
    }

    /// Remove all files located in the `cargo-vet/empty` directory, as it
    /// should be empty.
    async fn gc_empty(&self) -> Result<(), std::io::Error> {
        let empty = self.root.as_ref().unwrap().join(CACHE_EMPTY_PACKAGE);
        let mut empty_entries = tokio::fs::read_dir(&empty).await?;
        while let Some(entry) = empty_entries.next_entry().await? {
            remove_dir_entry(&entry).await?;
        }
        Ok(())
    }

    /// Remove any non '.crate' files from the registry cache, '.crate' files
    /// which are older than `max_package_age`, and any source directories from
    /// the registry src which no longer have a corresponding .crate.
    async fn gc_packages(&self, max_package_age: Duration) -> Result<(), io::Error> {
        let cache = self.root.as_ref().unwrap().join(CACHE_REGISTRY_CACHE);
        let src = self.root.as_ref().unwrap().join(CACHE_REGISTRY_SRC);

        let mut kept_packages = Vec::new();

        let mut cache_entries = tokio::fs::read_dir(&cache).await?;
        while let Some(entry) = cache_entries.next_entry().await? {
            if let Some(to_keep) = should_keep_package(&entry, max_package_age).await {
                kept_packages.push(to_keep);
            } else {
                remove_dir_entry(&entry).await?;
            }
        }

        let mut src_entries = tokio::fs::read_dir(&src).await?;
        while let Some(entry) = src_entries.next_entry().await? {
            if !kept_packages.contains(&entry.file_name()) || !fetch_is_ok(&entry.path()).await {
                remove_dir_entry(&entry).await?;
            }
        }
        Ok(())
    }

    /// Delete every file in the cache directory other than the cache lock, and
    /// clear out the command history and diff cache files.
    ///
    /// NOTE: The diff_cache and command_history files will be re-created when
    /// the cache is unlocked, however they will be empty.
    pub async fn clean(&self) -> Result<(), io::Error> {
        let root = self.root.as_ref().expect("cannot clean a mocked cache");

        // Make sure we don't write back the command history and diff cache when
        // dropping.
        {
            let mut guard = self.state.lock().unwrap();
            guard.command_history = Default::default();
            guard.diff_cache = Default::default();
        }

        let mut root_entries = tokio::fs::read_dir(&root).await?;
        while let Some(entry) = root_entries.next_entry().await? {
            if entry.file_name() != Path::new(CACHE_VET_LOCK) {
                remove_dir_entry(&entry).await?;
            }
        }
        Ok(())
    }

    /// Sync version of `clean`
    pub fn clean_sync(&self) -> Result<(), io::Error> {
        tokio::runtime::Handle::current().block_on(self.clean())
    }

    pub fn get_last_fetch(&self) -> Option<FetchCommand> {
        let guard = self.state.lock().unwrap();
        guard.command_history.last_fetch.clone()
    }

    pub fn set_last_fetch(&self, last_fetch: FetchCommand) {
        let mut guard = self.state.lock().unwrap();
        guard.command_history.last_fetch = Some(last_fetch);
    }
}

/// Queries a package in the crates.io registry for a specific published version
pub fn exact_version<'a>(
    this: &'a crates_index::Crate,
    target_version: &Version,
) -> Option<&'a crates_index::Version> {
    for index_version in this.versions() {
        if let Ok(index_ver) = index_version.version().parse::<cargo_metadata::Version>() {
            if &index_ver == target_version {
                return Some(index_version);
            }
        }
    }
    None
}

#[tracing::instrument(err)]
fn unpack_package(tarball: &File, unpack_dir: &Path) -> Result<(), UnpackError> {
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
        let mut entry = entry.map_err(UnpackError::ArchiveIterate)?;
        let entry_path = entry
            .path()
            .map_err(UnpackError::ArchiveEntry)?
            .into_owned();

        // We're going to unpack this tarball into the global source
        // directory, but we want to make sure that it doesn't accidentally
        // (or maliciously) overwrite source code from other crates. Cargo
        // itself should never generate a tarball that hits this error, and
        // crates.io should also block uploads with these sorts of tarballs,
        // but be extra sure by adding a check here as well.
        if !entry_path.starts_with(prefix) {
            return Err(UnpackError::InvalidPaths {
                entry_path,
                prefix: prefix.to_owned(),
            });
        }

        entry
            .unpack_in(parent)
            .map_err(|error| UnpackError::Unpack {
                entry_path: entry_path.clone(),
                error,
            })?;
    }

    // The lock file is created after unpacking so we overwrite a lock file
    // which may have been extracted from the package.
    let mut ok = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lockfile)
        .map_err(|error| UnpackError::LockCreate {
            target: lockfile.clone(),
            error,
        })?;

    // Write to the lock file to indicate that unpacking was successful.
    write!(ok, "ok").map_err(|error| UnpackError::LockCreate {
        target: lockfile.clone(),
        error,
    })?;

    Ok(())
}

async fn fetch_is_ok(fetch: &Path) -> bool {
    match tokio::fs::read_to_string(fetch.join(CARGO_OK_FILE)).await {
        Ok(ok) => ok == CARGO_OK_BODY,
        Err(_) => false,
    }
}

/// Based on the type of file for an entry, either recursively remove the
/// directory, or remove the file. This is intended to be roughly equivalent to
/// `rm -r`.
async fn remove_dir_entry(entry: &tokio::fs::DirEntry) -> Result<(), io::Error> {
    info!("gc: removing {}", entry.path().display());
    let file_type = entry.file_type().await?;
    if file_type.is_dir() {
        tokio::fs::remove_dir_all(entry.path()).await?;
    } else {
        tokio::fs::remove_file(entry.path()).await?;
    }
    Ok(())
}

/// Given a directory entry for a file, returns how old it is. If there is an
/// issue (e.g. mtime >= now), will return `None` instead.
async fn get_file_age(entry: &tokio::fs::DirEntry) -> Option<Duration> {
    let now = SystemTime::now();
    let meta = entry.metadata().await.ok()?;
    now.duration_since(meta.modified().ok()?).ok()
}

/// Returns tne name of the crate if it should be preserved, or `None` if it shouldn't.
async fn should_keep_package(
    entry: &tokio::fs::DirEntry,
    max_package_age: Duration,
) -> Option<OsString> {
    // Get the stem and extension from the directory entry's path, and
    // immediately remove it if something goes wrong.
    let path = entry.path();
    let stem = path.file_stem()?;
    if path.extension()? != OsStr::new("crate") {
        return None;
    }

    match get_file_age(entry).await {
        Some(age) if age > max_package_age => None,
        _ => Some(stem.to_owned()),
    }
}

fn find_cargo_registry() -> Result<CargoRegistry, crates_index::Error> {
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

fn load_toml<T>(file_name: &str, reader: impl Read) -> Result<(SourceFile, T), LoadTomlError>
where
    T: for<'a> Deserialize<'a>,
{
    let mut reader = BufReader::new(reader);
    let mut string = String::new();
    reader.read_to_string(&mut string)?;
    let result = toml::de::from_str(&string);
    // We defer the NamedSource creation into each branch because the error path wants to
    // have access to the input string, but NamedSource consumes and erases it.
    match result {
        Ok(toml) => Ok((Arc::new(NamedSource::new(file_name, string)), toml)),
        Err(error) => {
            let (line, col) = error.line_col().unwrap_or((0, 0));
            let span = SourceOffset::from_location(&string, line + 1, col);
            Err(TomlParseError {
                source_code: Arc::new(NamedSource::new(file_name, string)),
                span,
                error,
            }
            .into())
        }
    }
}
fn store_toml<T>(mut writer: impl Write, heading: &str, val: T) -> Result<(), StoreTomlError>
where
    T: Serialize,
{
    // FIXME: do this in a temp file and swap it into place to avoid corruption?
    let toml_document = to_formatted_toml(val)?;
    writeln!(writer, "{}{}", heading, toml_document)?;
    Ok(())
}
fn load_json<T>(reader: impl Read) -> Result<T, LoadJsonError>
where
    T: for<'a> Deserialize<'a>,
{
    let mut reader = BufReader::new(reader);
    let mut string = String::new();
    reader.read_to_string(&mut string)?;
    let json = serde_json::from_str(&string).map_err(|error| JsonParseError { error })?;
    Ok(json)
}
fn store_json<T>(mut writer: impl Write, val: T) -> Result<(), StoreJsonError>
where
    T: Serialize,
{
    // FIXME: do this in a temp file and swap it into place to avoid corruption?
    let json_string = serde_json::to_string(&val)?;
    writeln!(writer, "{}", json_string)?;
    Ok(())
}

fn store_audits(writer: impl Write, mut audits: AuditsFile) -> Result<(), StoreTomlError> {
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
fn store_config(writer: impl Write, mut config: ConfigFile) -> Result<(), StoreTomlError> {
    config
        .exemptions
        .values_mut()
        .for_each(|entries| entries.sort());

    let heading = r###"
# cargo-vet config file
"###;

    store_toml(writer, heading, config)?;
    Ok(())
}
fn store_imports(writer: impl Write, imports: ImportsFile) -> Result<(), StoreTomlError> {
    let heading = r###"
# cargo-vet imports lock
"###;

    store_toml(writer, heading, imports)?;
    Ok(())
}
fn store_diff_cache(writer: impl Write, diff_cache: DiffCache) -> Result<(), StoreTomlError> {
    let heading = "";

    store_toml(writer, heading, diff_cache)?;
    Ok(())
}
fn store_command_history(
    writer: impl Write,
    command_history: CommandHistory,
) -> Result<(), StoreJsonError> {
    store_json(writer, command_history)?;
    Ok(())
}
