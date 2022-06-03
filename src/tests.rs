use std::{collections::BTreeMap, ffi::OsString, path::PathBuf};

use cargo_metadata::{Metadata, Version, VersionReq};
use serde_json::{json, Value};

use crate::{
    format::{
        AuditKind, Delta, DependencyCriteria, MetaConfig, PolicyEntry, SAFE_TO_DEPLOY, SAFE_TO_RUN,
    },
    init_files,
    resolver::ResolveReport,
    AuditEntry, AuditsFile, Cli, Config, ConfigFile, CriteriaEntry, ImportsFile, PackageExt,
    PartialConfig, SortedMap, Store, UnauditedDependency,
};

// Some room above and below
const DEFAULT_VER: u64 = 10;
const DEFAULT_CRIT: &str = "reviewed";

struct MockMetadata {
    packages: Vec<MockPackage>,
    pkgids: Vec<String>,
    idx_by_name_and_ver: BTreeMap<&'static str, BTreeMap<Version, usize>>,
}

struct MockPackage {
    name: &'static str,
    version: Version,
    deps: Vec<MockDependency>,
    dev_deps: Vec<MockDependency>,
    build_deps: Vec<MockDependency>,
    targets: Vec<&'static str>,
    is_root: bool,
    is_first_party: bool,
}

struct MockDependency {
    name: &'static str,
    version: Version,
}

impl Default for MockPackage {
    fn default() -> Self {
        Self {
            name: "",
            version: ver(DEFAULT_VER),
            deps: vec![],
            dev_deps: vec![],
            build_deps: vec![],
            targets: vec!["lib"],
            is_root: false,
            is_first_party: false,
        }
    }
}

fn ver(major: u64) -> Version {
    Version {
        major,
        minor: 0,
        patch: 0,
        pre: Default::default(),
        build: Default::default(),
    }
}

fn dep(name: &'static str) -> MockDependency {
    dep_ver(name, DEFAULT_VER)
}

fn dep_ver(name: &'static str, version: u64) -> MockDependency {
    MockDependency {
        name,
        version: ver(version),
    }
}

#[allow(dead_code)]
fn default_unaudited(version: Version, config: &ConfigFile) -> UnauditedDependency {
    UnauditedDependency {
        version,
        criteria: config.default_criteria.clone(),
        dependency_criteria: DependencyCriteria::new(),
        notes: None,
        suggest: true,
    }
}
fn unaudited(version: Version, criteria: &str) -> UnauditedDependency {
    UnauditedDependency {
        version,
        criteria: criteria.to_string(),
        dependency_criteria: DependencyCriteria::new(),
        notes: None,
        suggest: true,
    }
}

fn unaudited_dep(
    version: Version,
    criteria: &str,
    dependency_criteria: impl IntoIterator<
        Item = (
            impl Into<String>,
            impl IntoIterator<Item = impl Into<String>>,
        ),
    >,
) -> UnauditedDependency {
    UnauditedDependency {
        version,
        criteria: criteria.to_string(),
        notes: None,
        suggest: true,
        dependency_criteria: dependency_criteria
            .into_iter()
            .map(|(k, v)| {
                (
                    k.into(),
                    v.into_iter().map(|s| s.into()).collect::<Vec<_>>(),
                )
            })
            .collect(),
    }
}

fn delta_audit(from: Version, to: Version, criteria: &str) -> AuditEntry {
    let delta = Delta { from, to };
    AuditEntry {
        who: None,
        notes: None,
        criteria: criteria.to_string(),
        kind: AuditKind::Delta {
            delta,
            dependency_criteria: DependencyCriteria::default(),
        },
    }
}

#[allow(dead_code)]
fn delta_audit_dep(
    from: Version,
    to: Version,
    criteria: &str,
    dependency_criteria: impl IntoIterator<
        Item = (
            impl Into<String>,
            impl IntoIterator<Item = impl Into<String>>,
        ),
    >,
) -> AuditEntry {
    let delta = Delta { from, to };
    AuditEntry {
        who: None,
        notes: None,
        criteria: criteria.to_string(),
        kind: AuditKind::Delta {
            delta,
            dependency_criteria: dependency_criteria
                .into_iter()
                .map(|(k, v)| {
                    (
                        k.into(),
                        v.into_iter().map(|s| s.into()).collect::<Vec<_>>(),
                    )
                })
                .collect(),
        },
    }
}

fn full_audit(version: Version, criteria: &str) -> AuditEntry {
    AuditEntry {
        who: None,
        notes: None,
        criteria: criteria.to_string(),
        kind: AuditKind::Full {
            version,
            dependency_criteria: DependencyCriteria::default(),
        },
    }
}

fn full_audit_dep(
    version: Version,
    criteria: &str,
    dependency_criteria: impl IntoIterator<
        Item = (
            impl Into<String>,
            impl IntoIterator<Item = impl Into<String>>,
        ),
    >,
) -> AuditEntry {
    AuditEntry {
        who: None,
        notes: None,
        criteria: criteria.to_string(),
        kind: AuditKind::Full {
            version,
            dependency_criteria: dependency_criteria
                .into_iter()
                .map(|(k, v)| {
                    (
                        k.into(),
                        v.into_iter().map(|s| s.into()).collect::<Vec<_>>(),
                    )
                })
                .collect(),
        },
    }
}

fn violation_hard(version: VersionReq) -> AuditEntry {
    AuditEntry {
        who: None,
        notes: None,
        criteria: "weak-reviewed".to_string(),
        kind: AuditKind::Violation { violation: version },
    }
}
#[allow(dead_code)]
fn violation(version: VersionReq, criteria: &str) -> AuditEntry {
    AuditEntry {
        who: None,
        notes: None,
        criteria: criteria.to_string(),
        kind: AuditKind::Violation { violation: version },
    }
}

fn default_policy() -> PolicyEntry {
    PolicyEntry {
        criteria: vec![],
        dev_criteria: vec![],
        dependency_criteria: SortedMap::new(),
        targets: None,
        dev_targets: None,
        notes: None,
    }
}

fn self_policy(criteria: impl IntoIterator<Item = impl Into<String>>) -> PolicyEntry {
    PolicyEntry {
        criteria: criteria.into_iter().map(|s| s.into()).collect(),
        ..default_policy()
    }
}

fn dep_policy(
    dependency_criteria: impl IntoIterator<
        Item = (
            impl Into<String>,
            impl IntoIterator<Item = impl Into<String>>,
        ),
    >,
) -> PolicyEntry {
    PolicyEntry {
        dependency_criteria: dependency_criteria
            .into_iter()
            .map(|(k, v)| {
                (
                    k.into(),
                    v.into_iter().map(|s| s.into()).collect::<Vec<_>>(),
                )
            })
            .collect(),
        ..default_policy()
    }
}

impl MockMetadata {
    fn simple() -> Self {
        // A simple dependency tree to test basic functionality on.
        //
        //                                    Graph
        // =======================================================================================
        //
        //                                 root-package
        //                                       |
        //                                 first-party
        //                                /           \
        //                       third-party1       third-party2
        //                            |
        //                  transitive-third-party1
        //
        MockMetadata::new(vec![
            MockPackage {
                name: "root-package",
                is_root: true,
                is_first_party: true,
                deps: vec![dep("first-party")],
                ..Default::default()
            },
            MockPackage {
                name: "first-party",
                is_first_party: true,
                deps: vec![dep("third-party1"), dep("third-party2")],
                ..Default::default()
            },
            MockPackage {
                name: "third-party1",
                deps: vec![dep("transitive-third-party1")],
                ..Default::default()
            },
            MockPackage {
                name: "third-party2",
                ..Default::default()
            },
            MockPackage {
                name: "transitive-third-party1",
                ..Default::default()
            },
        ])
    }

    fn complex() -> Self {
        // A Complex dependency tree to test more weird interactions and corner cases:
        //
        // * firstAB: first-party shared between two roots
        // * firstB-nodeps: first-party with no third-parties
        // * third-core: third-party used by everything, has two versions in-tree
        //
        //                                      Graph
        // =======================================================================================
        //
        //                         rootA                rootB
        //                        -------       ---------------------
        //                       /       \     /          |          \
        //                      /         \   /           |           \
        //                    firstA     firstAB       firstB     firstB-nodeps
        //                   /      \         \           |
        //                  /        \         \          |
        //                 /        thirdA    thirdAB     +
        //                /             \        |       /
        //               /               \       |      /
        //        third-core:v5           third-core:v10
        //
        MockMetadata::new(vec![
            MockPackage {
                name: "rootA",
                is_root: true,
                is_first_party: true,
                deps: vec![dep("firstA"), dep("firstAB")],
                ..Default::default()
            },
            MockPackage {
                name: "rootB",
                is_root: true,
                is_first_party: true,
                deps: vec![dep("firstB"), dep("firstAB"), dep("firstB-nodeps")],
                ..Default::default()
            },
            MockPackage {
                name: "firstA",
                is_first_party: true,
                deps: vec![dep("thirdA"), dep_ver("third-core", 5)],
                ..Default::default()
            },
            MockPackage {
                name: "firstAB",
                is_first_party: true,
                deps: vec![dep("thirdAB")],
                ..Default::default()
            },
            MockPackage {
                name: "firstB",
                is_first_party: true,
                deps: vec![dep("third-core")],
                ..Default::default()
            },
            MockPackage {
                name: "firstB-nodeps",
                is_first_party: true,
                ..Default::default()
            },
            MockPackage {
                name: "thirdA",
                deps: vec![dep("third-core")],
                ..Default::default()
            },
            MockPackage {
                name: "thirdAB",
                deps: vec![dep("third-core")],
                ..Default::default()
            },
            MockPackage {
                name: "third-core",
                ..Default::default()
            },
            MockPackage {
                name: "third-core",
                version: ver(5),
                ..Default::default()
            },
        ])
    }

    fn simple_deps() -> Self {
        // Different dependency cases
        MockMetadata::new(vec![
            MockPackage {
                name: "root",
                is_root: true,
                is_first_party: true,
                deps: vec![dep("normal"), dep("proc-macro")],
                dev_deps: vec![dep("dev"), dep("dev-proc-macro")],
                build_deps: vec![dep("build"), dep("build-proc-macro")],
                ..Default::default()
            },
            MockPackage {
                name: "normal",
                ..Default::default()
            },
            MockPackage {
                name: "dev",
                ..Default::default()
            },
            MockPackage {
                name: "build",
                ..Default::default()
            },
            MockPackage {
                name: "proc-macro",
                targets: vec!["proc-macro"],
                ..Default::default()
            },
            MockPackage {
                name: "dev-proc-macro",
                targets: vec!["proc-macro"],
                ..Default::default()
            },
            MockPackage {
                name: "build-proc-macro",
                targets: vec!["proc-macro"],
                ..Default::default()
            },
        ])
    }

    fn cycle() -> Self {
        // Different dependency cases
        MockMetadata::new(vec![
            MockPackage {
                name: "root",
                is_root: true,
                is_first_party: true,
                deps: vec![dep("normal")],
                dev_deps: vec![dep("dev-cycle")],
                ..Default::default()
            },
            MockPackage {
                name: "normal",
                ..Default::default()
            },
            MockPackage {
                name: "dev-cycle",
                deps: vec![dep("root")],
                ..Default::default()
            },
        ])
    }

    fn dev_detection() -> Self {
        MockMetadata::new(vec![
            MockPackage {
                name: "root",
                is_root: true,
                is_first_party: true,
                deps: vec![dep("normal"), dep("both")],
                dev_deps: vec![dep("dev-cycle-direct"), dep("both"), dep("simple-dev")],
                ..Default::default()
            },
            MockPackage {
                name: "normal",
                ..Default::default()
            },
            MockPackage {
                name: "both",
                ..Default::default()
            },
            MockPackage {
                name: "simple-dev",
                deps: vec![dep("simple-dev-indirect")],
                ..Default::default()
            },
            MockPackage {
                name: "simple-dev-indirect",
                ..Default::default()
            },
            MockPackage {
                name: "dev-cycle-direct",
                deps: vec![dep("dev-cycle-indirect")],
                ..Default::default()
            },
            MockPackage {
                name: "dev-cycle-indirect",
                deps: vec![dep("root")],
                ..Default::default()
            },
        ])
    }

    fn haunted_tree() -> Self {
        MockMetadata::new(vec![
            MockPackage {
                name: "root",
                is_root: true,
                is_first_party: true,
                deps: vec![dep("first")],
                ..Default::default()
            },
            MockPackage {
                name: "first",
                is_root: true,
                is_first_party: true,
                deps: vec![dep("third-normal")],
                dev_deps: vec![dep("third-dev")],
                ..Default::default()
            },
            MockPackage {
                name: "third-normal",
                ..Default::default()
            },
            MockPackage {
                name: "third-dev",
                ..Default::default()
            },
        ])
    }

    fn new(packages: Vec<MockPackage>) -> Self {
        let mut pkgids = vec![];
        let mut idx_by_name_and_ver = BTreeMap::<&str, BTreeMap<Version, usize>>::new();

        for (idx, package) in packages.iter().enumerate() {
            let pkgid = if package.is_first_party {
                format!(
                    "{} {} (path+file:///C:/FAKE/{})",
                    package.name, package.version, package.name
                )
            } else {
                format!(
                    "{} {} (registry+https://github.com/rust-lang/crates.io-index)",
                    package.name, package.version
                )
            };
            pkgids.push(pkgid);
            let old = idx_by_name_and_ver
                .entry(package.name)
                .or_default()
                .insert(package.version.clone(), idx);
            assert!(
                old.is_none(),
                "duplicate version {} {}",
                package.name,
                package.version
            );
        }

        Self {
            packages,
            pkgids,
            idx_by_name_and_ver,
        }
    }

    fn pkgid(&self, package: &MockPackage) -> &str {
        self.pkgid_by(package.name, &package.version)
    }

    fn pkgid_by(&self, name: &str, version: &Version) -> &str {
        &self.pkgids[self.idx_by_name_and_ver[name][version]]
    }

    fn package_by(&self, name: &str, version: &Version) -> &MockPackage {
        &self.packages[self.idx_by_name_and_ver[name][version]]
    }

    fn source(&self, package: &MockPackage) -> Value {
        if package.is_first_party {
            json!(null)
        } else {
            json!("registry+https://github.com/rust-lang/crates.io-index")
        }
    }

    fn metadata(&self) -> Metadata {
        let meta_json = json!({
            "packages": self.packages.iter().map(|package| json!({
                "name": package.name,
                "version": package.version.to_string(),
                "id": self.pkgid(package),
                "license": "MIT",
                "license_file": null,
                "description": "whatever",
                "source": self.source(package),
                "dependencies": package.deps.iter().chain(&package.dev_deps).chain(&package.build_deps).map(|dep| json!({
                    "name": dep.name,
                    "source": self.source(self.package_by(dep.name, &dep.version)),
                    "req": format!("={}", dep.version),
                    "kind": null,
                    "rename": null,
                    "optional": false,
                    "uses_default_features": true,
                    "features": [],
                    "target": null,
                    "registry": null
                })).collect::<Vec<_>>(),
                "targets": package.targets.iter().map(|target| json!({
                    "kind": [
                        target
                    ],
                    "crate_types": [
                        target
                    ],
                    "name": package.name,
                    "src_path": "C:\\Users\\fake_user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\DUMMY\\src\\lib.rs",
                    "edition": "2015",
                    "doc": true,
                    "doctest": true,
                    "test": true
                })).collect::<Vec<_>>(),
                "features": {},
                "manifest_path": "C:\\Users\\fake_user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\DUMMY\\Cargo.toml",
                "metadata": null,
                "publish": null,
                "authors": [],
                "categories": [],
                "keywords": [],
                "readme": "README.md",
                "repository": null,
                "homepage": null,
                "documentation": null,
                "edition": "2015",
                "links": null,
                "default_run": null,
                "rust_version": null
            })).collect::<Vec<_>>(),
            "workspace_members": self.packages.iter().filter_map(|package| {
                if package.is_root {
                    Some(self.pkgid(package))
                } else {
                    None
                }
            }).collect::<Vec<_>>(),
            "resolve": {
                "nodes": self.packages.iter().map(|package| {
                    let mut all_deps = BTreeMap::<(&str, &Version), Vec<Option<&str>>>::new();
                    for dep in &package.deps {
                        all_deps.entry((dep.name, &dep.version)).or_default().push(None);
                    }
                    for dep in &package.build_deps {
                        all_deps.entry((dep.name, &dep.version)).or_default().push(Some("build"));
                    }
                    for dep in &package.dev_deps {
                        all_deps.entry((dep.name, &dep.version)).or_default().push(Some("dev"));
                    }
                    json!({
                        "id": self.pkgid(package),
                        "dependencies": all_deps.keys().map(|(name, version)| self.pkgid_by(name, version)).collect::<Vec<_>>(),
                        "deps": all_deps.iter().map(|((name, version), kinds)| json!({
                            "name": name,
                            "pkg": self.pkgid_by(name, version),
                            "dep_kinds": kinds.iter().map(|kind| json!({
                                "kind": kind,
                                "target": null,
                            })).collect::<Vec<_>>(),
                        })).collect::<Vec<_>>(),
                    })
                }).collect::<Vec<_>>(),
                "root": null,
            },
            "target_directory": "C:\\FAKE\\target",
            "version": 1,
            "workspace_root": "C:\\FAKE\\",
            "metadata": null,
        });
        serde_json::from_value(meta_json).unwrap()
    }
}

fn files_inited(metadata: &Metadata) -> (ConfigFile, AuditsFile, ImportsFile) {
    let (mut config, mut audits, imports) = init_files(metadata, None).unwrap();

    // Criteria hierarchy:
    //
    // * strong-reviewed
    //   * reviewed (default)
    //      * weak-reviewed
    // * fuzzed
    //
    // This lets use mess around with "strong reqs", "weaker reqs", and "unrelated reqs"
    // with "reviewed" as the implicit default everything cares about.

    audits.criteria = SortedMap::from_iter(vec![
        (
            "strong-reviewed".to_string(),
            CriteriaEntry {
                implies: vec!["reviewed".to_string()],
                description: Some("strongly reviewed".to_string()),
                description_url: None,
            },
        ),
        (
            "reviewed".to_string(),
            CriteriaEntry {
                implies: vec!["weak-reviewed".to_string()],
                description: Some("reviewed".to_string()),
                description_url: None,
            },
        ),
        (
            "weak-reviewed".to_string(),
            CriteriaEntry {
                implies: vec![],
                description: Some("weakly reviewed".to_string()),
                description_url: None,
            },
        ),
        (
            "fuzzed".to_string(),
            CriteriaEntry {
                implies: vec![],
                description: Some("fuzzed".to_string()),
                description_url: None,
            },
        ),
    ]);

    // Make the root packages use our custom criteria instead of the builtins
    for pkgid in &metadata.workspace_members {
        for package in &metadata.packages {
            if package.id == *pkgid {
                config.policy.insert(
                    package.name.clone(),
                    PolicyEntry {
                        criteria: vec![DEFAULT_CRIT.to_string()],
                        dev_criteria: vec![DEFAULT_CRIT.to_string()],
                        dependency_criteria: DependencyCriteria::new(),
                        targets: None,
                        dev_targets: None,
                        notes: None,
                    },
                );
            }
        }
    }
    config.default_criteria = DEFAULT_CRIT.to_string();

    // Rewrite the default used by init
    for unaudited in &mut config.unaudited {
        for entry in unaudited.1 {
            assert_eq!(&*entry.criteria, "safe-to-deploy");
            entry.criteria = DEFAULT_CRIT.to_string();
        }
    }

    (config, audits, imports)
}

fn files_no_unaudited(metadata: &Metadata) -> (ConfigFile, AuditsFile, ImportsFile) {
    let (mut config, audits, imports) = files_inited(metadata);

    // Just clear all the unaudited entries out
    config.unaudited.clear();

    (config, audits, imports)
}

fn files_full_audited(metadata: &Metadata) -> (ConfigFile, AuditsFile, ImportsFile) {
    let (config, mut audits, imports) = files_no_unaudited(metadata);

    let mut audited = SortedMap::<String, Vec<AuditEntry>>::new();
    for package in &metadata.packages {
        if package.is_third_party() {
            audited
                .entry(package.name.clone())
                .or_insert(vec![])
                .push(full_audit(package.version.clone(), DEFAULT_CRIT));
        }
    }
    audits.audits = audited;

    (config, audits, imports)
}

fn builtin_files_inited(metadata: &Metadata) -> (ConfigFile, AuditsFile, ImportsFile) {
    init_files(metadata, None).unwrap()
}

fn builtin_files_no_unaudited(metadata: &Metadata) -> (ConfigFile, AuditsFile, ImportsFile) {
    let (mut config, audits, imports) = builtin_files_inited(metadata);

    // Just clear all the unaudited entries out
    config.unaudited.clear();

    (config, audits, imports)
}
fn builtin_files_full_audited(metadata: &Metadata) -> (ConfigFile, AuditsFile, ImportsFile) {
    let (config, mut audits, imports) = builtin_files_no_unaudited(metadata);

    let mut audited = SortedMap::<String, Vec<AuditEntry>>::new();
    for package in &metadata.packages {
        if package.is_third_party() {
            audited
                .entry(package.name.clone())
                .or_insert(vec![])
                .push(full_audit(package.version.clone(), SAFE_TO_DEPLOY));
        }
    }
    audits.audits = audited;

    (config, audits, imports)
}
fn builtin_files_minimal_audited(metadata: &Metadata) -> (ConfigFile, AuditsFile, ImportsFile) {
    let (mut config, mut audits, imports) = builtin_files_inited(metadata);

    let mut audited = SortedMap::<String, Vec<AuditEntry>>::new();
    for (name, entries) in std::mem::take(&mut config.unaudited) {
        for entry in entries {
            audited
                .entry(name.clone())
                .or_insert(vec![])
                .push(full_audit(entry.version, &entry.criteria));
        }
    }
    audits.audits = audited;

    (config, audits, imports)
}

fn mock_cfg(metadata: &Metadata) -> Config {
    Config {
        metacfg: MetaConfig(vec![]),
        metadata: metadata.clone(),
        _rest: PartialConfig {
            cli: Cli::mock(),
            cargo: OsString::new(),
            tmp: PathBuf::new(),
            cargo_home: None,
        },
    }
}

fn get_report(metadata: &Metadata, report: ResolveReport) -> String {
    let cfg = mock_cfg(metadata);
    let mut stdout = Vec::new();
    report.print_human(&mut stdout, &cfg).unwrap();
    String::from_utf8(stdout).unwrap()
}

fn get_unaudited(store: &Store) -> String {
    toml::ser::to_string_pretty(&store.config.unaudited).unwrap()
}

fn _init_trace_logger() {
    use simplelog::*;
    let _ = TermLogger::init(
        LevelFilter::Trace,
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

#[test]
fn mock_simple_init() {
    // (Pass) Should look the same as a fresh 'vet init'.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, audits, imports) = files_inited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-init", stdout);
}

#[test]
fn mock_simple_no_unaudited() {
    // (Fail) Should look the same as a fresh 'vet init' but with all 'unaudited' entries deleted.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, audits, imports) = files_no_unaudited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-no-unaudited", stdout);
}

#[test]
fn mock_simple_full_audited() {
    // (Pass) All entries have direct full audits.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, audits, imports) = files_full_audited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-full-audited", stdout);
}

#[test]
fn builtin_simple_init() {
    // (Pass) Should look the same as a fresh 'vet init'.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_inited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-init", stdout);
}

#[test]
fn builtin_simple_no_unaudited() {
    // (Fail) Should look the same as a fresh 'vet init' but with all 'unaudited' entries deleted.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_no_unaudited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-no-unaudited", stdout);
}

#[test]
fn builtin_simple_full_audited() {
    // (Pass) All entries have direct full audits.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_full_audited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-full-audited", stdout);
}

#[test]
fn mock_simple_violation_cur_unaudited() {
    // (Fail) All marked 'unaudited' but a 'violation' entry matches a current version.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_inited(&metadata);

    let violation = VersionReq::parse(&format!("={DEFAULT_VER}")).unwrap();
    audits
        .audits
        .entry("third-party1".to_string())
        .or_insert(vec![])
        .push(violation_hard(violation));

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-violation-cur-unaudited", stdout);
}

#[test]
fn mock_simple_violation_cur_full_audit() {
    // (Fail) All full audited but a 'violation' entry matches a current version.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let violation = VersionReq::parse(&format!("={DEFAULT_VER}")).unwrap();
    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            violation_hard(violation),
            full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-violation-cur-full-audit", stdout);
}

#[test]
fn mock_simple_violation_delta() {
    // (Fail) A 'violation' matches a delta but not the cur version

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let violation = VersionReq::parse("=5.0.0").unwrap();
    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            violation_hard(violation),
            full_audit(ver(3), SAFE_TO_DEPLOY),
            delta_audit(ver(3), ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-violation-delta", stdout);
}

#[test]
fn mock_simple_violation_full_audit() {
    // (Fail) A 'violation' matches a full audit but not the cur version

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let violation = VersionReq::parse("=3.0.0").unwrap();
    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            violation_hard(violation),
            full_audit(ver(3), SAFE_TO_DEPLOY),
            delta_audit(ver(3), ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-violation-full-audit", stdout);
}

#[test]
fn mock_simple_violation_wildcard() {
    // (Fail) A 'violation' matches a full audit but not the cur version

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let violation = VersionReq::parse("*").unwrap();
    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            violation_hard(violation),
            full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-violation-wildcard", stdout);
}

#[test]
fn mock_simple_missing_transitive() {
    // (Fail) Missing an audit for a transitive dep

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    audits
        .audits
        .get_mut("transitive-third-party1")
        .unwrap()
        .clear();

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-missing-transitive", stdout);
}

#[test]
fn mock_simple_missing_direct_internal() {
    // (Fail) Missing an audit for a direct dep that has children

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    audits.audits.get_mut("third-party1").unwrap().clear();

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-missing-direct-internal", stdout);
}

#[test]
fn mock_simple_missing_direct_leaf() {
    // (Fail) Missing an entry for direct dep that has no children

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    audits.audits.get_mut("third-party2").unwrap().clear();

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-missing-direct-leaf", stdout);
}

#[test]
fn mock_simple_missing_leaves() {
    // (Fail) Missing all leaf audits (but not the internal)

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    audits.audits.get_mut("third-party2").unwrap().clear();
    audits
        .audits
        .get_mut("transitive-third-party1")
        .unwrap()
        .clear();

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-missing-leaves", stdout);
}

#[test]
fn mock_simple_weaker_transitive_req() {
    // (Pass) A third-party dep with weaker requirements on a child dep

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let trans_audits = &mut audits.audits.get_mut("transitive-third-party1").unwrap();
    trans_audits.clear();
    trans_audits.push(full_audit(ver(DEFAULT_VER), "weak-reviewed"));

    let direct_audits = &mut audits.audits.get_mut("third-party1").unwrap();
    direct_audits.clear();
    direct_audits.push(full_audit_dep(
        ver(DEFAULT_VER),
        "reviewed",
        [("transitive-third-party1", ["weak-reviewed"])],
    ));

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-weaker-transitive-req", stdout);
}

#[test]
fn mock_simple_weaker_transitive_req_using_implies() {
    // (Pass) A third-party dep with weaker requirements on a child dep
    // but the child dep actually has *super* reqs, to check that implies works

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let trans_audits = &mut audits.audits.get_mut("transitive-third-party1").unwrap();
    trans_audits.clear();
    trans_audits.push(full_audit(ver(DEFAULT_VER), "strong-reviewed"));

    let direct_audits = &mut audits.audits.get_mut("third-party1").unwrap();
    direct_audits.clear();
    direct_audits.push(full_audit_dep(
        ver(DEFAULT_VER),
        "reviewed",
        [("transitive-third-party1", ["weak-reviewed"])],
    ));

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-weaker-transitive-req-using-implies", stdout);
}

#[test]
fn mock_simple_lower_version_review() {
    // (Fail) A dep that has a review but for a lower version.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let direct_audits = &mut audits.audits.get_mut("third-party1").unwrap();
    direct_audits.clear();
    direct_audits.push(full_audit(ver(DEFAULT_VER - 1), DEFAULT_CRIT));

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-lower-version-review", stdout);
}

#[test]
fn mock_simple_higher_version_review() {
    // (Fail) A dep that has a review but for a higher version.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let direct_audits = &mut audits.audits.get_mut("third-party1").unwrap();
    direct_audits.clear();
    direct_audits.push(full_audit(ver(DEFAULT_VER + 1), DEFAULT_CRIT));

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-higher-version-review", stdout);
}

#[test]
fn mock_simple_higher_and_lower_version_review() {
    // (Fail) A dep that has a review but for both a higher and lower version.
    // Once I mock out fake diffs it should prefer the lower one because the
    // system will make application size grow quadratically.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let direct_audits = &mut audits.audits.get_mut("third-party1").unwrap();
    direct_audits.clear();
    direct_audits.push(full_audit(ver(DEFAULT_VER - 1), DEFAULT_CRIT));
    direct_audits.push(full_audit(ver(DEFAULT_VER + 1), DEFAULT_CRIT));

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-higher-and-lower-version-review", stdout);
}

#[test]
fn mock_simple_reviewed_too_weakly() {
    // (Fail) A dep has a review but the criteria is too weak

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let trans_audits = &mut audits.audits.get_mut("transitive-third-party1").unwrap();
    trans_audits.clear();
    trans_audits.push(full_audit(ver(DEFAULT_VER), "weak-reviewed"));

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-reviewed-too-weakly", stdout);
}

#[test]
fn mock_simple_delta_to_unaudited() {
    // (Pass) A dep has a delta to an unaudited entry

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = files_full_audited(&metadata);

    let direct_audits = &mut audits.audits.get_mut("third-party1").unwrap();
    direct_audits.clear();
    direct_audits.push(delta_audit(
        ver(DEFAULT_VER - 5),
        ver(DEFAULT_VER),
        DEFAULT_CRIT,
    ));

    let direct_unaudited = &mut config.unaudited;
    direct_unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(ver(DEFAULT_VER - 5), DEFAULT_CRIT)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-delta-to-unaudited", stdout);
}

#[test]
fn mock_simple_delta_to_unaudited_overshoot() {
    // (Fail) A dep has a delta but it overshoots the unaudited entry.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = files_full_audited(&metadata);

    let direct_audits = &mut audits.audits.get_mut("third-party1").unwrap();
    direct_audits.clear();
    direct_audits.push(delta_audit(
        ver(DEFAULT_VER - 6),
        ver(DEFAULT_VER),
        DEFAULT_CRIT,
    ));

    let direct_unaudited = &mut config.unaudited;
    direct_unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(ver(DEFAULT_VER - 5), DEFAULT_CRIT)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-delta-to-unaudited-overshoot", stdout);
}

#[test]
fn mock_simple_delta_to_unaudited_undershoot() {
    // (Fail) A dep has a delta but it undershoots the unaudited entry.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = files_full_audited(&metadata);

    let direct_audits = &mut audits.audits.get_mut("third-party1").unwrap();
    direct_audits.clear();
    direct_audits.push(delta_audit(
        ver(DEFAULT_VER - 3),
        ver(DEFAULT_VER),
        DEFAULT_CRIT,
    ));

    let direct_unaudited = &mut config.unaudited;
    direct_unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(ver(DEFAULT_VER - 5), DEFAULT_CRIT)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-delta-to-unaudited-undershoot", stdout);
}

#[test]
fn mock_simple_delta_to_full_audit() {
    // (Pass) A dep has a delta to a fully audited entry

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let direct_audits = &mut audits.audits.get_mut("third-party1").unwrap();
    direct_audits.clear();
    direct_audits.push(delta_audit(
        ver(DEFAULT_VER - 5),
        ver(DEFAULT_VER),
        DEFAULT_CRIT,
    ));
    direct_audits.push(full_audit(ver(DEFAULT_VER - 5), DEFAULT_CRIT));

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-delta-to-full-audit", stdout);
}

#[test]
fn mock_simple_delta_to_full_audit_overshoot() {
    // (Fail) A dep has a delta to a fully audited entry but overshoots

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let direct_audits = &mut audits.audits.get_mut("third-party1").unwrap();
    direct_audits.clear();
    direct_audits.push(delta_audit(
        ver(DEFAULT_VER - 6),
        ver(DEFAULT_VER),
        DEFAULT_CRIT,
    ));
    direct_audits.push(full_audit(ver(DEFAULT_VER - 5), DEFAULT_CRIT));

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-delta-to-full-audit-overshoot", stdout);
}

#[test]
fn mock_simple_delta_to_full_audit_undershoot() {
    // (Fail) A dep has a delta to a fully audited entry but undershoots

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let direct_audits = &mut audits.audits.get_mut("third-party1").unwrap();
    direct_audits.clear();
    direct_audits.push(delta_audit(
        ver(DEFAULT_VER - 3),
        ver(DEFAULT_VER),
        DEFAULT_CRIT,
    ));
    direct_audits.push(full_audit(ver(DEFAULT_VER - 5), DEFAULT_CRIT));

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-delta-to-full-audit-undershoot", stdout);
}

#[test]
fn mock_simple_reverse_delta_to_full_audit() {
    // (Pass) A dep has a *reverse* delta to a fully audited entry

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let direct_audits = &mut audits.audits.get_mut("third-party1").unwrap();
    direct_audits.clear();
    direct_audits.push(delta_audit(
        ver(DEFAULT_VER + 5),
        ver(DEFAULT_VER),
        DEFAULT_CRIT,
    ));
    direct_audits.push(full_audit(ver(DEFAULT_VER + 5), DEFAULT_CRIT));

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-reverse-delta-to-full-audit", stdout);
}

#[test]
fn mock_simple_reverse_delta_to_unaudited() {
    // (Pass) A dep has a *reverse* delta to an unaudited entry

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = files_full_audited(&metadata);

    let direct_audits = &mut audits.audits.get_mut("third-party1").unwrap();
    direct_audits.clear();
    direct_audits.push(delta_audit(
        ver(DEFAULT_VER + 5),
        ver(DEFAULT_VER),
        DEFAULT_CRIT,
    ));

    let direct_unaudited = &mut config.unaudited;
    direct_unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(ver(DEFAULT_VER + 5), DEFAULT_CRIT)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-reverse-delta-to-unaudited", stdout);
}

#[test]
fn mock_simple_wrongly_reversed_delta_to_unaudited() {
    // (Fail) A dep has a *reverse* delta to an unaudited entry but they needed a normal one

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = files_full_audited(&metadata);

    let direct_audits = &mut audits.audits.get_mut("third-party1").unwrap();
    direct_audits.clear();
    direct_audits.push(delta_audit(
        ver(DEFAULT_VER),
        ver(DEFAULT_VER - 5),
        DEFAULT_CRIT,
    ));

    let direct_unaudited = &mut config.unaudited;
    direct_unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(ver(DEFAULT_VER - 5), DEFAULT_CRIT)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-wrongly-reversed-delta-to-unaudited", stdout);
}

#[test]
fn mock_simple_wrongly_reversed_delta_to_full_audit() {
    // (Fail) A dep has a *reverse* delta to a fully audited entry but they needed a normal one

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let direct_audits = &mut audits.audits.get_mut("third-party1").unwrap();
    direct_audits.clear();
    direct_audits.push(delta_audit(
        ver(DEFAULT_VER),
        ver(DEFAULT_VER - 5),
        DEFAULT_CRIT,
    ));
    direct_audits.push(full_audit(ver(DEFAULT_VER - 5), DEFAULT_CRIT));

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-wrongly-reversed-delta-to-full-audit", stdout);
}

#[test]
fn mock_simple_needed_reversed_delta_to_unaudited() {
    // (Fail) A dep has a delta to an unaudited entry but they needed a reversed one

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = files_full_audited(&metadata);

    let direct_audits = &mut audits.audits.get_mut("third-party1").unwrap();
    direct_audits.clear();
    direct_audits.push(delta_audit(
        ver(DEFAULT_VER),
        ver(DEFAULT_VER + 5),
        DEFAULT_CRIT,
    ));

    let direct_unaudited = &mut config.unaudited;
    direct_unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(ver(DEFAULT_VER + 5), DEFAULT_CRIT)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-needed-reversed-delta-to-unaudited", stdout);
}

#[test]
fn mock_simple_delta_to_unaudited_too_weak() {
    // (Fail) A dep has a delta to an unaudited entry but it's too weak

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = files_full_audited(&metadata);

    let direct_audits = &mut audits.audits.get_mut("third-party1").unwrap();
    direct_audits.clear();
    direct_audits.push(delta_audit(
        ver(DEFAULT_VER - 5),
        ver(DEFAULT_VER),
        "weak-reviewed",
    ));

    let direct_unaudited = &mut config.unaudited;
    direct_unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(ver(DEFAULT_VER - 5), DEFAULT_CRIT)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-delta-to-unaudited-too-weak", stdout);
}

#[test]
fn mock_simple_delta_to_full_audit_too_weak() {
    // (Fail) A dep has a delta to a fully audited entry but it's too weak

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let direct_audits = &mut audits.audits.get_mut("third-party1").unwrap();
    direct_audits.clear();
    direct_audits.push(delta_audit(
        ver(DEFAULT_VER - 5),
        ver(DEFAULT_VER),
        "weak-reviewed",
    ));
    direct_audits.push(full_audit(ver(DEFAULT_VER - 5), DEFAULT_CRIT));

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-delta-to-full-audit-too-weak", stdout);
}

#[test]
fn mock_simple_delta_to_too_weak_full_audit() {
    // (Fail) A dep has a delta to a fully audited entry but it's too weak

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let direct_audits = &mut audits.audits.get_mut("third-party1").unwrap();
    direct_audits.clear();
    direct_audits.push(delta_audit(
        ver(DEFAULT_VER - 5),
        ver(DEFAULT_VER),
        DEFAULT_CRIT,
    ));
    direct_audits.push(full_audit(ver(DEFAULT_VER - 5), "weak-reviewed"));

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-simple-delta-to-too-weak-full-audit", stdout);
}

#[test]
fn mock_complex_inited() {
    // (Fail) Should look the same as a fresh 'vet init' but with all 'unaudited' entries deleted.

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (config, audits, imports) = files_inited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-complex-inited", stdout);
}

#[test]
fn mock_complex_no_unaudited() {
    // (Fail) Should look the same as a fresh 'vet init' but with all 'unaudited' entries deleted.

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (config, audits, imports) = files_no_unaudited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-complex-no-unaudited", stdout);
}

#[test]
fn mock_complex_full_audited() {
    // (Pass) All entries have direct full audits.

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (config, audits, imports) = files_full_audited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-complex-full-audited", stdout);
}

#[test]
fn builtin_complex_inited() {
    // (Fail) Should look the same as a fresh 'vet init' but with all 'unaudited' entries deleted.

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_inited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-complex-inited", stdout);
}

#[test]
fn builtin_complex_no_unaudited() {
    // (Fail) Should look the same as a fresh 'vet init' but with all 'unaudited' entries deleted.

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_no_unaudited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-complex-no-unaudited", stdout);
}

#[test]
fn builtin_complex_full_audited() {
    // (Pass) All entries have direct full audits.

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_full_audited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-complex-full-audited", stdout);
}

#[test]
fn builtin_complex_minimal_audited() {
    // (Pass) All entries have direct full audits.

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_minimal_audited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-complex-minimal-audited", stdout);
}

#[test]
fn mock_complex_missing_core5() {
    // (Fail) Missing an audit for the v5 version of third-core

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    audits.audits.insert(
        "third-core".to_string(),
        vec![full_audit(ver(DEFAULT_VER), "reviewed")],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-complex-missing-core5", stdout);
}

#[test]
fn mock_complex_missing_core10() {
    // (Fail) Missing an audit for the v10 version of third-core

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    audits.audits.insert(
        "third-core".to_string(),
        vec![full_audit(ver(5), "reviewed")],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-complex-missing-core10", stdout);
}

#[test]
fn mock_complex_core10_too_weak() {
    // (Fail) Criteria for core10 is too weak

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    audits.audits.insert(
        "third-core".to_string(),
        vec![
            full_audit(ver(DEFAULT_VER), "weak-reviewed"),
            full_audit(ver(5), "reviewed"),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-complex-core10-too-weak", stdout);
}

#[test]
fn mock_complex_core10_partially_too_weak() {
    // (Fail) Criteria for core10 is too weak for thirdA but not thirdA and thirdAB (full)

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    audits.audits.insert(
        "third-core".to_string(),
        vec![
            full_audit(ver(DEFAULT_VER), "weak-reviewed"),
            full_audit(ver(5), "reviewed"),
        ],
    );

    let audit_with_weaker_req = full_audit_dep(
        ver(DEFAULT_VER),
        "reviewed",
        [("third-core", ["weak-reviewed"])],
    );
    audits
        .audits
        .insert("thirdA".to_string(), vec![audit_with_weaker_req.clone()]);
    audits
        .audits
        .insert("thirdAB".to_string(), vec![audit_with_weaker_req]);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("mock-complex-core10-partially-too-weak", stdout);
}

#[test]
fn mock_complex_core10_partially_too_weak_via_weak_delta() {
    // (Fail) Criteria for core10 is too weak for thirdA but not thirdA and thirdAB (weak delta)

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    audits.audits.insert(
        "third-core".to_string(),
        vec![
            delta_audit(ver(5), ver(DEFAULT_VER), "weak-reviewed"),
            full_audit(ver(5), "reviewed"),
        ],
    );

    let audit_with_weaker_req = full_audit_dep(
        ver(DEFAULT_VER),
        "reviewed",
        [("third-core", ["weak-reviewed"])],
    );
    audits
        .audits
        .insert("thirdA".to_string(), vec![audit_with_weaker_req.clone()]);
    audits
        .audits
        .insert("thirdAB".to_string(), vec![audit_with_weaker_req]);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!(
        "mock-complex-core10-partially-too-weak-via-weak-delta",
        stdout
    );
}

#[test]
fn mock_complex_core10_partially_too_weak_via_strong_delta() {
    // (Fail) Criteria for core10 is too weak for thirdA but not thirdA and thirdAB
    // because there's a strong delta from 5->10 but 0->5 is still weak!

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = files_full_audited(&metadata);

    audits.audits.insert(
        "third-core".to_string(),
        vec![
            delta_audit(ver(5), ver(DEFAULT_VER), "reviewed"),
            full_audit(ver(5), "weak-reviewed"),
        ],
    );

    let audit_with_weaker_req = full_audit_dep(
        ver(DEFAULT_VER),
        "reviewed",
        [("third-core", ["weak-reviewed"])],
    );
    audits
        .audits
        .insert("thirdA".to_string(), vec![audit_with_weaker_req.clone()]);
    audits
        .audits
        .insert("thirdAB".to_string(), vec![audit_with_weaker_req]);

    config.policy.insert(
        "firstA".to_string(),
        dep_policy([("third-core", ["weak-reviewed"])]),
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!(
        "mock-complex-core10-partially-too-weak-via-strong-delta",
        stdout
    );
}

#[test]
fn mock_simple_policy_root_too_strong() {
    // (Fail) Root policy is too strong

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = files_full_audited(&metadata);

    config
        .policy
        .insert("root-package".to_string(), self_policy(["strong-reviewed"]));

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("simple-policy-root-too-strong", stdout);
}

#[test]
fn mock_simple_policy_root_weaker() {
    // (Pass) Root policy weaker than necessary

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = files_full_audited(&metadata);

    config
        .policy
        .insert("root-package".to_string(), self_policy(["weak-reviewed"]));

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("simple-policy-root-weaker", stdout);
}

#[test]
fn mock_simple_policy_first_too_strong() {
    // (Fail) First-party policy is too strong

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = files_full_audited(&metadata);

    config
        .policy
        .insert("first-party".to_string(), self_policy(["strong-reviewed"]));

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("simple-policy-first-too-strong", stdout);
}

#[test]
fn mock_simple_policy_first_weaker() {
    // (Pass) First-party policy weaker than necessary

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = files_full_audited(&metadata);

    config
        .policy
        .insert("first-party".to_string(), self_policy(["weak-reviewed"]));

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("simple-policy-first-weaker", stdout);
}

#[test]
fn mock_simple_policy_root_dep_weaker() {
    // (Pass) root->first-party policy weaker than necessary

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = files_full_audited(&metadata);

    config.policy.insert(
        "root-package".to_string(),
        dep_policy([("first-party", ["weak-reviewed"])]),
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("simple-policy-root-dep-weaker", stdout);
}

#[test]
fn mock_simple_policy_root_dep_too_strong() {
    // (Pass) root->first-party policy stronger than necessary

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = files_full_audited(&metadata);

    config.policy.insert(
        "root-package".to_string(),
        dep_policy([("first-party", ["strong-reviewed"])]),
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("simple-policy-root-dep-too-strong", stdout);
}

#[test]
fn mock_simple_policy_first_dep_weaker() {
    // (Pass) first-party->third-party policy weaker than necessary

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = files_full_audited(&metadata);

    config.policy.insert(
        "first-party".to_string(),
        dep_policy([("third-party1", ["weak-reviewed"])]),
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("simple-policy-first-dep-weaker", stdout);
}

#[test]
fn mock_simple_policy_first_dep_too_strong() {
    // (Pass) first-party->third-party policy too strong

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = files_full_audited(&metadata);

    config.policy.insert(
        "first-party".to_string(),
        dep_policy([("third-party1", ["strong-reviewed"])]),
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("simple-policy-first-dep-too-strong", stdout);
}

#[test]
fn mock_simple_policy_first_dep_stronger() {
    // (Pass) first-party->third-party policy stronger but satisfied

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = files_full_audited(&metadata);

    config.policy.insert(
        "first-party".to_string(),
        dep_policy([("third-party2", ["strong-reviewed"])]),
    );

    audits.audits.insert(
        "third-party2".to_string(),
        vec![full_audit(ver(DEFAULT_VER), "strong-reviewed")],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("simple-policy-first-dep-stronger", stdout);
}

#[test]
fn mock_simple_policy_first_dep_weaker_needed() {
    // (Pass) first-party->third-party policy weaker out of necessity

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = files_full_audited(&metadata);

    config.policy.insert(
        "first-party".to_string(),
        dep_policy([("third-party1", ["weak-reviewed"])]),
    );

    audits.audits.insert(
        "third-party1".to_string(),
        vec![full_audit(ver(DEFAULT_VER), "weak-reviewed")],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("simple-policy-first-dep-weaker-needed", stdout);
}

#[test]
fn mock_simple_policy_first_dep_extra() {
    // (Pass) first-party->third-party policy has extra satisfied criteria

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = files_full_audited(&metadata);

    config.policy.insert(
        "first-party".to_string(),
        dep_policy([("third-party2", ["reviewed", "fuzzed"])]),
    );

    audits.audits.insert(
        "third-party2".to_string(),
        vec![
            full_audit(ver(DEFAULT_VER), "reviewed"),
            full_audit(ver(DEFAULT_VER), "fuzzed"),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("simple-policy-first-dep-extra", stdout);
}

#[test]
fn mock_simple_policy_first_dep_extra_missing() {
    // (Fail) first-party->third-party policy has extra unsatisfied criteria

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = files_full_audited(&metadata);

    config.policy.insert(
        "first-party".to_string(),
        dep_policy([("third-party2", ["reviewed", "fuzzed"])]),
    );

    audits.audits.insert(
        "third-party2".to_string(),
        vec![full_audit(ver(DEFAULT_VER), "reviewed")],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("simple-policy-first-dep-extra-missing", stdout);
}

#[test]
fn mock_simple_policy_first_extra_partially_missing() {
    // (Fail) first-party policy has extra unsatisfied criteria

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = files_full_audited(&metadata);

    config.policy.insert(
        "first-party".to_string(),
        self_policy(["reviewed", "fuzzed"]),
    );

    audits.audits.insert(
        "third-party2".to_string(),
        vec![
            full_audit(ver(DEFAULT_VER), "reviewed"),
            full_audit(ver(DEFAULT_VER), "fuzzed"),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("simple-policy-first-extra-partially-missing", stdout);
}

#[test]
fn mock_simple_first_policy_redundant() {
    // (Pass) first-party policy has redundant implied things

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = files_full_audited(&metadata);

    config.policy.insert(
        "first-party".to_string(),
        self_policy(["reviewed", "weak-reviewed"]),
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("simple-policy-first-policy-redundant", stdout);
}

#[test]
fn builtin_simple_deps_inited() {
    // (Pass) Should look the same as a fresh 'vet init'.
    let mock = MockMetadata::simple_deps();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_inited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-deps-init", stdout);
}

#[test]
fn builtin_simple_deps_no_unaudited() {
    // (Fail) Should look the same as a fresh 'vet init' but with all 'unaudited' entries deleted.

    let mock = MockMetadata::simple_deps();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_no_unaudited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-deps-no-unaudited", stdout);
}

#[test]
fn builtin_simple_deps_full_audited() {
    // (Pass) All entries have direct full audits.

    let mock = MockMetadata::simple_deps();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_full_audited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-deps-full-audited", stdout);
}

#[test]
fn builtin_simple_deps_minimal_audited() {
    // (Pass) All entries have direct full audits.

    let mock = MockMetadata::simple_deps();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_minimal_audited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-deps-minimal-audited", stdout);
}

#[test]
fn builtin_no_deps() {
    // (Pass) No actual deps
    let mock = MockMetadata::new(vec![MockPackage {
        name: "root-package",
        is_root: true,
        is_first_party: true,
        deps: vec![],
        ..Default::default()
    }]);

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_full_audited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-no-deps", stdout);
}

#[test]
fn builtin_only_first_deps() {
    // (Pass) No actual deps
    let mock = MockMetadata::new(vec![
        MockPackage {
            name: "root-package",
            is_root: true,
            is_first_party: true,
            deps: vec![dep("first-party")],
            ..Default::default()
        },
        MockPackage {
            name: "first-party",
            is_first_party: true,
            deps: vec![],
            ..Default::default()
        },
    ]);

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_full_audited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-only-first-deps", stdout);
}

#[test]
fn builtin_cycle_inited() {
    // (Pass) Should look the same as a fresh 'vet init'.
    let mock = MockMetadata::cycle();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_inited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-cycle-inited", stdout);
}

#[test]
fn builtin_cycle_unaudited() {
    // (Fail) Should look the same as a fresh 'vet init' but with all 'unaudited' entries deleted.

    let mock = MockMetadata::cycle();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_no_unaudited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-cycle-unaudited", stdout);
}

#[test]
fn builtin_cycle_full_audited() {
    // (Pass) All entries have direct full audits.

    let mock = MockMetadata::cycle();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_full_audited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-cycle-full-audited", stdout);
}

#[test]
fn builtin_cycle_minimal_audited() {
    // (Pass) All entries have direct full audits.

    let mock = MockMetadata::cycle();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_minimal_audited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-cycle-minimal-audited", stdout);
}

#[test]
fn builtin_dev_detection() {
    // (Pass) Check that we properly identify things that are or aren't only dev-deps,
    // even when they're indirect or used in both contexts.

    let mock = MockMetadata::dev_detection();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_no_unaudited(&metadata);
    audits.audits.insert(
        "normal".to_string(),
        vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );
    audits.audits.insert(
        "both".to_string(),
        vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );
    audits.audits.insert(
        "simple-dev".to_string(),
        vec![full_audit(ver(DEFAULT_VER), SAFE_TO_RUN)],
    );
    audits.audits.insert(
        "simple-dev-indirect".to_string(),
        vec![full_audit(ver(DEFAULT_VER), SAFE_TO_RUN)],
    );
    audits.audits.insert(
        "dev-cycle-direct".to_string(),
        vec![full_audit(ver(DEFAULT_VER), SAFE_TO_RUN)],
    );
    audits.audits.insert(
        "dev-cycle-indirect".to_string(),
        vec![full_audit(ver(DEFAULT_VER), SAFE_TO_RUN)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-dev-detection", stdout);
}

#[test]
fn builtin_dev_detection_empty() {
    // (Fail) same as above but without any audits to confirm expectations

    let mock = MockMetadata::dev_detection();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_no_unaudited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-dev-detection-empty", stdout);
}

#[test]
fn builtin_dev_detection_empty_deeper() {
    // (Fail) same as above but deeper

    let mock = MockMetadata::dev_detection();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_no_unaudited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, true);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-dev-detection-empty-deeper", stdout);
}

#[test]
fn builtin_simple_unaudited_extra() {
    // (Warn) there's an extra unused unaudited entry, but the other is needed
    // BUSTED: this test is broken (doesn't emit warning)

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert("third-party1".to_string(), vec![]);

    config.unaudited.insert(
        "third-party1".to_string(),
        vec![
            unaudited(ver(5), SAFE_TO_DEPLOY),
            unaudited(ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-unaudited-extra", stdout);
}

#[test]
fn builtin_simple_unaudited_extra_regenerate() {
    // (Pass) there's an extra unused unaudited entry, but the other is needed.
    // Should result in only the v10 unaudited entry remaining.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert("third-party1".to_string(), vec![]);

    config.unaudited.insert(
        "third-party1".to_string(),
        vec![
            unaudited(ver(5), SAFE_TO_DEPLOY),
            unaudited(ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_unaudited(&cfg, &mut store).unwrap();

    let unaudited = get_unaudited(&store);
    insta::assert_snapshot!("builtin-simple-unaudited-extra-regenerate", unaudited);
}

#[test]
fn builtin_simple_unaudited_not_a_real_dep() {
    // (Warn) there's an unaudited entry for a package that isn't in our tree at all.
    // BUSTED: this test is broken (doesn't emit warning)

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_full_audited(&metadata);

    config.unaudited.insert(
        "fake-dep".to_string(),
        vec![unaudited(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-not-a-real-dep", stdout);
}

#[test]
fn builtin_simple_unaudited_not_a_real_dep_regenerate() {
    // (Pass) there's an unaudited entry for a package that isn't in our tree at all.
    // Should strip the result and produce an empty unaudited file.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_full_audited(&metadata);

    config.unaudited.insert(
        "fake-dep".to_string(),
        vec![unaudited(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_unaudited(&cfg, &mut store).unwrap();

    let unaudited = get_unaudited(&store);
    insta::assert_snapshot!("builtin-simple-not-a-real-dep-regenerate", unaudited);
}

#[test]
fn builtin_simple_deps_unaudited_overbroad() {
    // (Warn) the unaudited entry is needed but it's overbroad
    // BUSTED: this test is broken (doesn't emit warning)

    let mock = MockMetadata::simple_deps();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert("dev".to_string(), vec![]);

    config.unaudited.insert(
        "dev".to_string(),
        vec![unaudited(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-unaudited-overbroad", stdout);
}

#[test]
fn builtin_simple_deps_unaudited_overbroad_regenerate() {
    // (Pass) the unaudited entry is needed but it's overbroad
    // Should downgrade from safe-to-deploy to safe-to-run

    let mock = MockMetadata::simple_deps();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert("dev".to_string(), vec![]);

    config.unaudited.insert(
        "dev".to_string(),
        vec![unaudited(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_unaudited(&cfg, &mut store).unwrap();

    let unaudited = get_unaudited(&store);
    insta::assert_snapshot!("builtin-simple-unaudited-overbroad-regenerate", unaudited);
}

#[test]
fn builtin_complex_unaudited_twins() {
    // (Pass) two versions of a crate exist and both are unaudited and they're needed

    let mock = MockMetadata::complex();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert("third-core".to_string(), vec![]);

    config.unaudited.insert(
        "third-core".to_string(),
        vec![
            unaudited(ver(DEFAULT_VER), SAFE_TO_DEPLOY),
            unaudited(ver(5), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-unaudited-twins", stdout);
}

#[test]
fn builtin_complex_unaudited_twins_regenerate() {
    // (Pass) two versions of a crate exist and both are unaudited and they're needed
    // Should be a no-op and both entries should remain

    let mock = MockMetadata::complex();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert("third-core".to_string(), vec![]);

    config.unaudited.insert(
        "third-core".to_string(),
        vec![
            unaudited(ver(DEFAULT_VER), SAFE_TO_DEPLOY),
            unaudited(ver(5), SAFE_TO_DEPLOY),
        ],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_unaudited(&cfg, &mut store).unwrap();

    let unaudited = get_unaudited(&store);
    insta::assert_snapshot!("builtin-simple-unaudited-twins-regenerate", unaudited);
}

#[test]
fn builtin_complex_unaudited_partial_twins() {
    // (Pass) two versions of a crate exist and one is unaudited and one is audited

    let mock = MockMetadata::complex();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-core".to_string(),
        vec![full_audit(ver(5), SAFE_TO_DEPLOY)],
    );

    config.unaudited.insert(
        "third-core".to_string(),
        vec![unaudited(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-unaudited-partial-twins", stdout);
}

#[test]
fn builtin_complex_unaudited_partial_twins_regenerate() {
    // (Pass) two versions of a crate exist and one is unaudited and one is audited
    // Should be a no-op and both entries should remain

    let mock = MockMetadata::complex();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-core".to_string(),
        vec![full_audit(ver(5), SAFE_TO_DEPLOY)],
    );

    config.unaudited.insert(
        "third-core".to_string(),
        vec![unaudited(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_unaudited(&cfg, &mut store).unwrap();

    let unaudited = get_unaudited(&store);
    insta::assert_snapshot!(
        "builtin-simple-unaudited-partial-twins-regenerate",
        unaudited
    );
}

#[test]
fn builtin_simple_unaudited_in_delta() {
    // (Warn) An audited entry overlaps a delta and isn't needed
    // BUSTED: this test is broken (doesn't emit warning)

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            full_audit(ver(3), SAFE_TO_DEPLOY),
            delta_audit(ver(3), ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    config.unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(ver(5), SAFE_TO_DEPLOY)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-unaudited-in-delta", stdout);
}

#[test]
fn builtin_simple_unaudited_in_delta_regenerate() {
    // (Pass) An audited entry overlaps a delta and isn't needed
    // Should emit an empty unaudited file

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            full_audit(ver(3), SAFE_TO_DEPLOY),
            delta_audit(ver(3), ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    config.unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(ver(5), SAFE_TO_DEPLOY)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_unaudited(&cfg, &mut store).unwrap();

    let unaudited = get_unaudited(&store);
    insta::assert_snapshot!("builtin-simple-unaudited-in-delta-regenerate", unaudited);
}

#[test]
fn builtin_simple_unaudited_in_full() {
    // (Warn) An audited entry overlaps a full audit and isn't needed
    // BUSTED: this test is broken (doesn't emit warning)

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            full_audit(ver(3), SAFE_TO_DEPLOY),
            delta_audit(ver(3), ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    config.unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(ver(3), SAFE_TO_DEPLOY)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-unaudited-in-full", stdout);
}

#[test]
fn builtin_simple_unaudited_in_full_regenerate() {
    // (Pass) An audited entry overlaps a full audit and isn't needed
    // Should emit an empty unaudited file

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            full_audit(ver(3), SAFE_TO_DEPLOY),
            delta_audit(ver(3), ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    config.unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(ver(3), SAFE_TO_DEPLOY)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_unaudited(&cfg, &mut store).unwrap();

    let unaudited = get_unaudited(&store);
    insta::assert_snapshot!("builtin-simple-unaudited-in-full-regenerate", unaudited);
}

#[test]
fn builtin_simple_unaudited_in_direct_full() {
    // (Warn) An audited entry overlaps a full audit which is the cur version and isn't needed

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );

    config.unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-unaudited-in-direct-full", stdout);
}

#[test]
fn builtin_simple_unaudited_in_direct_full_regnerate() {
    // (Pass) An audited entry overlaps a full audit which is the cur version and isn't needed
    // Should produce an empty unaudited

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );

    config.unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_unaudited(&cfg, &mut store).unwrap();

    let unaudited = get_unaudited(&store);
    insta::assert_snapshot!(
        "builtin-simple-unaudited-in-direct-full-regenerate",
        unaudited
    );
}

#[test]
fn builtin_simple_unaudited_nested_weaker_req() {
    // (Pass) A dep that has weaker requirements on its dep
    // including dependency_criteria on an unaudited entry

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            delta_audit_dep(
                ver(3),
                ver(6),
                SAFE_TO_DEPLOY,
                [("transitive-third-party1", [SAFE_TO_RUN])],
            ),
            delta_audit_dep(
                ver(6),
                ver(DEFAULT_VER),
                SAFE_TO_DEPLOY,
                [("transitive-third-party1", [SAFE_TO_RUN])],
            ),
        ],
    );
    audits.audits.insert(
        "transitive-third-party1".to_string(),
        vec![
            delta_audit(ver(4), ver(8), SAFE_TO_RUN),
            delta_audit(ver(8), ver(DEFAULT_VER), SAFE_TO_RUN),
        ],
    );

    config.unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited_dep(
            ver(3),
            SAFE_TO_DEPLOY,
            [("transitive-third-party1", [SAFE_TO_RUN])],
        )],
    );

    config.unaudited.insert(
        "transitive-third-party1".to_string(),
        vec![unaudited(ver(4), SAFE_TO_RUN)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-unaudited-nested-weaker-req", stdout);
}

#[test]
fn builtin_simple_unaudited_nested_weaker_req_needs_dep_criteria() {
    // (Fail) A dep that has weaker requirements on its dep
    // but the unaudited entry is missing that so the whole thing fails

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            delta_audit_dep(
                ver(3),
                ver(6),
                SAFE_TO_DEPLOY,
                [("transitive-third-party1", [SAFE_TO_RUN])],
            ),
            delta_audit_dep(
                ver(6),
                ver(DEFAULT_VER),
                SAFE_TO_DEPLOY,
                [("transitive-third-party1", [SAFE_TO_RUN])],
            ),
        ],
    );
    audits.audits.insert(
        "transitive-third-party1".to_string(),
        vec![
            delta_audit(ver(4), ver(8), SAFE_TO_RUN),
            delta_audit(ver(8), ver(DEFAULT_VER), SAFE_TO_RUN),
        ],
    );

    config.unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(ver(3), SAFE_TO_DEPLOY)],
    );

    config.unaudited.insert(
        "transitive-third-party1".to_string(),
        vec![unaudited(ver(4), SAFE_TO_RUN)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!(
        "builtin-simple-unaudited-nested-weaker-req-needs-dep-criteria",
        stdout
    );
}

#[test]
fn builtin_simple_unaudited_nested_weaker_req_regnerate() {
    // (Pass) A dep that has weaker requirements on its dep
    // BUSTED: doesn't emit dependency-criteria for third-party1's 'unaudited'

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            delta_audit_dep(
                ver(3),
                ver(6),
                SAFE_TO_DEPLOY,
                [("transitive-third-party1", [SAFE_TO_RUN])],
            ),
            delta_audit_dep(
                ver(6),
                ver(DEFAULT_VER),
                SAFE_TO_DEPLOY,
                [("transitive-third-party1", [SAFE_TO_RUN])],
            ),
        ],
    );
    audits.audits.insert(
        "transitive-third-party1".to_string(),
        vec![
            delta_audit(ver(4), ver(8), SAFE_TO_RUN),
            delta_audit(ver(8), ver(DEFAULT_VER), SAFE_TO_RUN),
        ],
    );

    config.unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited_dep(
            ver(3),
            SAFE_TO_DEPLOY,
            [("transitive-third-party1", [SAFE_TO_RUN])],
        )],
    );

    config.unaudited.insert(
        "transitive-third-party1".to_string(),
        vec![unaudited(ver(4), SAFE_TO_RUN)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_unaudited(&cfg, &mut store).unwrap();

    let unaudited = get_unaudited(&store);
    insta::assert_snapshot!(
        "builtin-simple-unaudited-nested-weaker-req-regenerate",
        unaudited
    );
}

#[test]
fn builtin_simple_unaudited_nested_stronger_req() {
    // (Pass) A dep that has stronger requirements on its dep

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    config.policy.insert(
        "first-party".to_string(),
        dep_policy([("third-party1", [SAFE_TO_RUN])]),
    );

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            delta_audit_dep(
                ver(3),
                ver(6),
                SAFE_TO_RUN,
                [("transitive-third-party1", [SAFE_TO_DEPLOY])],
            ),
            delta_audit_dep(
                ver(6),
                ver(DEFAULT_VER),
                SAFE_TO_RUN,
                [("transitive-third-party1", [SAFE_TO_DEPLOY])],
            ),
        ],
    );
    audits.audits.insert(
        "transitive-third-party1".to_string(),
        vec![
            delta_audit(ver(4), ver(8), SAFE_TO_DEPLOY),
            delta_audit(ver(8), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    config.unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(ver(3), SAFE_TO_RUN)],
    );

    config.unaudited.insert(
        "transitive-third-party1".to_string(),
        vec![unaudited(ver(4), SAFE_TO_DEPLOY)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-unaudited-nested-stronger-req", stdout);
}

#[test]
fn builtin_simple_unaudited_nested_stronger_req_regnerate() {
    // (Pass) A dep that has stronger requirements on its dep
    // BUSTED: should emit safe-to-deploy for transitive-third-party1

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    config.policy.insert(
        "first-party".to_string(),
        dep_policy([("third-party1", [SAFE_TO_RUN])]),
    );

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            delta_audit_dep(
                ver(3),
                ver(6),
                SAFE_TO_RUN,
                [("transitive-third-party1", [SAFE_TO_DEPLOY])],
            ),
            delta_audit_dep(
                ver(6),
                ver(DEFAULT_VER),
                SAFE_TO_RUN,
                [("transitive-third-party1", [SAFE_TO_DEPLOY])],
            ),
        ],
    );
    audits.audits.insert(
        "transitive-third-party1".to_string(),
        vec![
            delta_audit(ver(4), ver(8), SAFE_TO_DEPLOY),
            delta_audit(ver(8), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    config.unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(ver(3), SAFE_TO_RUN)],
    );

    config.unaudited.insert(
        "transitive-third-party1".to_string(),
        vec![unaudited(ver(4), SAFE_TO_DEPLOY)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_unaudited(&cfg, &mut store).unwrap();

    let unaudited = get_unaudited(&store);
    insta::assert_snapshot!(
        "builtin-simple-unaudited-nested-stronger-req-regenerate",
        unaudited
    );
}

#[test]
fn builtin_simple_deps_unaudited_adds_uneeded_criteria() {
    // (Warn) An audited entry overlaps a full audit which is the cur version and isn't needed
    // BUSTED: this test is broken (doesn't emit warning)

    let mock = MockMetadata::simple_deps();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "dev".to_string(),
        vec![
            full_audit(ver(5), SAFE_TO_RUN),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    config
        .unaudited
        .insert("dev".to_string(), vec![unaudited(ver(5), SAFE_TO_DEPLOY)]);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!(
        "builtin-simple-deps-unaudited-adds-uneeded-criteria",
        stdout
    );
}

#[test]
fn builtin_simple_deps_unaudited_adds_uneeded_criteria_regenerate() {
    // (Pass) An audited entry overlaps a full audit which is the cur version and isn't needed
    // Should produce an empty unaudited

    let mock = MockMetadata::simple_deps();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "dev".to_string(),
        vec![
            full_audit(ver(5), SAFE_TO_RUN),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    config
        .unaudited
        .insert("dev".to_string(), vec![unaudited(ver(5), SAFE_TO_DEPLOY)]);

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_unaudited(&cfg, &mut store).unwrap();

    let unaudited = get_unaudited(&store);
    insta::assert_snapshot!(
        "builtin-simple-deps-unaudited-adds-uneeded-criteria-regenerate",
        unaudited
    );
}

#[test]
fn builtin_dev_detection_unaudited_adds_uneeded_criteria_indirect() {
    // (Warn) An audited entry overlaps a full audit which is the cur version and isn't needed
    // BUSTED: this test is broken (doesn't emit warning)
    // TODO: or is this test wrong? should the delta apply?

    let mock = MockMetadata::dev_detection();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_minimal_audited(&metadata);

    audits.audits.insert(
        "simple-dev-indirect".to_string(),
        vec![
            full_audit(ver(5), SAFE_TO_RUN),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    config.unaudited.insert(
        "simple-dev-indirect".to_string(),
        vec![unaudited(ver(5), SAFE_TO_DEPLOY)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!(
        "builtin-dev-detection-unaudited-adds-uneeded-criteria-indirect",
        stdout
    );
}

#[test]
fn builtin_dev_detection_unaudited_adds_uneeded_criteria_indirect_regenerate() {
    // (Pass) An audited entry overlaps a full audit which is the cur version and isn't needed
    // Should result in an empty unaudited file

    let mock = MockMetadata::dev_detection();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_minimal_audited(&metadata);

    audits.audits.insert(
        "simple-dev-indirect".to_string(),
        vec![
            full_audit(ver(5), SAFE_TO_RUN),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_RUN),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    config.unaudited.insert(
        "simple-dev-indirect".to_string(),
        vec![unaudited(ver(5), SAFE_TO_DEPLOY)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_unaudited(&cfg, &mut store).unwrap();

    let unaudited = get_unaudited(&store);
    insta::assert_snapshot!(
        "builtin-dev-detection-unaudited-adds-uneeded-criteria-indirect-regenerate",
        unaudited
    );
}

#[test]
fn builtin_dev_detection_cursed_full() {
    // (Fail): dev-indirect has safe-to-run and by policy we only need safe-to-run
    // but dev (its parent) is audited for safe-to-deploy which requires the child
    // be safe-to-deploy. If we implement criteria "desugarring" this would pass.
    //
    // This test is "cursed" because it caused some crashes in glitched out the blame system.

    let mock = MockMetadata::dev_detection();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "simple-dev-indirect".to_string(),
        vec![
            full_audit(ver(5), SAFE_TO_RUN),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_RUN),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-dev-detection-cursed-full", stdout);
}

#[test]
fn builtin_dev_detection_cursed_minimal() {
    // (Pass): the same as the full cursed one, but without the cursed part.

    let mock = MockMetadata::dev_detection();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_minimal_audited(&metadata);

    audits.audits.insert(
        "simple-dev-indirect".to_string(),
        vec![
            full_audit(ver(5), SAFE_TO_RUN),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_RUN),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-dev-detection-cursed-minimal", stdout);
}

#[test]
fn builtin_simple_delta_cycle() {
    // (Pass) simple delta cycle

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            full_audit(ver(3), SAFE_TO_DEPLOY),
            delta_audit(ver(3), ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(5), ver(7), SAFE_TO_DEPLOY),
            delta_audit(ver(7), ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(7), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-delta-cycle", stdout);
}

#[test]
fn builtin_simple_noop_delta() {
    // (Warn) completely pointless noop delta
    // BUSTED: fails to warn about a 5->5 delta

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            full_audit(ver(3), SAFE_TO_DEPLOY),
            delta_audit(ver(3), ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(5), ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(5), ver(7), SAFE_TO_DEPLOY),
            delta_audit(ver(7), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-noop-delta", stdout);
}

#[test]
fn builtin_simple_delta_double_cycle() {
    // (Pass) double delta cycle

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            full_audit(ver(2), SAFE_TO_DEPLOY),
            delta_audit(ver(2), ver(3), SAFE_TO_DEPLOY),
            delta_audit(ver(3), ver(4), SAFE_TO_DEPLOY),
            delta_audit(ver(4), ver(3), SAFE_TO_DEPLOY),
            delta_audit(ver(4), ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(5), ver(6), SAFE_TO_DEPLOY),
            delta_audit(ver(6), ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(6), ver(7), SAFE_TO_DEPLOY),
            delta_audit(ver(7), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-delta-double-cycle", stdout);
}

#[test]
fn builtin_simple_delta_broken_double_cycle() {
    // (Fail) double delta cycle that's broken

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            full_audit(ver(2), SAFE_TO_DEPLOY),
            delta_audit(ver(2), ver(3), SAFE_TO_DEPLOY),
            delta_audit(ver(3), ver(4), SAFE_TO_DEPLOY),
            delta_audit(ver(4), ver(3), SAFE_TO_DEPLOY),
            // broken: delta_audit(ver(4), ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(5), ver(6), SAFE_TO_DEPLOY),
            delta_audit(ver(6), ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(6), ver(7), SAFE_TO_DEPLOY),
            delta_audit(ver(7), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-delta-broken-double-cycle", stdout);
}

#[test]
fn builtin_simple_delta_broken_cycle() {
    // (Fail) simple delta cycle that's broken

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            full_audit(ver(3), SAFE_TO_DEPLOY),
            delta_audit(ver(3), ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(5), ver(7), SAFE_TO_DEPLOY),
            delta_audit(ver(7), ver(5), SAFE_TO_DEPLOY),
            // broken: delta_audit(ver(7), ver(8), SAFE_TO_DEPLOY),
            delta_audit(ver(8), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-delta-broken-cycle", stdout);
}

#[test]
fn builtin_simple_long_cycle() {
    // (Pass) long delta cycle

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            full_audit(ver(2), SAFE_TO_DEPLOY),
            delta_audit(ver(2), ver(7), SAFE_TO_DEPLOY),
            delta_audit(ver(7), ver(6), SAFE_TO_DEPLOY),
            delta_audit(ver(6), ver(8), SAFE_TO_DEPLOY),
            delta_audit(ver(8), ver(7), SAFE_TO_DEPLOY),
            delta_audit(ver(8), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-long-cycle", stdout);
}

#[test]
fn builtin_simple_useless_long_cycle() {
    // (Pass) useless long delta cycle

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            full_audit(ver(2), SAFE_TO_DEPLOY),
            delta_audit(ver(2), ver(7), SAFE_TO_DEPLOY),
            delta_audit(ver(7), ver(6), SAFE_TO_DEPLOY),
            delta_audit(ver(6), ver(8), SAFE_TO_DEPLOY),
            delta_audit(ver(8), ver(7), SAFE_TO_DEPLOY),
            delta_audit(ver(7), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-simple-useless-long-cycle", stdout);
}

#[test]
fn builtin_haunted_init() {
    // (Pass) Should look the same as a fresh 'vet init'.

    let mock = MockMetadata::haunted_tree();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_inited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);
    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-haunted-init", stdout);
}

#[test]
fn builtin_haunted_no_unaudited() {
    // (Fail) Should look the same as a fresh 'vet init' but with all 'unaudited' entries deleted.

    let mock = MockMetadata::haunted_tree();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_no_unaudited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-haunted-no-unaudited", stdout);
}

#[test]
fn builtin_haunted_no_unaudited_deeper() {
    // (Fail) Should look the same as a fresh 'vet init' but with all 'unaudited' entries deleted.

    let mock = MockMetadata::haunted_tree();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_no_unaudited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, true);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-haunted-no-unaudited-deeper", stdout);
}

#[test]
fn builtin_haunted_full_audited() {
    // (Pass) All entries have direct full audits.

    let mock = MockMetadata::haunted_tree();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_full_audited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-haunted-full-audited", stdout);
}

#[test]
fn builtin_haunted_minimal_audited() {
    // (Pass) All entries have direct minimal audits.

    let mock = MockMetadata::haunted_tree();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_minimal_audited(&metadata);

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, false);

    let stdout = get_report(&metadata, report);
    insta::assert_snapshot!("builtin-haunted-minimal-audited", stdout);
}

// TESTING BACKLOG:
//
// * custom policies
//   * basic
//   * custom criteria to third-party
//   * custom criteria to first-party
//   * two first-parties depending on the same thing
//      * which is itself first-party
//      * which is a third-party
//      * with different policies
//         * where only the weaker one is satisfied (fail but give good diagnostic)
//
// * foreign mappings
//   * only using builtins
//   * 1:1 explicit mappings
//   * asymmetric cases
//   * missing mappings
//   * foreign has criteria with the same name, unmapped (don't accidentally mix it up)
//   * foreign has criteria with the same name, mapped to that name
//   * foreign has criteria with the same name, mapped to a different name
//
// * misc
//   * git deps are first party but not in workspace
//   * path deps are first party but not in workspace
//   * multiple root packages
//   * weird workspaces
//   * running from weird directories
//   * a node explicitly setting all its dependency_criteria to "no reqs"
//     * ...should this just be an error? that feels wrong to do. otherwise:
//       * with perfectly fine children
//       * with children that fail to validate at all
//
// * malformed inputs:
//   * no default criteria specified
//   * referring to non-existent criteria
//   * referring to non-existent crates (in crates.io? or just in our dep graph?)
//   * referring to non-existent versions?
//   * Bad delta syntax
//   * Bad version syntax
//   * entries in tomls that don't map to anything (at least warn to catch typos?)
//     * might be running an old version of cargo-vet on a newer repo?
