use std::{
    collections::BTreeMap,
    ffi::OsString,
    fmt, fs, io,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use cargo_metadata::{Metadata, Version};
use clap::Parser;
use serde_json::{json, Value};

use crate::{
    editor::Editor,
    format::{
        AuditKind, CriteriaName, CriteriaStr, Delta, DependencyCriteria, FastMap, MetaConfig,
        PackageName, PackageStr, PolicyEntry, VersionReq, SAFE_TO_DEPLOY, SAFE_TO_RUN,
    },
    init_files,
    out::Out,
    resolver::{ResolveDepth, ResolveReport},
    AuditEntry, AuditsFile, Config, ConfigFile, CriteriaEntry, ExemptedDependency, ImportsFile,
    PackageExt, PartialConfig, SortedMap, Store,
};

/// Helper for performing an `assert_snapshot!` for the report output of a
/// resolver invocation. This will generate both human and JSON reports for the
/// given resolve report, and snapshot both. The JSON reports will have the
/// suffix `.json`.
///
/// Unlike a normal `assert_snapshot!` the snapshot name isn't inferred by this
/// macro, as multiple snapshots with different names need to be generated.
macro_rules! assert_report_snapshot {
    ($name:expr, $metadata:expr, $report:expr) => {{
        let (human, json) = $crate::tests::get_reports(&$metadata, $report);
        insta::assert_snapshot!($name, human);
        insta::assert_snapshot!(concat!($name, ".json"), json);
    }};
}

mod audit_as_crates_io;
mod certify;
mod regenerate_unaudited;
mod store_parsing;
mod vet;
mod violations;

// Some room above and below
const DEFAULT_VER: u64 = 10;
const DEFAULT_CRIT: CriteriaStr = "reviewed";

// Some strings for imports
const FOREIGN: &str = "peer-company";
const FOREIGN_URL: &str = "https://peercompany.co.uk";
const OTHER_FOREIGN: &str = "rival-company";
const OTHER_FOREIGN_URL: &str = "https://rivalcompany.ca";

lazy_static::lazy_static! {
    static ref TEST_RUNTIME: tokio::runtime::Runtime = {
        let error_colors_enabled = false;
        miette::set_hook(Box::new(move |_| {
            let graphical_theme = if error_colors_enabled {
                miette::GraphicalTheme::unicode()
            } else {
                miette::GraphicalTheme::unicode_nocolor()
            };
            Box::new(
                miette::MietteHandlerOpts::new()
                    .graphical_theme(graphical_theme)
                    .build()
            )
        })).expect("Failed to initialize error handler");

        tracing_subscriber::fmt::fmt()
            .with_max_level(tracing::level_filters::LevelFilter::OFF)
            // Toggle this on for tracing in tests
            // .with_max_level(tracing::level_filters::LevelFilter::TRACE)
            .with_target(false)
            .without_time()
            .with_writer(std::io::stderr)
            .init();

        tokio::runtime::Runtime::new().unwrap()
    };

}

struct MockMetadata {
    packages: Vec<MockPackage>,
    pkgids: Vec<String>,
    idx_by_name_and_ver: BTreeMap<PackageStr<'static>, BTreeMap<Version, usize>>,
}

struct MockPackage {
    name: &'static str,
    version: Version,
    deps: Vec<MockDependency>,
    dev_deps: Vec<MockDependency>,
    build_deps: Vec<MockDependency>,
    targets: Vec<&'static str>,
    is_workspace: bool,
    is_first_party: bool,
}

struct MockDependency {
    name: &'static str,
    version: Version,
}

pub struct MockRegistry {
    packages: FastMap<PackageStr<'static>, Vec<MockRegistryVersion>>,
}

struct MockRegistryVersion {
    version: Version,
    /// Dependency info dummied out in case we ever want that
    deps: Vec<()>,
}

fn reg_ver(pub_ver: u64) -> MockRegistryVersion {
    MockRegistryVersion {
        version: ver(pub_ver),
        deps: vec![],
    }
}

impl MockRegistry {
    pub fn testing_cinematic_universe() -> Self {
        Self {
            packages: [
                ("root-package", vec![reg_ver(DEFAULT_VER)]),
                ("third-party1", vec![reg_ver(DEFAULT_VER)]),
                ("third-party2", vec![reg_ver(DEFAULT_VER)]),
                ("transitive-third-party1", vec![reg_ver(DEFAULT_VER)]),
                ("first-party", vec![reg_ver(DEFAULT_VER)]),
                ("firstA", vec![reg_ver(DEFAULT_VER)]),
                ("firstAB", vec![reg_ver(DEFAULT_VER)]),
                ("firstB", vec![reg_ver(DEFAULT_VER)]),
                ("firstB-nodeps", vec![reg_ver(DEFAULT_VER)]),
                ("thirdA", vec![reg_ver(DEFAULT_VER)]),
                ("thirdAB", vec![reg_ver(DEFAULT_VER)]),
                ("third-core", vec![reg_ver(DEFAULT_VER), reg_ver(5)]),
                ("normal", vec![reg_ver(DEFAULT_VER)]),
                ("dev", vec![reg_ver(DEFAULT_VER)]),
                ("build", vec![reg_ver(DEFAULT_VER)]),
                ("proc-macro", vec![reg_ver(DEFAULT_VER)]),
                ("dev-proc-macro", vec![reg_ver(DEFAULT_VER)]),
                ("build-proc-macro", vec![reg_ver(DEFAULT_VER)]),
                ("dev-cycle", vec![reg_ver(DEFAULT_VER)]),
                ("both", vec![reg_ver(DEFAULT_VER)]),
                ("simple-dev", vec![reg_ver(DEFAULT_VER)]),
                ("simple-dev-indirect", vec![reg_ver(DEFAULT_VER)]),
                ("dev-cycle-direct", vec![reg_ver(DEFAULT_VER)]),
                ("dev-cycle-indirect", vec![reg_ver(DEFAULT_VER)]),
                ("third-normal", vec![reg_ver(DEFAULT_VER)]),
                ("third-dev", vec![reg_ver(DEFAULT_VER)]),
            ]
            .into_iter()
            .collect(),
        }
    }
    pub fn package(&self, name: PackageStr) -> Option<crates_index::Crate> {
        use std::io::Write;

        let package_entry = self.packages.get(name)?;
        let mut package_file = Vec::<u8>::new();
        for package_version in package_entry {
            // Dependencies dummied out in case we ever want them
            let line = json!({
                "name": name,
                "vers": package_version.version,
                // These fields are all dummied out here in case we ever want them
                "deps": package_version.deps.iter().map(|_dep| json!({
                    "name": "some_dep_name",
                    "req": "^0.1.2",
                    "features": [],
                    "optional": false,
                    "default_features": true,
                    // The target platform for the dependency.
                    // null if not a target dependency.
                    // Otherwise, a string such as "cfg(windows)".
                    "target": null,
                    // The dependency kind.
                    // "dev", "build", or "normal".
                    // Note: this is a required field, but a small number of entries
                    // exist in the crates.io index with either a missing or null
                    // `kind` field due to implementation bugs.
                    "kind": "normal",
                    // The URL of the index of the registry where this dependency is
                    // from as a string. If not specified or null, it is assumed the
                    // dependency is in the current registry.
                    "registry": null,
                    // If the dependency is renamed, this is a string of the actual
                    // package name. If not specified or null, this dependency is not
                    // renamed.
                    "package": null,
                })).collect::<Vec<_>>(),
                // A SHA256 checksum of the `.crate` file.
                "cksum": "d867001db0e2b6e0496f9fac96930e2d42233ecd3ca0413e0753d4c7695d289c",
                // Set of features defined for the package.
                // Each feature maps to an array of features or dependencies it enables.
                "features": {},
                "yanked": false,
                // The `links` string value from the package's manifest, or null if not
                // specified. This field is optional and defaults to null.
                "links": null,
                // An unsigned 32-bit integer value indicating the schema version of this
                // entry.
                "v": 2u32,
                // This optional field contains features with new, extended syntax.
                // Specifically, namespaced features (`dep:`) and weak dependencies
                // (`pkg?/feat`).
                "features2": {},
            });
            serde_json::ser::to_writer(&mut package_file, &line).unwrap();
            writeln!(&mut package_file).unwrap();
        }
        let result = crates_index::Crate::from_slice(&package_file)
            .expect("failed to parse mock crates index file");
        Some(result)
    }
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
            is_workspace: false,
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
fn default_exemptions(version: Version, config: &ConfigFile) -> ExemptedDependency {
    ExemptedDependency {
        version,
        criteria: vec![config.default_criteria.clone().into()],
        dependency_criteria: DependencyCriteria::new(),
        notes: None,
        suggest: true,
    }
}
fn exemptions(version: Version, criteria: CriteriaStr) -> ExemptedDependency {
    ExemptedDependency {
        version,
        criteria: vec![criteria.to_string().into()],
        dependency_criteria: DependencyCriteria::new(),
        notes: None,
        suggest: true,
    }
}

fn exemptions_dep(
    version: Version,
    criteria: CriteriaStr,
    dependency_criteria: impl IntoIterator<
        Item = (
            impl Into<PackageName>,
            impl IntoIterator<Item = impl Into<CriteriaName>>,
        ),
    >,
) -> ExemptedDependency {
    ExemptedDependency {
        version,
        criteria: vec![criteria.to_string().into()],
        notes: None,
        suggest: true,
        dependency_criteria: dependency_criteria
            .into_iter()
            .map(|(k, v)| {
                (
                    k.into(),
                    v.into_iter().map(|s| s.into().into()).collect::<Vec<_>>(),
                )
            })
            .collect(),
    }
}

fn delta_audit(from: Version, to: Version, criteria: CriteriaStr) -> AuditEntry {
    let delta = Delta { from, to };
    AuditEntry {
        who: None,
        notes: None,
        criteria: vec![criteria.to_string().into()],
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
    criteria: CriteriaStr,
    dependency_criteria: impl IntoIterator<
        Item = (
            impl Into<PackageName>,
            impl IntoIterator<Item = impl Into<CriteriaName>>,
        ),
    >,
) -> AuditEntry {
    let delta = Delta { from, to };
    AuditEntry {
        who: None,
        notes: None,
        criteria: vec![criteria.to_string().into()],
        kind: AuditKind::Delta {
            delta,
            dependency_criteria: dependency_criteria
                .into_iter()
                .map(|(k, v)| {
                    (
                        k.into(),
                        v.into_iter().map(|s| s.into().into()).collect::<Vec<_>>(),
                    )
                })
                .collect(),
        },
    }
}

fn full_audit(version: Version, criteria: CriteriaStr) -> AuditEntry {
    AuditEntry {
        who: None,
        notes: None,
        criteria: vec![criteria.to_string().into()],
        kind: AuditKind::Full {
            version,
            dependency_criteria: DependencyCriteria::default(),
        },
    }
}

fn full_audit_m(
    version: Version,
    criteria: impl IntoIterator<Item = impl Into<CriteriaName>>,
) -> AuditEntry {
    AuditEntry {
        who: None,
        notes: None,
        criteria: criteria.into_iter().map(|s| s.into().into()).collect(),
        kind: AuditKind::Full {
            version,
            dependency_criteria: DependencyCriteria::default(),
        },
    }
}

fn full_audit_dep(
    version: Version,
    criteria: CriteriaStr,
    dependency_criteria: impl IntoIterator<
        Item = (
            impl Into<PackageName>,
            impl IntoIterator<Item = impl Into<CriteriaName>>,
        ),
    >,
) -> AuditEntry {
    AuditEntry {
        who: None,
        notes: None,
        criteria: vec![criteria.to_string().into()],
        kind: AuditKind::Full {
            version,
            dependency_criteria: dependency_criteria
                .into_iter()
                .map(|(k, v)| {
                    (
                        k.into(),
                        v.into_iter().map(|s| s.into().into()).collect::<Vec<_>>(),
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
        criteria: vec![SAFE_TO_RUN.to_string().into()],
        kind: AuditKind::Violation { violation: version },
    }
}
#[allow(dead_code)]
fn violation(version: VersionReq, criteria: CriteriaStr) -> AuditEntry {
    AuditEntry {
        who: None,
        notes: None,
        criteria: vec![criteria.to_string().into()],
        kind: AuditKind::Violation { violation: version },
    }
}
#[allow(dead_code)]
fn violation_m(
    version: VersionReq,
    criteria: impl IntoIterator<Item = impl Into<CriteriaName>>,
) -> AuditEntry {
    AuditEntry {
        who: None,
        notes: None,
        criteria: criteria.into_iter().map(|s| s.into().into()).collect(),
        kind: AuditKind::Violation { violation: version },
    }
}

fn default_policy() -> PolicyEntry {
    PolicyEntry {
        audit_as_crates_io: None,
        criteria: None,
        dev_criteria: None,
        dependency_criteria: SortedMap::new(),
        notes: None,
    }
}

fn audit_as_policy(audit_as_crates_io: Option<bool>) -> PolicyEntry {
    PolicyEntry {
        audit_as_crates_io,
        ..default_policy()
    }
}

fn self_policy(criteria: impl IntoIterator<Item = impl Into<CriteriaName>>) -> PolicyEntry {
    PolicyEntry {
        criteria: Some(criteria.into_iter().map(|s| s.into().into()).collect()),
        ..default_policy()
    }
}

fn dep_policy(
    dependency_criteria: impl IntoIterator<
        Item = (
            impl Into<PackageName>,
            impl IntoIterator<Item = impl Into<CriteriaName>>,
        ),
    >,
) -> PolicyEntry {
    PolicyEntry {
        dependency_criteria: dependency_criteria
            .into_iter()
            .map(|(k, v)| {
                (
                    k.into(),
                    v.into_iter().map(|s| s.into().into()).collect::<Vec<_>>(),
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
                is_workspace: true,
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
                is_workspace: true,
                is_first_party: true,
                deps: vec![dep("firstA"), dep("firstAB")],
                ..Default::default()
            },
            MockPackage {
                name: "rootB",
                is_workspace: true,
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
                is_workspace: true,
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
                is_workspace: true,
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
                is_workspace: true,
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
                is_workspace: true,
                is_first_party: true,
                deps: vec![dep("first")],
                ..Default::default()
            },
            MockPackage {
                name: "first",
                is_workspace: true,
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
        let mut idx_by_name_and_ver = BTreeMap::<PackageStr, BTreeMap<Version, usize>>::new();

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

    fn pkgid_by(&self, name: PackageStr, version: &Version) -> &str {
        &self.pkgids[self.idx_by_name_and_ver[name][version]]
    }

    fn package_by(&self, name: PackageStr, version: &Version) -> &MockPackage {
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
                if package.is_workspace {
                    Some(self.pkgid(package))
                } else {
                    None
                }
            }).collect::<Vec<_>>(),
            "resolve": {
                "nodes": self.packages.iter().map(|package| {
                    let mut all_deps = BTreeMap::<(PackageStr, &Version), Vec<Option<&str>>>::new();
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
    let (mut config, mut audits, imports) = init_files(metadata, None);

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
                implies: vec!["reviewed".to_string().into()],
                description: Some("strongly reviewed".to_string()),
                description_url: None,
            },
        ),
        (
            "reviewed".to_string(),
            CriteriaEntry {
                implies: vec!["weak-reviewed".to_string().into()],
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
                        audit_as_crates_io: None,
                        criteria: Some(vec![DEFAULT_CRIT.to_string().into()]),
                        dev_criteria: Some(vec![DEFAULT_CRIT.to_string().into()]),
                        dependency_criteria: DependencyCriteria::new(),
                        notes: None,
                    },
                );
            }
        }
    }
    config.default_criteria = DEFAULT_CRIT.to_string();

    // Rewrite the default used by init
    for exemption in &mut config.exemptions {
        for entry in exemption.1 {
            assert_eq!(&*entry.criteria, &["safe-to-deploy".to_string()]);
            entry.criteria = vec![DEFAULT_CRIT.to_string().into()];
        }
    }

    (config, audits, imports)
}

fn files_no_exemptions(metadata: &Metadata) -> (ConfigFile, AuditsFile, ImportsFile) {
    let (mut config, audits, imports) = files_inited(metadata);

    // Just clear all the exemptions out
    config.exemptions.clear();

    (config, audits, imports)
}

fn files_full_audited(metadata: &Metadata) -> (ConfigFile, AuditsFile, ImportsFile) {
    let (config, mut audits, imports) = files_no_exemptions(metadata);

    let mut audited = SortedMap::<PackageName, Vec<AuditEntry>>::new();
    for package in &metadata.packages {
        if package.is_third_party(&config.policy) {
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
    init_files(metadata, None)
}

fn builtin_files_no_exemptions(metadata: &Metadata) -> (ConfigFile, AuditsFile, ImportsFile) {
    let (mut config, audits, imports) = builtin_files_inited(metadata);

    // Just clear all the exemptions out
    config.exemptions.clear();

    (config, audits, imports)
}
fn builtin_files_full_audited(metadata: &Metadata) -> (ConfigFile, AuditsFile, ImportsFile) {
    let (config, mut audits, imports) = builtin_files_no_exemptions(metadata);

    let mut audited = SortedMap::<PackageName, Vec<AuditEntry>>::new();
    for package in &metadata.packages {
        if package.is_third_party(&config.policy) {
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

    let mut audited = SortedMap::<PackageName, Vec<AuditEntry>>::new();
    for (name, entries) in std::mem::take(&mut config.exemptions) {
        for entry in entries {
            audited
                .entry(name.clone())
                .or_insert(vec![])
                .push(full_audit_m(
                    entry.version,
                    entry.criteria.iter().map(|s| &**s).collect::<Vec<_>>(),
                ));
        }
    }
    audits.audits = audited;

    (config, audits, imports)
}

fn mock_cfg(metadata: &Metadata) -> Config {
    mock_cfg_args(metadata, ["cargo", "vet"])
}

fn mock_cfg_args<I, T>(metadata: &Metadata, itr: I) -> Config
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let crate::cli::FakeCli::Vet(cli) =
        crate::cli::FakeCli::try_parse_from(itr).expect("Parsing arguments for mock_cfg failed!");
    Config {
        metacfg: MetaConfig(vec![]),
        metadata: metadata.clone(),
        _rest: PartialConfig {
            cli,
            cache_dir: PathBuf::new(),
            mock_cache: true,
        },
    }
}

fn get_reports(metadata: &Metadata, report: ResolveReport) -> (String, String) {
    // FIXME: Figure out how to handle disabling output colours better in tests.
    console::set_colors_enabled(false);
    console::set_colors_enabled_stderr(false);

    let cfg = mock_cfg(metadata);
    let suggest = report.compute_suggest(&cfg, None, true).unwrap();

    let human_output = BasicTestOutput::new();
    report
        .print_human(&human_output.clone().as_dyn(), &cfg, suggest.as_ref())
        .unwrap();
    let json_output = BasicTestOutput::new();
    report
        .print_json(&json_output.clone().as_dyn(), &cfg, suggest.as_ref())
        .unwrap();
    (human_output.to_string(), json_output.to_string())
}

#[allow(clippy::type_complexity)]
struct BasicTestOutput {
    output: Mutex<Vec<u8>>,
    on_read_line: Option<Box<dyn Fn(&str) -> io::Result<String> + Send + Sync + 'static>>,
    on_edit: Option<Box<dyn Fn(String) -> io::Result<String> + Send + Sync + 'static>>,
}

impl BasicTestOutput {
    fn new() -> Arc<Self> {
        Arc::new(BasicTestOutput {
            output: Mutex::new(Vec::new()),
            on_read_line: None,
            on_edit: None,
        })
    }

    fn with_callbacks(
        on_read_line: impl Fn(&str) -> io::Result<String> + Send + Sync + 'static,
        on_edit: impl Fn(String) -> io::Result<String> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(BasicTestOutput {
            output: Mutex::new(Vec::new()),
            on_read_line: Some(Box::new(on_read_line)),
            on_edit: Some(Box::new(on_edit)),
        })
    }

    fn as_dyn(self: Arc<Self>) -> Arc<dyn Out> {
        self
    }
}

impl fmt::Display for BasicTestOutput {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        std::str::from_utf8(&self.output.lock().unwrap())
            .unwrap()
            .fmt(f)
    }
}

impl Out for BasicTestOutput {
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.output.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn clear_screen(&self) -> io::Result<()> {
        writeln!(self, "<<<CLEAR SCREEN>>>");
        Ok(())
    }

    fn read_line_with_prompt(&self, initial: &str) -> io::Result<String> {
        write!(self, "{}", initial);
        if let Some(on_read_line) = &self.on_read_line {
            let response = on_read_line(initial)?;
            writeln!(self, "{}", response);
            Ok(response)
        } else {
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    fn editor<'b>(&'b self, name: &'b str) -> io::Result<Editor<'b>> {
        if let Some(on_edit) = &self.on_edit {
            let mut editor = Editor::new(name)?;
            editor.set_run_editor(move |path| {
                let original = fs::read_to_string(path)?;
                writeln!(self, "<<<EDITING {}>>>\n{}", name, original);
                match on_edit(original) {
                    Ok(contents) => {
                        writeln!(self, "<<<EDIT OK>>>\n{}\n<<<END EDIT>>>", contents);
                        fs::write(path, contents)?;
                        Ok(true)
                    }
                    Err(err) => {
                        writeln!(self, "<<<EDIT ERROR>>>");
                        Err(err)
                    }
                }
            });
            Ok(editor)
        } else {
            panic!("Unexpected editor call without on_edit configured!");
        }
    }
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
