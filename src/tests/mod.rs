use std::{
    collections::BTreeMap,
    ffi::OsString,
    fmt,
    fmt::Write,
    fs, io,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use cargo_metadata::{semver, Metadata};
use clap::Parser;
use serde_json::{json, Value};

use crate::{
    format::{
        AuditEntry, AuditKind, AuditsFile, ConfigFile, CratesAPICrate, CratesAPICrateMetadata,
        CratesAPITrustpubData, CratesAPIUser, CratesAPIVersion, CratesPublisher, CratesSourceId,
        CratesUserId, CriteriaEntry, CriteriaMap, CriteriaName, CriteriaStr, ExemptedDependency,
        FastMap, ImportsFile, MetaConfig, PackageName, PackagePolicyEntry, PackageStr, PolicyEntry,
        SortedMap, SortedSet, TrustEntry, VersionReq, VetVersion, WildcardEntry, SAFE_TO_DEPLOY,
        SAFE_TO_RUN,
    },
    git_tool::Editor,
    network::Network,
    out::Out,
    resolver::ResolveReport,
    storage::Store,
    Config, PackageExt, PartialConfig,
};

/// Helper for performing an `assert_snapshot!` for the report output of a
/// resolver invocation. This will generate both human and JSON reports for the
/// given resolve report, and snapshot both. The JSON reports will have the
/// suffix `.json`.
///
/// Unlike a normal `assert_snapshot!` the snapshot name isn't inferred by this
/// macro, as multiple snapshots with different names need to be generated.
macro_rules! assert_report_snapshot {
    ($name:expr, $metadata:expr, $store:expr) => {
        assert_report_snapshot!($name, $metadata, $store, None);
    };
    ($name:expr, $metadata:expr, $store:expr, $network:expr) => {{
        let report = $crate::resolver::resolve(&$metadata, None, &$store);
        let (human, json) = $crate::tests::get_reports(&$metadata, report, &$store, $network);
        insta::assert_snapshot!($name, human);
        insta::assert_snapshot!(concat!($name, ".json"), json);
    }};
}

mod aggregate;
mod audit_as_crates_io;
mod certify;
mod crate_policies;
mod explain_audit;
mod import;
mod regenerate_unaudited;
mod registry;
mod renew;
mod store_parsing;
mod trusted;
mod unpublished;
mod vet;
mod violations;
mod wildcard;

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
                    .width(80)
                    .build()
            )
        })).expect("Failed to initialize error handler");

        tracing_subscriber::fmt::fmt()
            .with_max_level(tracing::level_filters::LevelFilter::TRACE)
            .with_target(false)
            .without_time()
            .with_writer(tracing_subscriber::fmt::writer::TestWriter::new())
            .init();

        tokio::runtime::Runtime::new().unwrap()
    };

}

struct MockMetadata {
    packages: Vec<MockPackage>,
    pkgids: Vec<String>,
    idx_by_name_and_ver: BTreeMap<PackageStr<'static>, BTreeMap<VetVersion, usize>>,
}

struct MockPackage {
    name: &'static str,
    version: VetVersion,
    deps: Vec<MockDependency>,
    dev_deps: Vec<MockDependency>,
    build_deps: Vec<MockDependency>,
    targets: Vec<&'static str>,
    is_workspace: bool,
    is_first_party: bool,
}

struct MockDependency {
    name: &'static str,
    version: VetVersion,
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

fn ver(major: u64) -> VetVersion {
    VetVersion {
        semver: semver::Version {
            major,
            minor: 0,
            patch: 0,
            pre: Default::default(),
            build: Default::default(),
        },
        git_rev: None,
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
fn default_exemptions(version: VetVersion, config: &ConfigFile) -> ExemptedDependency {
    ExemptedDependency {
        version,
        criteria: vec![config.default_criteria.clone().into()],
        notes: None,
        suggest: true,
    }
}
fn exemptions(version: VetVersion, criteria: CriteriaStr) -> ExemptedDependency {
    ExemptedDependency {
        version,
        criteria: vec![criteria.to_string().into()],
        notes: None,
        suggest: true,
    }
}

fn delta_audit(from: VetVersion, to: VetVersion, criteria: CriteriaStr) -> AuditEntry {
    AuditEntry {
        who: vec![],
        notes: None,
        criteria: vec![criteria.to_string().into()],
        kind: AuditKind::Delta { from, to },
        importable: true,
        aggregated_from: vec![],
        is_fresh_import: false,
    }
}

fn full_audit(version: VetVersion, criteria: CriteriaStr) -> AuditEntry {
    AuditEntry {
        who: vec![],
        notes: None,
        criteria: vec![criteria.to_string().into()],
        kind: AuditKind::Full { version },
        importable: true,
        aggregated_from: vec![],
        is_fresh_import: false,
    }
}

fn full_audit_m(
    version: VetVersion,
    criteria: impl IntoIterator<Item = impl Into<CriteriaName>>,
) -> AuditEntry {
    AuditEntry {
        who: vec![],
        notes: None,
        criteria: criteria.into_iter().map(|s| s.into().into()).collect(),
        kind: AuditKind::Full { version },
        importable: true,
        aggregated_from: vec![],
        is_fresh_import: false,
    }
}

fn violation_hard(version: VersionReq) -> AuditEntry {
    AuditEntry {
        who: vec![],
        notes: None,
        criteria: vec![SAFE_TO_RUN.to_string().into()],
        kind: AuditKind::Violation { violation: version },
        importable: true,
        aggregated_from: vec![],
        is_fresh_import: false,
    }
}
#[allow(dead_code)]
fn violation(version: VersionReq, criteria: CriteriaStr) -> AuditEntry {
    AuditEntry {
        who: vec![],
        notes: None,
        criteria: vec![criteria.to_string().into()],
        kind: AuditKind::Violation { violation: version },
        importable: true,
        aggregated_from: vec![],
        is_fresh_import: false,
    }
}
#[allow(dead_code)]
fn violation_m(
    version: VersionReq,
    criteria: impl IntoIterator<Item = impl Into<CriteriaName>>,
) -> AuditEntry {
    AuditEntry {
        who: vec![],
        notes: None,
        criteria: criteria.into_iter().map(|s| s.into().into()).collect(),
        kind: AuditKind::Violation { violation: version },
        importable: true,
        aggregated_from: vec![],
        is_fresh_import: false,
    }
}

fn wildcard_audit(user_id: u64, criteria: CriteriaStr) -> WildcardEntry {
    WildcardEntry {
        who: vec![],
        notes: None,
        criteria: vec![criteria.to_string().into()],
        source: CratesSourceId::User { user_id },
        start: mock_months_ago(1).date_naive().into(),
        end: mock_today().into(),
        renew: None,
        aggregated_from: vec![],
        is_fresh_import: false,
    }
}

fn wildcard_audit_m(
    user_id: u64,
    criteria: impl IntoIterator<Item = impl Into<CriteriaName>>,
) -> WildcardEntry {
    WildcardEntry {
        who: vec![],
        notes: None,
        criteria: criteria.into_iter().map(|s| s.into().into()).collect(),
        source: CratesSourceId::User { user_id },
        start: mock_months_ago(1).date_naive().into(),
        end: mock_today().into(),
        renew: None,
        aggregated_from: vec![],
        is_fresh_import: false,
    }
}

fn wildcard_audit_trustpub(trustpub: &str, criteria: CriteriaStr) -> WildcardEntry {
    WildcardEntry {
        who: vec![],
        notes: None,
        criteria: vec![criteria.to_string().into()],
        source: CratesSourceId::TrustedPublisher {
            trusted_publisher: trustpub.to_owned(),
        },
        start: mock_months_ago(1).date_naive().into(),
        end: mock_today().into(),
        renew: None,
        aggregated_from: vec![],
        is_fresh_import: false,
    }
}

fn trusted_entry(user_id: u64, criteria: CriteriaStr) -> TrustEntry {
    TrustEntry {
        notes: None,
        criteria: vec![criteria.to_string().into()],
        source: CratesSourceId::User { user_id },
        start: mock_months_ago(1).date_naive().into(),
        end: mock_today().into(),
        aggregated_from: vec![],
    }
}

fn publisher_entry(version: VetVersion, user_id: u64) -> CratesPublisher {
    CratesPublisher {
        version,
        when: mock_weeks_ago(2).date_naive(),
        source: crate::format::CratesPublisherSource::User {
            user_id,
            user_login: format!("user{user_id}"),
            user_name: None,
        },
        is_fresh_import: false,
    }
}

fn publisher_entry_named(
    version: VetVersion,
    user_id: u64,
    login: &str,
    name: &str,
) -> CratesPublisher {
    CratesPublisher {
        version,
        when: mock_weeks_ago(2).date_naive(),
        source: crate::format::CratesPublisherSource::User {
            user_id,
            user_login: login.to_owned(),
            user_name: Some(name.to_owned()),
        },
        is_fresh_import: false,
    }
}

fn publisher_entry_trustpub(version: VetVersion, trustpub: &str) -> CratesPublisher {
    CratesPublisher {
        version,
        when: mock_weeks_ago(2).date_naive(),
        source: crate::format::CratesPublisherSource::TrustedPublisher {
            trusted_publisher: trustpub.to_owned(),
        },
        is_fresh_import: false,
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

fn audit_as_policy(audit_as_crates_io: Option<bool>) -> PackagePolicyEntry {
    PackagePolicyEntry::Unversioned(PolicyEntry {
        audit_as_crates_io,
        ..default_policy()
    })
}

fn audit_as_policy_with<F: Fn(&mut PolicyEntry)>(
    audit_as_crates_io: Option<bool>,
    alter: F,
) -> PackagePolicyEntry {
    let mut entry = PolicyEntry {
        audit_as_crates_io,
        ..default_policy()
    };
    alter(&mut entry);
    PackagePolicyEntry::Unversioned(entry)
}

fn self_policy(criteria: impl IntoIterator<Item = impl Into<CriteriaName>>) -> PackagePolicyEntry {
    PackagePolicyEntry::Unversioned(PolicyEntry {
        criteria: Some(criteria.into_iter().map(|s| s.into().into()).collect()),
        ..default_policy()
    })
}

fn dep_policy(
    dependency_criteria: impl IntoIterator<
        Item = (
            impl Into<PackageName>,
            impl IntoIterator<Item = impl Into<CriteriaName>>,
        ),
    >,
) -> PackagePolicyEntry {
    PackagePolicyEntry::Unversioned(PolicyEntry {
        dependency_criteria: dependency_criteria
            .into_iter()
            .map(|(k, v)| {
                (
                    k.into().into(),
                    v.into_iter().map(|s| s.into().into()).collect::<Vec<_>>(),
                )
            })
            .collect(),
        ..default_policy()
    })
}

fn criteria(description: &str) -> CriteriaEntry {
    CriteriaEntry {
        description: Some(description.to_owned()),
        description_url: None,
        implies: vec![],
        aggregated_from: vec![],
    }
}

fn criteria_implies(
    description: &str,
    implies: impl IntoIterator<Item = impl Into<CriteriaName>>,
) -> CriteriaEntry {
    CriteriaEntry {
        description: Some(description.to_owned()),
        description_url: None,
        implies: implies.into_iter().map(|s| s.into().into()).collect(),
        aggregated_from: vec![],
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

    fn simple_local_git() -> Self {
        // Identical to `simple` except that `third-party1` is a local git version.
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
                deps: vec![
                    MockDependency {
                        name: "third-party1",
                        version: "10.0.0@git:00112233445566778899aabbccddeeff00112233"
                            .parse()
                            .unwrap(),
                    },
                    dep("third-party2"),
                ],
                ..Default::default()
            },
            MockPackage {
                name: "third-party1",
                version: "10.0.0@git:00112233445566778899aabbccddeeff00112233"
                    .parse()
                    .unwrap(),
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

    /// The `third-party` crate is used as both a first- and third-party crate (with different
    /// versions).
    fn overlapping() -> Self {
        MockMetadata::new(vec![
            MockPackage {
                name: "root-package",
                is_workspace: true,
                is_first_party: true,
                deps: vec![dep("first-party"), dep_ver("third-party", 1)],
                ..Default::default()
            },
            MockPackage {
                name: "first-party",
                is_first_party: true,
                deps: vec![dep_ver("third-party", 2)],
                ..Default::default()
            },
            MockPackage {
                name: "third-party",
                is_first_party: true,
                version: ver(1),
                ..Default::default()
            },
            MockPackage {
                name: "third-party",
                version: ver(2),
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

    fn descriptive() -> Self {
        MockMetadata::new(vec![MockPackage {
            name: "descriptive",
            is_workspace: true,
            is_first_party: true,
            ..Default::default()
        }])
    }

    fn new(packages: Vec<MockPackage>) -> Self {
        let mut pkgids = vec![];
        let mut idx_by_name_and_ver = BTreeMap::<PackageStr, BTreeMap<VetVersion, usize>>::new();

        for (idx, package) in packages.iter().enumerate() {
            let pkgid = if package.is_first_party {
                format!(
                    "{} {} (path+file:///C:/FAKE/{})",
                    package.name, package.version, package.name
                )
            } else if let Some(git_rev) = &package.version.git_rev {
                format!(
                    "{} {} (git+https://github.com/owner/{}#{})",
                    package.name, package.version.semver, package.name, git_rev
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

    fn pkgid_by(&self, name: PackageStr, version: &VetVersion) -> &str {
        &self.pkgids[self.idx_by_name_and_ver[name][version]]
    }

    fn package_by(&self, name: PackageStr, version: &VetVersion) -> &MockPackage {
        &self.packages[self.idx_by_name_and_ver[name][version]]
    }

    fn source(&self, package: &MockPackage) -> Value {
        if package.is_first_party {
            json!(null)
        } else if let Some(git_rev) = &package.version.git_rev {
            format!("git+https://github.com/owner/{}#{}", package.name, git_rev).into()
        } else {
            json!("registry+https://github.com/rust-lang/crates.io-index")
        }
    }

    fn metadata(&self) -> Metadata {
        let meta_json = json!({
            "packages": self.packages.iter().map(|package| json!({
                "name": package.name,
                "version": package.version.semver.to_string(),
                "id": self.pkgid(package),
                "license": "MIT",
                "license_file": null,
                "description": "whatever",
                "source": self.source(package),
                "dependencies": package.deps.iter().chain(&package.dev_deps).chain(&package.build_deps).map(|dep| json!({
                    "name": dep.name,
                    "source": self.source(self.package_by(dep.name, &dep.version)),
                    "req": format!("={}", dep.version.semver),
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
                    let mut all_deps = BTreeMap::<(PackageStr, &VetVersion), Vec<Option<&str>>>::new();
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

fn init_files(
    metadata: &Metadata,
    criteria: impl IntoIterator<Item = (CriteriaName, CriteriaEntry)>,
    default_criteria: &str,
) -> (ConfigFile, AuditsFile, ImportsFile) {
    let mut config = ConfigFile {
        cargo_vet: Default::default(),
        default_criteria: default_criteria.to_owned(),
        imports: Default::default(),
        policy: Default::default(),
        exemptions: Default::default(),
    };
    let audits = AuditsFile {
        criteria: criteria.into_iter().collect(),
        wildcard_audits: SortedMap::new(),
        audits: SortedMap::new(),
        trusted: SortedMap::new(),
    };
    let imports = ImportsFile {
        unpublished: SortedMap::new(),
        publisher: SortedMap::new(),
        audits: SortedMap::new(),
    };

    // Make the root packages use our custom criteria instead of the builtins
    if default_criteria != SAFE_TO_DEPLOY {
        for pkgid in &metadata.workspace_members {
            for package in &metadata.packages {
                if package.id == *pkgid {
                    config.policy.insert(
                        package.name.to_string(),
                        PackagePolicyEntry::Unversioned(PolicyEntry {
                            audit_as_crates_io: None,
                            criteria: Some(vec![default_criteria.to_string().into()]),
                            dev_criteria: Some(vec![default_criteria.to_string().into()]),
                            dependency_criteria: CriteriaMap::new(),
                            notes: None,
                        }),
                    );
                }
            }
        }
    }

    // Use `update_store` to generate exemptions which would allow the tree to
    // be mocked, then deconstruct the store again. Callers may want to
    // initialize the store differently during their tests.
    let mut store = Store::mock(config, audits, imports);
    crate::resolver::update_store(&mock_cfg(metadata), &mut store, |_| {
        crate::resolver::UpdateMode {
            search_mode: crate::resolver::SearchMode::RegenerateExemptions,
            prune_exemptions: true,
            prune_non_importable_audits: true,
            prune_imports: true,
        }
    });

    (store.config, store.audits, store.imports)
}

fn files_inited(metadata: &Metadata) -> (ConfigFile, AuditsFile, ImportsFile) {
    // Criteria hierarchy:
    //
    // * strong-reviewed
    //   * reviewed (default)
    //      * weak-reviewed
    // * fuzzed
    //
    // This lets use mess around with "strong reqs", "weaker reqs", and "unrelated reqs"
    // with "reviewed" as the implicit default everything cares about.

    init_files(
        metadata,
        [
            (
                "strong-reviewed".to_string(),
                criteria_implies("strongly reviewed", ["reviewed"]),
            ),
            (
                "reviewed".to_string(),
                criteria_implies("reviewed", ["weak-reviewed"]),
            ),
            ("weak-reviewed".to_string(), criteria("weakly reviewed")),
            ("fuzzed".to_string(), criteria("fuzzed")),
        ],
        DEFAULT_CRIT,
    )
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
                .entry(package.name.to_string())
                .or_default()
                .push(full_audit(package.vet_version(), DEFAULT_CRIT));
        }
    }
    audits.audits = audited;

    (config, audits, imports)
}

fn builtin_files_inited(metadata: &Metadata) -> (ConfigFile, AuditsFile, ImportsFile) {
    init_files(metadata, [], SAFE_TO_DEPLOY)
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
                .entry(package.name.to_string())
                .or_default()
                .push(full_audit(package.vet_version(), SAFE_TO_DEPLOY));
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
            audited.entry(name.clone()).or_default().push(full_audit_m(
                entry.version,
                entry.criteria.iter().map(|s| &**s).collect::<Vec<_>>(),
            ));
        }
    }
    audits.audits = audited;

    (config, audits, imports)
}

/// Returns a fixed datetime that should be considered `now`: 2023-01-01 12:00 UTC.
fn mock_now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_utc(
        chrono::NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(2023, 1, 1).unwrap(),
            chrono::NaiveTime::from_hms_opt(12, 0, 0).unwrap(),
        ),
        chrono::Utc,
    )
}

/// Returns a fixed datetime that is `months` months ago relative to `mock_now()`
fn mock_months_ago(months: u32) -> chrono::DateTime<chrono::Utc> {
    mock_now() - chrono::Months::new(months)
}

/// Returns a fixed datetime that is `weeks` weeks ago relative to `mock_now()`
fn mock_weeks_ago(weeks: i64) -> chrono::DateTime<chrono::Utc> {
    mock_now() - chrono::Duration::weeks(weeks)
}

/// Returns a fixed date that should be considered `today`: 2023-01-01.
///
/// This is derived from `mock_now()`.
fn mock_today() -> chrono::NaiveDate {
    mock_now().date_naive()
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
            now: mock_now(),
            cache_dir: PathBuf::new(),
            mock_cache: true,
        },
    }
}

fn get_reports(
    metadata: &Metadata,
    report: ResolveReport,
    store: &Store,
    network: Option<&Network>,
) -> (String, String) {
    // FIXME: Figure out how to handle disabling output colours better in tests.
    console::set_colors_enabled(false);
    console::set_colors_enabled_stderr(false);

    let cfg = mock_cfg(metadata);
    let suggest = report.compute_suggest(&cfg, store, network).unwrap();

    let human_output = BasicTestOutput::new();
    report
        .print_human(&human_output.clone().as_dyn(), &cfg, suggest.as_ref())
        .unwrap();
    let json_output = BasicTestOutput::new();
    report
        .print_json(&json_output.clone().as_dyn(), suggest.as_ref())
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
        write!(self, "{initial}");
        if let Some(on_read_line) = &self.on_read_line {
            let response = on_read_line(initial)?;
            writeln!(self, "{response}");
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
                writeln!(self, "<<<EDITING {name}>>>\n{original}");
                match on_edit(original) {
                    Ok(contents) => {
                        writeln!(self, "<<<EDIT OK>>>\n{contents}\n<<<END EDIT>>>");
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

/// Format a diff between the old and new strings for reporting.
fn generate_diff(old: &str, new: &str) -> String {
    similar::utils::diff_lines(similar::Algorithm::Myers, old, new)
        .into_iter()
        .fold(String::new(), |mut out, (tag, line)| {
            let _ = write!(out, "{tag}{line}");
            out
        })
}

/// Generate a diff between two values returned from `Store::mock_commit`.
fn diff_store_commits(old: &SortedMap<String, String>, new: &SortedMap<String, String>) -> String {
    let mut result = String::new();
    let keys = old.keys().chain(new.keys()).collect::<SortedSet<&String>>();
    for key in keys {
        let old = old.get(key).map(|s| &s[..]).unwrap_or("");
        let new = new.get(key).map(|s| &s[..]).unwrap_or("");
        if old == new {
            writeln!(&mut result, "{key}: (unchanged)").unwrap();
            continue;
        }
        let diff = generate_diff(old, new);
        writeln!(&mut result, "{key}:\n{diff}").unwrap();
    }
    result
}

#[derive(Clone)]
struct MockRegistryVersion {
    version: semver::Version,
    published_by: Option<CratesUserId>,
    trustpub: Option<CratesAPITrustpubData>,
    created_at: chrono::DateTime<chrono::Utc>,
}

fn reg_published_by(
    version: VetVersion,
    published_by: Option<CratesUserId>,
    when: chrono::DateTime<chrono::Utc>,
) -> MockRegistryVersion {
    assert!(
        version.git_rev.is_none(),
        "cannot publish a git version to registry"
    );
    MockRegistryVersion {
        version: version.semver,
        published_by,
        trustpub: None,
        created_at: when,
    }
}

fn reg_trustpub_by(
    version: VetVersion,
    trustpub: &str,
    when: chrono::DateTime<chrono::Utc>,
) -> MockRegistryVersion {
    assert!(
        version.git_rev.is_none(),
        "cannot publish a git version to registry"
    );
    let (provider, repository) = trustpub.split_once(':').unwrap();
    assert_eq!(provider, "github");
    MockRegistryVersion {
        version: version.semver,
        published_by: None,
        trustpub: Some(CratesAPITrustpubData::GitHub {
            repository: repository.to_owned(),
        }),
        created_at: when,
    }
}

struct MockRegistryPackage {
    versions: Vec<MockRegistryVersion>,
    metadata: CratesAPICrateMetadata,
}

#[derive(Default)]
struct MockRegistryBuilder {
    users: FastMap<CratesUserId, CratesAPIUser>,
    packages: FastMap<PackageName, MockRegistryPackage>,
}

impl MockRegistryBuilder {
    fn new() -> Self {
        Default::default()
    }

    fn user(&mut self, id: CratesUserId, login: &str, name: &str) -> &mut Self {
        self.users.insert(
            id,
            CratesAPIUser {
                id,
                login: login.to_owned(),
                name: Some(name.to_owned()),
            },
        );
        self
    }

    fn package(&mut self, name: PackageStr<'_>, versions: &[MockRegistryVersion]) -> &mut Self {
        self.package_m(
            name,
            CratesAPICrateMetadata {
                description: None,
                repository: None,
            },
            versions,
        )
    }

    fn package_m(
        &mut self,
        name: PackageStr<'_>,
        metadata: CratesAPICrateMetadata,
        versions: &[MockRegistryVersion],
    ) -> &mut Self {
        // To keep things simple, only handle the URL for 4+ characters in package names for now.
        assert!(name.len() >= 4);
        self.packages.insert(
            name.to_owned(),
            MockRegistryPackage {
                metadata,
                versions: versions.to_owned(),
            },
        );
        self
    }

    fn serve(&self, network: &mut Network) {
        for (name, pkg) in &self.packages {
            // Serve the index entry as part of the http index.
            network.mock_serve(
                format!(
                    "https://index.crates.io/{}/{}/{name}",
                    &name[0..2],
                    &name[2..4]
                ).to_ascii_lowercase(),
               pkg.versions
                    .iter()
                    .map(|v| {
                        serde_json::to_string(&json!({
                            "name": name,
                            "vers": &v.version,
                            "deps": [],
                            "cksum": "90527ab4abff2f0608cdb1a78e2349180e1d92059f59b5a65ce2a1a15a499b73",
                            "features": {},
                            "yanked": false
                        }))
                        .unwrap()
                    })
                    .collect::<Vec<_>>()
                    .join("\n"),
            );

            // Serve the crates.io API to match the http index and host extra metadata.
            //
            // NOTE: crates.io actually serves the API case-insensitively,
            // unlike the http index, which is case-sensitive (and lowercase).
            // Preserving case here matches how we currently construct the API
            // url internally, but may need to be changed in the future.
            network.mock_serve_json(
                format!("https://crates.io/api/v1/crates/{name}"),
                &CratesAPICrate {
                    crate_data: pkg.metadata.clone(),
                    versions: pkg
                        .versions
                        .iter()
                        .map(|v| CratesAPIVersion {
                            created_at: v.created_at,
                            num: v.version.clone(),
                            published_by: v.published_by.map(|id| {
                                let user = &self.users[&id];
                                CratesAPIUser {
                                    id,
                                    login: user.login.clone(),
                                    name: user.name.clone(),
                                }
                            }),
                            trustpub_data: v.trustpub.clone(),
                        })
                        .collect(),
                },
            )
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
