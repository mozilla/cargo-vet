use std::collections::BTreeMap;

use cargo_metadata::{Metadata, Version, VersionReq};
use serde_json::{json, Value};

use crate::{
    AuditEntry, AuditsFile, ConfigFile, CriteriaEntry, ImportsFile, StableMap, UnauditedDependency,
};

// Some room above and below
const DEFAULT_VER: u64 = 10;

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

impl MockMetadata {
    fn simple() -> Self {
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

            if !package.build_deps.is_empty() {
                unimplemented!("build-deps aren't mockable yet");
            }
            if !package.dev_deps.is_empty() {
                unimplemented!("dev-deps aren't mockable yet");
            }
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
                "dependencies": package.deps.iter().map(|dep| json!({
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
                "targets": [
                    {
                        "kind": [
                            "lib"
                        ],
                        "crate_types": [
                            "lib"
                        ],
                        "name": package.name,
                        "src_path": "C:\\Users\\fake_user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\DUMMY\\src\\lib.rs",
                        "edition": "2015",
                        "doc": true,
                        "doctest": true,
                        "test": true
                    },
                ],
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
                "nodes": self.packages.iter().map(|package| json!({
                    "id": self.pkgid(package),
                    "dependencies": package.deps.iter().map(|dep| {
                        self.pkgid_by(dep.name, &dep.version)
                    }).collect::<Vec<_>>(),
                    "deps": package.deps.iter().map(|dep| json!({
                        "name": dep.name,
                        "pkg": self.pkgid_by(dep.name, &dep.version),
                        "dep_kinds": [
                            {
                                "kind": null,
                                "target": null,
                            }
                        ],
                    })).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
                "root": null,
            },
            "target_directory": "C:\\FAKE\\target",
            "version": 1,
            "workspace_root": "C:\\FAKE\\",
            "metadata": null,
        });
        serde_json::from_value(meta_json).unwrap()
    }

    fn files_full_audited(&self) -> (ConfigFile, AuditsFile, ImportsFile) {
        let (config, mut audits, imports) = self.files_no_unaudited();

        let mut audited = StableMap::<String, Vec<AuditEntry>>::new();
        for package in &self.packages {
            if !package.is_first_party {
                audited
                    .entry(package.name.to_string())
                    .or_insert(vec![])
                    .push(AuditEntry::full_audit(package.version.clone()));
            }
        }
        audits.audits = audited;

        (config, audits, imports)
    }

    fn files_inited(&self) -> (ConfigFile, AuditsFile, ImportsFile) {
        let (mut config, audits, imports) = self.files_no_unaudited();

        let mut unaudited = StableMap::<String, Vec<UnauditedDependency>>::new();
        for package in &self.packages {
            if !package.is_first_party {
                unaudited
                    .entry(package.name.to_string())
                    .or_insert(vec![])
                    .push(UnauditedDependency {
                        version: package.version.clone(),
                        notes: None,
                        suggest: true,
                        criteria: None,
                    });
            }
        }
        config.unaudited = unaudited;

        (config, audits, imports)
    }

    fn files_no_unaudited(&self) -> (ConfigFile, AuditsFile, ImportsFile) {
        let config = ConfigFile {
            imports: StableMap::new(),
            unaudited: StableMap::new(),
            policy: crate::PolicyTable {
                criteria: None,
                dependency_criteria: None,
                build_and_dev_criteria: None,
                targets: None,
                build_and_dev_targets: None,
            },
        };

        // Criteria hierarchy:
        //
        // * strong-reviewed
        //   * reviewed (default)
        //      * weak-reviewed
        // * fuzzed
        //
        // This lets use mess around with "strong reqs", "weaker reqs", and "unrelated reqs"
        // with "reviewed" as the implicit default everything cares about.

        let audits = AuditsFile {
            criteria: StableMap::from_iter(vec![
                (
                    "strong-reviewed".to_string(),
                    CriteriaEntry {
                        default: false,
                        implies: vec!["reviewed".to_string()],
                        description: String::new(),
                    },
                ),
                (
                    "reviewed".to_string(),
                    CriteriaEntry {
                        default: true,
                        implies: vec!["weak-reviewed".to_string()],
                        description: String::new(),
                    },
                ),
                (
                    "weak-reviewed".to_string(),
                    CriteriaEntry {
                        default: false,
                        implies: vec![],
                        description: String::new(),
                    },
                ),
                (
                    "fuzzed".to_string(),
                    CriteriaEntry {
                        default: false,
                        implies: vec![],
                        description: String::new(),
                    },
                ),
            ]),
            audits: StableMap::new(),
        };
        let imports = ImportsFile {
            audits: StableMap::new(),
        };
        (config, audits, imports)
    }
}

fn unaudited(audits: &AuditsFile, version: Version) -> UnauditedDependency {
    let defaults = audits
        .criteria
        .iter()
        .filter_map(|(criteria, entry)| {
            if entry.default {
                Some(criteria.clone())
            } else {
                None
            }
        })
        .collect();

    UnauditedDependency {
        version,
        criteria: Some(defaults),
        notes: None,
        suggest: true,
    }
}

#[test]
fn mock_simple_init() {
    // (Pass) Should look the same as a fresh 'vet init'.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, audits, imports) = mock.files_inited();

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-init", stdout);
}

#[test]
fn mock_simple_no_unaudited() {
    // (Fail) Should look the same as a fresh 'vet init' but with all 'unaudited' entries deleted.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, audits, imports) = mock.files_no_unaudited();

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-no-unaudited", stdout);
}

#[test]
fn mock_simple_full_audited() {
    // (Pass) All entries have direct full audits.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, audits, imports) = mock.files_full_audited();

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-full-audited", stdout);
}

#[test]
fn mock_simple_forbidden_unaudited() {
    // (Fail) All marked 'unaudited' but a 'violation' entry matches a current version.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = mock.files_inited();

    let violation = VersionReq::parse(&format!("={DEFAULT_VER}")).unwrap();
    audits
        .audits
        .entry("third-party1".to_string())
        .or_insert(vec![])
        .push(AuditEntry::violation(violation));

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-forbidden-unaudited", stdout);
}

#[test]
fn mock_simple_missing_transitive() {
    // (Fail) Missing an audit for a transitive dep

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = mock.files_full_audited();

    audits.audits["transitive-third-party1"].clear();

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-missing-transitive", stdout);
}

#[test]
fn mock_simple_missing_direct_internal() {
    // (Fail) Missing an audit for a direct dep that has children

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = mock.files_full_audited();

    audits.audits["third-party1"].clear();

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-missing-direct-internal", stdout);
}

#[test]
fn mock_simple_missing_direct_leaf() {
    // (Fail) Missing an entry for direct dep that has no children

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = mock.files_full_audited();

    audits.audits["third-party2"].clear();

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-missing-direct-leaf", stdout);
}

#[test]
fn mock_simple_missing_leaves() {
    // (Fail) Missing all leaf audits (but not the internal)

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = mock.files_full_audited();

    audits.audits["third-party2"].clear();
    audits.audits["transitive-third-party1"].clear();

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-missing-leaves", stdout);
}

#[test]
fn mock_simple_weaker_transitive_req() {
    // (Pass) A third-party dep with weaker requirements on a child dep

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = mock.files_full_audited();

    let trans_audits = &mut audits.audits["transitive-third-party1"];
    trans_audits.clear();
    trans_audits.push(AuditEntry {
        criteria: Some(vec!["weak-reviewed".to_string()]),
        ..AuditEntry::full_audit(ver(DEFAULT_VER))
    });

    let direct_audits = &mut audits.audits["third-party1"];
    direct_audits.clear();
    direct_audits.push(AuditEntry {
        dependency_criteria: Some(
            [(
                "transitive-third-party1".to_string(),
                vec!["weak-reviewed".to_string()],
            )]
            .into_iter()
            .collect(),
        ),
        ..AuditEntry::full_audit(ver(DEFAULT_VER))
    });

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-weaker-transitive-req", stdout);
}

#[test]
fn mock_simple_weaker_transitive_req_using_implies() {
    // (Pass) A third-party dep with weaker requirements on a child dep
    // but the child dep actually has *super* reqs, to check that implies works

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = mock.files_full_audited();

    let trans_audits = &mut audits.audits["transitive-third-party1"];
    trans_audits.clear();
    trans_audits.push(AuditEntry {
        criteria: Some(vec!["strong-reviewed".to_string()]),
        ..AuditEntry::full_audit(ver(DEFAULT_VER))
    });

    let direct_audits = &mut audits.audits["third-party1"];
    direct_audits.clear();
    direct_audits.push(AuditEntry {
        dependency_criteria: Some(
            [(
                "transitive-third-party1".to_string(),
                vec!["weak-reviewed".to_string()],
            )]
            .into_iter()
            .collect(),
        ),
        ..AuditEntry::full_audit(ver(DEFAULT_VER))
    });

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-weaker-transitive-req-using-implies", stdout);
}

#[test]
fn mock_simple_lower_version_review() {
    // (Fail) A dep that has a review but for a lower version.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = mock.files_full_audited();

    let direct_audits = &mut audits.audits["third-party1"];
    direct_audits.clear();
    direct_audits.push(AuditEntry::full_audit(ver(DEFAULT_VER - 1)));

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-lower-version-review", stdout);
}

#[test]
fn mock_simple_higher_version_review() {
    // (Fail) A dep that has a review but for a higher version.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = mock.files_full_audited();

    let direct_audits = &mut audits.audits["third-party1"];
    direct_audits.clear();
    direct_audits.push(AuditEntry::full_audit(ver(DEFAULT_VER + 1)));

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-higher-version-review", stdout);
}

#[test]
fn mock_simple_higher_and_lower_version_review() {
    // (Fail) A dep that has a review but for both a higher and lower version.
    // Once I mock out fake diffs it should prefer the lower one because the
    // system will make application size grow quadratically.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = mock.files_full_audited();

    let direct_audits = &mut audits.audits["third-party1"];
    direct_audits.clear();
    direct_audits.push(AuditEntry::full_audit(ver(DEFAULT_VER - 1)));
    direct_audits.push(AuditEntry::full_audit(ver(DEFAULT_VER + 1)));

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-higher-and-lower-version-review", stdout);
}

#[test]
fn mock_simple_reviewed_too_weakly() {
    // (Fail) A dep has a review but the criteria is too weak

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = mock.files_full_audited();

    let trans_audits = &mut audits.audits["transitive-third-party1"];
    trans_audits.clear();
    trans_audits.push(AuditEntry {
        criteria: Some(vec!["weak-reviewed".to_string()]),
        ..AuditEntry::full_audit(ver(DEFAULT_VER))
    });

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-reviewed-too-weakly", stdout);
}

#[test]
fn mock_simple_delta_to_unaudited() {
    // (Pass) A dep has a delta to an unaudited entry

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = mock.files_full_audited();

    let direct_audits = &mut audits.audits["third-party1"];
    direct_audits.clear();
    direct_audits.push(AuditEntry::delta_audit(
        ver(DEFAULT_VER - 5),
        ver(DEFAULT_VER),
    ));

    let direct_unaudited = &mut config.unaudited;
    direct_unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(&audits, ver(DEFAULT_VER - 5))],
    );

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-delta-to-unaudited", stdout);
}

#[test]
fn mock_simple_delta_to_unaudited_overshoot() {
    // (Fail) A dep has a delta but it overshoots the unaudited entry.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = mock.files_full_audited();

    let direct_audits = &mut audits.audits["third-party1"];
    direct_audits.clear();
    direct_audits.push(AuditEntry::delta_audit(
        ver(DEFAULT_VER - 7),
        ver(DEFAULT_VER),
    ));

    let direct_unaudited = &mut config.unaudited;
    direct_unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(&audits, ver(DEFAULT_VER - 5))],
    );

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-delta-to-unaudited-overshoot", stdout);
}

#[test]
fn mock_simple_delta_to_unaudited_undershoot() {
    // (Fail) A dep has a delta but it undershoots the unaudited entry.

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = mock.files_full_audited();

    let direct_audits = &mut audits.audits["third-party1"];
    direct_audits.clear();
    direct_audits.push(AuditEntry::delta_audit(
        ver(DEFAULT_VER - 3),
        ver(DEFAULT_VER),
    ));

    let direct_unaudited = &mut config.unaudited;
    direct_unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(&audits, ver(DEFAULT_VER - 5))],
    );

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-delta-to-unaudited-undershoot", stdout);
}

#[test]
fn mock_simple_delta_to_full_audit() {
    // (Pass) A dep has a delta to a fully audited entry

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = mock.files_full_audited();

    let direct_audits = &mut audits.audits["third-party1"];
    direct_audits.clear();
    direct_audits.push(AuditEntry::delta_audit(
        ver(DEFAULT_VER - 5),
        ver(DEFAULT_VER),
    ));
    direct_audits.push(AuditEntry::full_audit(ver(DEFAULT_VER - 5)));

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-delta-to-full-audit", stdout);
}

#[test]
fn mock_simple_delta_to_full_audit_overshoot() {
    // (Fail) A dep has a delta to a fully audited entry but overshoots

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = mock.files_full_audited();

    let direct_audits = &mut audits.audits["third-party1"];
    direct_audits.clear();
    direct_audits.push(AuditEntry::delta_audit(
        ver(DEFAULT_VER - 7),
        ver(DEFAULT_VER),
    ));
    direct_audits.push(AuditEntry::full_audit(ver(DEFAULT_VER - 5)));

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-delta-to-full-audit-overshoot", stdout);
}

#[test]
fn mock_simple_delta_to_full_audit_undershoot() {
    // (Fail) A dep has a delta to a fully audited entry but undershoots

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = mock.files_full_audited();

    let direct_audits = &mut audits.audits["third-party1"];
    direct_audits.clear();
    direct_audits.push(AuditEntry::delta_audit(
        ver(DEFAULT_VER - 3),
        ver(DEFAULT_VER),
    ));
    direct_audits.push(AuditEntry::full_audit(ver(DEFAULT_VER - 5)));

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-delta-to-full-audit-undershoot", stdout);
}

#[test]
fn mock_simple_reverse_delta_to_full_audit() {
    // (Pass) A dep has a *reverse* delta to a fully audited entry

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = mock.files_full_audited();

    let direct_audits = &mut audits.audits["third-party1"];
    direct_audits.clear();
    direct_audits.push(AuditEntry::delta_audit(
        ver(DEFAULT_VER + 5),
        ver(DEFAULT_VER),
    ));
    direct_audits.push(AuditEntry::full_audit(ver(DEFAULT_VER + 5)));

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-reverse-delta-to-full-audit", stdout);
}

#[test]
fn mock_simple_reverse_delta_to_unaudited() {
    // (Pass) A dep has a *reverse* delta to an unaudited entry

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = mock.files_full_audited();

    let direct_audits = &mut audits.audits["third-party1"];
    direct_audits.clear();
    direct_audits.push(AuditEntry::delta_audit(
        ver(DEFAULT_VER + 5),
        ver(DEFAULT_VER),
    ));

    let direct_unaudited = &mut config.unaudited;
    direct_unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(&audits, ver(DEFAULT_VER + 5))],
    );

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-reverse-delta-to-unaudited", stdout);
}

#[test]
fn mock_simple_wrongly_reversed_delta_to_unaudited() {
    // (Fail) A dep has a *reverse* delta to an unaudited entry but they needed a normal one

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = mock.files_full_audited();

    let direct_audits = &mut audits.audits["third-party1"];
    direct_audits.clear();
    direct_audits.push(AuditEntry::delta_audit(
        ver(DEFAULT_VER),
        ver(DEFAULT_VER - 5),
    ));

    let direct_unaudited = &mut config.unaudited;
    direct_unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(&audits, ver(DEFAULT_VER - 5))],
    );

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-wrongly-reversed-delta-to-unaudited", stdout);
}

#[test]
fn mock_simple_wrongly_reversed_delta_to_full_audit() {
    // (Fail) A dep has a *reverse* delta to a fully audited entry but they needed a normal one

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = mock.files_full_audited();

    let direct_audits = &mut audits.audits["third-party1"];
    direct_audits.clear();
    direct_audits.push(AuditEntry::delta_audit(
        ver(DEFAULT_VER),
        ver(DEFAULT_VER - 5),
    ));
    direct_audits.push(AuditEntry::full_audit(ver(DEFAULT_VER - 5)));

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-wrongly-reversed-delta-to-full-audit", stdout);
}

#[test]
fn mock_simple_needed_reversed_delta_to_unaudited() {
    // (Fail) A dep has a delta to an unaudited entry but they needed a reversed one

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = mock.files_full_audited();

    let direct_audits = &mut audits.audits["third-party1"];
    direct_audits.clear();
    direct_audits.push(AuditEntry::delta_audit(
        ver(DEFAULT_VER),
        ver(DEFAULT_VER + 5),
    ));

    let direct_unaudited = &mut config.unaudited;
    direct_unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(&audits, ver(DEFAULT_VER + 5))],
    );

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-needed-reversed-delta-to-unaudited", stdout);
}

#[test]
fn mock_simple_delta_to_unaudited_too_weak() {
    // (Fail) A dep has a delta to an unaudited entry but it's too weak

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = mock.files_full_audited();

    let direct_audits = &mut audits.audits["third-party1"];
    direct_audits.clear();
    direct_audits.push(AuditEntry {
        criteria: Some(vec!["weak-reviewed".to_string()]),
        ..AuditEntry::delta_audit(ver(DEFAULT_VER - 5), ver(DEFAULT_VER))
    });

    let direct_unaudited = &mut config.unaudited;
    direct_unaudited.insert(
        "third-party1".to_string(),
        vec![unaudited(&audits, ver(DEFAULT_VER - 5))],
    );

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-delta-to-unaudited-too-weak", stdout);
}

#[test]
fn mock_simple_delta_to_full_audit_too_weak() {
    // (Fail) A dep has a delta to a fully audited entry but it's too weak

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = mock.files_full_audited();

    let direct_audits = &mut audits.audits["third-party1"];
    direct_audits.clear();
    direct_audits.push(AuditEntry {
        criteria: Some(vec!["weak-reviewed".to_string()]),
        ..AuditEntry::delta_audit(ver(DEFAULT_VER - 5), ver(DEFAULT_VER))
    });
    direct_audits.push(AuditEntry::full_audit(ver(DEFAULT_VER - 5)));

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-delta-to-full-audit-too-weak", stdout);
}

#[test]
fn mock_simple_delta_to_too_weak_full_audit() {
    // (Fail) A dep has a delta to a fully audited entry but it's too weak

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = mock.files_full_audited();

    let direct_audits = &mut audits.audits["third-party1"];
    direct_audits.clear();
    direct_audits.push(AuditEntry::delta_audit(
        ver(DEFAULT_VER - 5),
        ver(DEFAULT_VER),
    ));
    direct_audits.push(AuditEntry {
        criteria: Some(vec!["weak-reviewed".to_string()]),
        ..AuditEntry::full_audit(ver(DEFAULT_VER - 5))
    });

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-simple-delta-to-too-weak-full-audit", stdout);
}
