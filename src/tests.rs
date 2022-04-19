use std::collections::BTreeMap;

use cargo_metadata::{Metadata, Version};
use serde_json::{json, Value};

use crate::{AuditsFile, ConfigFile, CriteriaEntry, ImportsFile, StableMap, UnauditedDependency};

struct MockMetadata {
    packages: Vec<MockPackage>,
    pkgids: Vec<String>,
    idx_by_name_and_ver: BTreeMap<&'static str, BTreeMap<Version, usize>>,
}

struct MockPackage {
    name: &'static str,
    version: Version,
    deps: Vec<(&'static str, Version)>,
    dev_deps: Vec<(&'static str, Version)>,
    build_deps: Vec<(&'static str, Version)>,
    is_root: bool,
    is_first_party: bool,
}

impl Default for MockPackage {
    fn default() -> Self {
        Self {
            name: "",
            version: ver(1),
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

impl MockMetadata {
    fn simple() -> Self {
        MockMetadata::new(vec![
            MockPackage {
                name: "root-package",
                is_root: true,
                is_first_party: true,
                deps: vec![("first-party", ver(1))],
                ..Default::default()
            },
            MockPackage {
                name: "first-party",
                is_first_party: true,
                deps: vec![("third-party1", ver(1)), ("third-party2", ver(1))],
                ..Default::default()
            },
            MockPackage {
                name: "third-party1",
                deps: vec![("transitive-third-party1", ver(1))],
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
                    "name": dep.0,
                    "source": self.source(self.package_by(dep.0, &dep.1)),
                    "req": format!("={}", dep.1),
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
                        self.pkgid_by(dep.0, &dep.1)
                    }).collect::<Vec<_>>(),
                    "deps": package.deps.iter().map(|dep| json!({
                        "name": dep.0,
                        "pkg": self.pkgid_by(dep.0, &dep.1),
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

    fn init_state(&self) -> (ConfigFile, AuditsFile, ImportsFile) {
        let (mut config, audits, imports) = self.no_unaudited();
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
                    });
            }
        }
        config.unaudited = unaudited;

        (config, audits, imports)
    }

    fn no_unaudited(&self) -> (ConfigFile, AuditsFile, ImportsFile) {
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
        let audits = AuditsFile {
            criteria: StableMap::from_iter(vec![(
                "reviewed".to_string(),
                CriteriaEntry {
                    default: true,
                    implies: vec![],
                    description: String::new(),
                },
            )]),
            audits: StableMap::new(),
        };
        let imports = ImportsFile {
            audits: StableMap::new(),
        };
        (config, audits, imports)
    }
}

#[test]
fn mock_init_state() {
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, audits, imports) = mock.init_state();

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-basic", stdout);
}

#[test]
fn mock_no_unaudited() {
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, audits, imports) = mock.no_unaudited();

    let report = crate::resolver::resolve(&metadata, &config, &audits, &imports);

    let mut stdout = Vec::new();
    report.print_report(&mut stdout).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    insta::assert_snapshot!("mock-no-unaudited", stdout);
}
