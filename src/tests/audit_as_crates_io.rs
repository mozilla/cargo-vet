use super::*;

fn build_registry(network: &mut Network, extra_packages: &[&str]) {
    let mut packages = vec![
        "root-package",
        "first-party",
        "firstA",
        "firstAB",
        "firstB",
        "firstB-nodeps",
        "descriptive",
    ];
    packages.extend_from_slice(extra_packages);

    let mut registry = MockRegistryBuilder::new();
    registry.user(1, "user1", "User One");
    for package in packages {
        registry.package_m(
            package,
            CratesAPICrateMetadata {
                description: Some(if package == "descriptive" {
                    "descriptive".to_owned()
                } else {
                    "whatever".to_owned()
                }),
                repository: None,
            },
            &[reg_published_by(
                ver(DEFAULT_VER),
                Some(1),
                mock_months_ago(12),
            )],
        );
    }
    registry.serve(network);
}

fn get_audit_as_crates_io(cfg: &Config, store: &Store, add_packages_to_index: bool) -> String {
    let mut cache = crate::storage::Cache::acquire(cfg).unwrap();
    let mut network = crate::network::Network::new_mock();
    build_registry(
        &mut network,
        if add_packages_to_index {
            &["first", "root"]
        } else {
            &[]
        },
    );
    let res = tokio::runtime::Handle::current().block_on(crate::check_audit_as_crates_io(
        cfg,
        store,
        Some(&network),
        &mut cache,
    ));
    match res {
        Ok(()) => String::new(),
        Err(e) => format!("{:?}", miette::Report::new(e)),
    }
}

fn get_audit_as_crates_io_no_network(cfg: &Config, store: &Store) -> String {
    let mut cache = crate::storage::Cache::acquire(cfg).unwrap();
    let res = tokio::runtime::Handle::current().block_on(crate::check_audit_as_crates_io(
        cfg, store, None, &mut cache,
    ));
    match res {
        Ok(()) => String::new(),
        Err(e) => format!("{:?}", miette::Report::new(e)),
    }
}

fn get_audit_as_crates_io_json(cfg: &Config, store: &Store) -> String {
    let mut cache = crate::storage::Cache::acquire(cfg).unwrap();
    let mut network = crate::network::Network::new_mock();
    build_registry(&mut network, &[]);
    let res = tokio::runtime::Handle::current().block_on(crate::check_audit_as_crates_io(
        cfg,
        store,
        Some(&network),
        &mut cache,
    ));
    match res {
        Ok(()) => String::new(),
        Err(e) => {
            let handler = miette::JSONReportHandler::new();
            let mut output = String::new();
            handler.render_report(&mut output, &e).unwrap();
            output
        }
    }
}

#[test]
fn simple_audit_as_crates_io() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_full_audited(&metadata);
    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io(&cfg, &store, false);
    insta::assert_snapshot!("simple-audit-as-crates-io", output);
}

#[test]
fn simple_audit_as_crates_io_no_network() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_full_audited(&metadata);
    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io_no_network(&cfg, &store);
    insta::assert_snapshot!("simple-audit-as-crates-io-no-network", output);
}

#[test]
fn simple_audit_as_crates_io_no_network_existing_audits() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_full_audited(&metadata);
    audits
        .audits
        .entry("first-party".to_owned())
        .or_default()
        .push(full_audit(ver(10), SAFE_TO_DEPLOY));
    {
        let root_pkg_entry = audits.audits.entry("root-package".to_owned()).or_default();
        root_pkg_entry.push(full_audit(ver(9), SAFE_TO_DEPLOY));
        root_pkg_entry.push(delta_audit(ver(9), ver(10), SAFE_TO_DEPLOY));
    }
    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io_no_network(&cfg, &store);
    insta::assert_snapshot!(
        "simple-audit-as-crates-io-no-network-existing-audit",
        output
    );
}

#[test]
fn simple_audit_as_crates_io_all_true() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_full_audited(&metadata);

    for package in &mock.packages {
        if package.is_first_party {
            config
                .policy
                .insert(package.name.to_owned(), audit_as_policy(Some(true)));
        }
    }

    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io(&cfg, &store, false);
    insta::assert_snapshot!("simple-audit-as-crates-io-all-true", output);
}

#[test]
fn simple_audit_as_crates_io_all_false() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_full_audited(&metadata);

    for package in &mock.packages {
        if package.is_first_party {
            config
                .policy
                .insert(package.name.to_owned(), audit_as_policy(Some(false)));
        }
    }

    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io(&cfg, &store, false);
    insta::assert_snapshot!("simple-audit-as-crates-io-all-false", output);
}

#[test]
fn complex_audit_as_crates_io() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_full_audited(&metadata);
    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io(&cfg, &store, false);
    insta::assert_snapshot!("complex-audit-as-crates-io", output);
}

#[test]
fn complex_audit_as_crates_io_all_true() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_full_audited(&metadata);

    for package in &mock.packages {
        if package.is_first_party {
            config
                .policy
                .insert(package.name.to_owned(), audit_as_policy(Some(true)));
        }
    }

    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io(&cfg, &store, false);
    insta::assert_snapshot!("complex-audit-as-crates-io-all-true", output);
}

#[test]
fn complex_audit_as_crates_io_all_false() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_full_audited(&metadata);

    for package in &mock.packages {
        if package.is_first_party {
            config
                .policy
                .insert(package.name.to_owned(), audit_as_policy(Some(false)));
        }
    }

    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io(&cfg, &store, false);
    insta::assert_snapshot!("complex-audit-as-crates-io-all-false", output);
}

#[test]
fn complex_audit_as_crates_io_max_wrong() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_full_audited(&metadata);

    config
        .policy
        .insert("rootA".to_owned(), audit_as_policy(Some(true)));
    config
        .policy
        .insert("rootB".to_owned(), audit_as_policy(Some(true)));

    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io(&cfg, &store, false);
    insta::assert_snapshot!("complex-audit-as-crates-io-max-wrong", output);
}

#[test]
fn complex_audit_as_crates_io_max_wrong_json() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_full_audited(&metadata);

    config
        .policy
        .insert("rootA".to_owned(), audit_as_policy(Some(true)));
    config
        .policy
        .insert("rootB".to_owned(), audit_as_policy(Some(true)));

    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io_json(&cfg, &store);
    insta::assert_snapshot!("complex-audit-as-crates-io-max-wrong-json", output);
}

#[test]
fn simple_deps_audit_as_crates_io() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::simple_deps();
    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_full_audited(&metadata);
    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io(&cfg, &store, false);
    insta::assert_snapshot!("simple-deps-audit-as-crates-io", output);
}

#[test]
fn dev_detection_audit_as_crates_io() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::dev_detection();
    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_full_audited(&metadata);
    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io(&cfg, &store, false);
    insta::assert_snapshot!("dev-detection-audit-as-crates-io", output);
}

#[test]
fn haunted_audit_as_crates_io() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::haunted_tree();
    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_full_audited(&metadata);
    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io(&cfg, &store, true);
    insta::assert_snapshot!("haunted-audit-as-crates-io", output);
}

#[test]
fn cycle_audit_as_crates_io() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::cycle();
    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_full_audited(&metadata);
    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io(&cfg, &store, false);
    insta::assert_snapshot!("cycle-audit-as-crates-io", output);
}

#[test]
fn audit_as_crates_io_non_first_party() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_full_audited(&metadata);

    for package in &mock.packages {
        config
            .policy
            .insert(package.name.to_owned(), audit_as_policy(Some(false)));
    }

    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io(&cfg, &store, false);
    insta::assert_snapshot!("audit-as-crates-io-non-first-party", output);
}

#[test]
fn audit_as_crates_io_metadata_mismatch() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::descriptive();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_full_audited(&metadata);

    config
        .policy
        .insert("descriptive".to_owned(), audit_as_policy(Some(true)));

    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io(&cfg, &store, true);
    insta::assert_snapshot!("audit-as-crates-io-metadata-mismatch", output);
}
