use super::*;

fn get_audit_as_crates_io(cfg: &Config, store: &Store) -> String {
    let mut cache = crate::storage::Cache::acquire(cfg).unwrap();
    let res = crate::check_audit_as_crates_io(cfg, store, &mut cache);
    match res {
        Ok(()) => String::new(),
        Err(e) => format!("{:?}", miette::Report::new(e)),
    }
}

fn get_audit_as_crates_io_json(cfg: &Config, store: &Store) -> String {
    let mut cache = crate::storage::Cache::acquire(cfg).unwrap();
    let res = crate::check_audit_as_crates_io(cfg, store, &mut cache);
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

    let output = get_audit_as_crates_io(&cfg, &store);
    insta::assert_snapshot!("simple-audit-as-crates-io", output);
}

#[test]
fn simple_audit_as_crates_io_all_true() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_full_audited(&metadata);

    for package in &mock.packages {
        config
            .policy
            .insert(package.name.to_owned(), audit_as_policy(Some(true)));
    }

    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io(&cfg, &store);
    insta::assert_snapshot!("simple-audit-as-crates-io-all-true", output);
}

#[test]
fn simple_audit_as_crates_io_all_false() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_full_audited(&metadata);

    for package in &mock.packages {
        config
            .policy
            .insert(package.name.to_owned(), audit_as_policy(Some(false)));
    }

    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io(&cfg, &store);
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

    let output = get_audit_as_crates_io(&cfg, &store);
    insta::assert_snapshot!("complex-audit-as-crates-io", output);
}

#[test]
fn complex_audit_as_crates_io_all_true() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::complex();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_full_audited(&metadata);

    for package in &mock.packages {
        config
            .policy
            .insert(package.name.to_owned(), audit_as_policy(Some(true)));
    }

    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io(&cfg, &store);
    insta::assert_snapshot!("complex-audit-as-crates-io-all-true", output);
}

#[test]
fn complex_audit_as_crates_io_all_false() {
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

    let output = get_audit_as_crates_io(&cfg, &store);
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

    let output = get_audit_as_crates_io(&cfg, &store);
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

    let output = get_audit_as_crates_io(&cfg, &store);
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

    let output = get_audit_as_crates_io(&cfg, &store);
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

    let output = get_audit_as_crates_io(&cfg, &store);
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

    let output = get_audit_as_crates_io(&cfg, &store);
    insta::assert_snapshot!("cycle-audit-as-crates-io", output);
}

#[test]
fn audit_as_crates_io_need_update() {
    // The "root" and "first" packages don't have their versions on crates.io
    // until the index is updated. If an `audit_as_crates_io` entry requires
    // `first` to be on crates.io, and it's not, we'll do an update, which
    // should reveal that `root` also needs to be audited.

    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::haunted_tree();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_full_audited(&metadata);
    config
        .policy
        .insert("first".to_owned(), audit_as_policy(Some(true)));
    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io(&cfg, &store);
    insta::assert_snapshot!("audit-as-crates-io-need-update", output);
}
