use super::*;

#[test]
fn wildcard_full_audit_locked() {
    // (Pass) A wildcard full-audit for a crate when locked

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, mut imports) = builtin_files_full_audited(&metadata);
    audits.audits.remove("transitive-third-party1");
    audits.wildcard_audits.insert(
        "transitive-third-party1".to_owned(),
        vec![wildcard_audit(1, SAFE_TO_DEPLOY)],
    );

    imports.publisher.insert(
        "transitive-third-party1".to_owned(),
        vec![publisher_entry(ver(DEFAULT_VER), 1)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store);

    assert_report_snapshot!("wildcard_full_audit_locked", &metadata, report);
}

#[test]
fn wildcard_full_audit_wrong_user_id_locked() {
    // (Fail) A wildcard full-audit for a crate with the wrong user when locked

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, mut imports) = builtin_files_full_audited(&metadata);
    audits.audits.remove("transitive-third-party1");
    audits.wildcard_audits.insert(
        "transitive-third-party1".to_owned(),
        vec![wildcard_audit(2, SAFE_TO_DEPLOY)],
    );

    imports.publisher.insert(
        "transitive-third-party1".to_owned(),
        vec![publisher_entry(ver(DEFAULT_VER), 1)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store);

    assert_report_snapshot!(
        "wildcard_full_audit_wrong_user_id_locked",
        &metadata,
        report
    );
}

#[test]
fn wildcard_delta_audit_locked() {
    // (Pass) A wildcard plus delta-audit for a crate when locked

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, mut imports) = builtin_files_full_audited(&metadata);
    audits.audits.insert(
        "transitive-third-party1".to_owned(),
        vec![delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );
    audits.wildcard_audits.insert(
        "transitive-third-party1".to_owned(),
        vec![wildcard_audit(1, SAFE_TO_DEPLOY)],
    );

    imports.publisher.insert(
        "transitive-third-party1".to_owned(),
        vec![publisher_entry(ver(5), 1)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store);

    assert_report_snapshot!("wildcard_delta_audit_locked", &metadata, report);
}

#[test]
fn wildcard_delta_audit_wrong_user_id_locked() {
    // (Fail) A wildcard plus delta-audit for a crate with the wrong user when locked

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, mut imports) = builtin_files_full_audited(&metadata);
    audits.audits.insert(
        "transitive-third-party1".to_owned(),
        vec![delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );
    audits.wildcard_audits.insert(
        "transitive-third-party1".to_owned(),
        vec![wildcard_audit(2, SAFE_TO_DEPLOY)],
    );

    imports.publisher.insert(
        "transitive-third-party1".to_owned(),
        vec![publisher_entry(ver(5), 1)],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store);

    assert_report_snapshot!(
        "wildcard_delta_audit_wrong_user_id_locked",
        &metadata,
        report
    );
}

#[test]
fn imported_wildcard_audit() {
    // (Pass) Delta audit based on an imported wildcard audit.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_full_audited(&metadata);
    audits.audits.remove("third-party1");
    audits.audits.insert(
        "transitive-third-party1".to_owned(),
        vec![delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );

    imports.audits.insert(
        FOREIGN.to_owned(),
        AuditsFile {
            criteria: [(
                "example".to_string(),
                criteria("Example criteria description"),
            )]
            .into_iter()
            .collect(),
            wildcard_audits: [
                (
                    "third-party1".to_owned(),
                    vec![wildcard_audit(3, SAFE_TO_DEPLOY)],
                ),
                (
                    "transitive-third-party1".to_owned(),
                    vec![wildcard_audit_m(1, [SAFE_TO_DEPLOY, "example"])],
                ),
            ]
            .into_iter()
            .collect(),
            audits: SortedMap::new(),
        },
    );
    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );

    imports.publisher.insert(
        "transitive-third-party1".to_owned(),
        vec![
            publisher_entry(ver(5), 1),
            publisher_entry(ver(DEFAULT_VER), 2),
        ],
    );
    imports.publisher.insert(
        "third-party1".to_owned(),
        vec![
            publisher_entry(ver(5), 3),
            publisher_entry(ver(DEFAULT_VER), 3),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store);

    assert_report_snapshot!("imported_wildcard_audit", &metadata, report);
}
