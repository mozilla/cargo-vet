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

    assert_report_snapshot!("wildcard_full_audit_locked", metadata, store);
}

#[test]
fn wildcard_full_audit_locked_trustpub() {
    // (Pass) A wildcard full-audit using trustpub for a crate when locked

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, mut imports) = builtin_files_full_audited(&metadata);
    audits.audits.remove("transitive-third-party1");
    audits.wildcard_audits.insert(
        "transitive-third-party1".to_owned(),
        vec![wildcard_audit_trustpub(
            "github:testing/transitive-third-party1",
            SAFE_TO_DEPLOY,
        )],
    );

    imports.publisher.insert(
        "transitive-third-party1".to_owned(),
        vec![publisher_entry_trustpub(
            ver(DEFAULT_VER),
            "github:testing/transitive-third-party1",
        )],
    );

    let store = Store::mock(config, audits, imports);

    assert_report_snapshot!("wildcard_full_audit_locked_trustpub", metadata, store);
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

    assert_report_snapshot!("wildcard_full_audit_wrong_user_id_locked", metadata, store);
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

    assert_report_snapshot!("wildcard_delta_audit_locked", metadata, store);
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

    assert_report_snapshot!("wildcard_delta_audit_wrong_user_id_locked", metadata, store);
}

#[test]
fn imported_wildcard_audit() {
    // (Pass) Delta audit based on an imported wildcard audit.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_full_audited(&metadata);
    audits
        .criteria
        .insert("example".to_string(), criteria("example criteria"));
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
            trusted: SortedMap::new(),
        },
    );
    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            criteria_map: [(
                "example".to_owned().into(),
                vec!["example".to_owned().into()],
            )]
            .into_iter()
            .collect(),
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

    assert_report_snapshot!("imported_wildcard_audit", metadata, store);
}
