use super::*;

#[test]
fn trusted_full_audit_locked() {
    // (Pass) A a trusted entry for a crate when locked

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, mut imports) = builtin_files_full_audited(&metadata);
    audits.audits.remove("transitive-third-party1");
    audits.trusted.insert(
        "transitive-third-party1".to_owned(),
        vec![trusted_entry(1, SAFE_TO_DEPLOY)],
    );

    imports.publisher.insert(
        "transitive-third-party1".to_owned(),
        vec![publisher_entry(ver(DEFAULT_VER), 1)],
    );

    let store = Store::mock(config, audits, imports);

    assert_report_snapshot!("trusted_full_audit_locked", metadata, store);
}

#[test]
fn trusted_wrong_user_id_locked() {
    // (Fail) A trusted entry for a crate with the wrong user when locked

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, mut imports) = builtin_files_full_audited(&metadata);
    audits.audits.remove("transitive-third-party1");
    audits.trusted.insert(
        "transitive-third-party1".to_owned(),
        vec![trusted_entry(2, SAFE_TO_DEPLOY)],
    );

    imports.publisher.insert(
        "transitive-third-party1".to_owned(),
        vec![publisher_entry(ver(DEFAULT_VER), 1)],
    );

    let store = Store::mock(config, audits, imports);

    assert_report_snapshot!("trusted_wrong_user_id_locked", metadata, store);
}

#[test]
fn trusted_delta_audit_locked() {
    // (Pass) A trusted entry plus delta-audit for a crate when locked

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, mut imports) = builtin_files_full_audited(&metadata);
    audits.audits.insert(
        "transitive-third-party1".to_owned(),
        vec![delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );
    audits.trusted.insert(
        "transitive-third-party1".to_owned(),
        vec![trusted_entry(1, SAFE_TO_DEPLOY)],
    );

    imports.publisher.insert(
        "transitive-third-party1".to_owned(),
        vec![publisher_entry(ver(5), 1)],
    );

    let store = Store::mock(config, audits, imports);

    assert_report_snapshot!("trusted_delta_audit_locked", metadata, store);
}

#[test]
fn trusted_delta_audit_wrong_user_id_locked() {
    // (Fail) A trusted entry plus delta-audit for a crate with the wrong user when locked

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, mut imports) = builtin_files_full_audited(&metadata);
    audits.audits.insert(
        "transitive-third-party1".to_owned(),
        vec![delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );
    audits.trusted.insert(
        "transitive-third-party1".to_owned(),
        vec![trusted_entry(2, SAFE_TO_DEPLOY)],
    );

    imports.publisher.insert(
        "transitive-third-party1".to_owned(),
        vec![publisher_entry(ver(5), 1)],
    );

    let store = Store::mock(config, audits, imports);

    assert_report_snapshot!("trusted_delta_audit_wrong_user_id_locked", metadata, store);
}
