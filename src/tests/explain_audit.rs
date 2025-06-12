use super::*;

#[test]
fn test_explain_audit_paths() {
    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_no_exemptions(&metadata);

    audits.audits.insert(
        "third-party".to_owned(),
        vec![
            full_audit(ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(5), ver(3), SAFE_TO_DEPLOY),
            delta_audit(ver(3), ver(9), SAFE_TO_DEPLOY),
            delta_audit(ver(9), ver(10), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);

    let output = BasicTestOutput::new();
    crate::do_cmd_explain_audit(
        &output.clone().as_dyn(),
        &store,
        "third-party",
        &ver(10),
        SAFE_TO_DEPLOY,
    )
    .unwrap();

    insta::assert_snapshot!(output.to_string());
}

#[test]
fn test_explain_audit_unpublished() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::descriptive();
    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_inited(&metadata);

    config.exemptions.remove("descriptive");
    config
        .policy
        .insert("descriptive".to_owned(), audit_as_policy(Some(true)));
    imports.unpublished.insert(
        "descriptive".to_owned(),
        vec![crate::format::UnpublishedEntry {
            version: ver(DEFAULT_VER),
            audited_as: ver(8),
            still_unpublished: false,
            is_fresh_import: false,
        }],
    );
    audits.audits.insert(
        "descriptive".to_owned(),
        vec![full_audit(ver(8), SAFE_TO_DEPLOY)],
    );

    let store = Store::mock(config, audits, imports);

    let output = BasicTestOutput::new();
    crate::do_cmd_explain_audit(
        &output.clone().as_dyn(),
        &store,
        "descriptive",
        &ver(10),
        SAFE_TO_DEPLOY,
    )
    .unwrap();

    insta::assert_snapshot!(output.to_string());
}

#[test]
fn test_explain_audit_wildcard() {
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

    let output = BasicTestOutput::new();
    crate::do_cmd_explain_audit(
        &output.clone().as_dyn(),
        &store,
        "transitive-third-party1",
        &ver(10),
        SAFE_TO_DEPLOY,
    )
    .unwrap();

    insta::assert_snapshot!(output.to_string());
}

#[test]
fn test_explain_audit_incomplete() {
    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_no_exemptions(&metadata);

    audits.audits.insert(
        "third-party".to_owned(),
        vec![
            full_audit(ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(5), ver(3), SAFE_TO_DEPLOY),
            delta_audit(ver(3), ver(9), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);

    let output = BasicTestOutput::new();
    crate::do_cmd_explain_audit(
        &output.clone().as_dyn(),
        &store,
        "third-party",
        &ver(10),
        SAFE_TO_DEPLOY,
    )
    .unwrap();

    insta::assert_snapshot!(output.to_string());
}
