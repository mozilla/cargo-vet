use super::*;

fn get_exemptions(store: &Store) -> String {
    toml_edit::ser::to_string_pretty(&store.config.exemptions).unwrap()
}

#[test]
fn builtin_simple_exemptions_not_a_real_dep_regenerate() {
    // (Pass) there's an exemptions entry for a package that isn't in our tree at all.
    // Should strip the result and produce an empty exemptions file.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_full_audited(&metadata);

    config.exemptions.insert(
        "fake-dep".to_string(),
        vec![exemptions(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_exemptions(&cfg, &mut store, None).unwrap();

    let exemptions = get_exemptions(&store);
    insta::assert_snapshot!("builtin-simple-not-a-real-dep-regenerate", exemptions);
}

#[test]
fn builtin_simple_deps_exemptions_overbroad_regenerate() {
    // (Pass) the exemptions entry is needed but it's overbroad
    // Should downgrade from safe-to-deploy to safe-to-run

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple_deps();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert("dev".to_string(), vec![]);

    config.exemptions.insert(
        "dev".to_string(),
        vec![exemptions(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_exemptions(&cfg, &mut store, None).unwrap();

    let exemptions = get_exemptions(&store);
    insta::assert_snapshot!("builtin-simple-unaudited-overbroad-regenerate", exemptions);
}

#[test]
fn builtin_complex_exemptions_twins_regenerate() {
    // (Pass) two versions of a crate exist and both are exemptions and they're needed
    // Should be a no-op and both entries should remain

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::complex();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert("third-core".to_string(), vec![]);

    config.exemptions.insert(
        "third-core".to_string(),
        vec![
            exemptions(ver(DEFAULT_VER), SAFE_TO_DEPLOY),
            exemptions(ver(5), SAFE_TO_DEPLOY),
        ],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_exemptions(&cfg, &mut store, None).unwrap();

    let exemptions = get_exemptions(&store);
    insta::assert_snapshot!("builtin-simple-unaudited-twins-regenerate", exemptions);
}

#[test]
fn builtin_complex_exemptions_partial_twins_regenerate() {
    // (Pass) two versions of a crate exist and one is exemptions and one is audited
    // Should be a no-op and both entries should remain

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::complex();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-core".to_string(),
        vec![full_audit(ver(5), SAFE_TO_DEPLOY)],
    );

    config.exemptions.insert(
        "third-core".to_string(),
        vec![exemptions(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_exemptions(&cfg, &mut store, None).unwrap();

    let exemptions = get_exemptions(&store);
    insta::assert_snapshot!(
        "builtin-simple-unaudited-partial-twins-regenerate",
        exemptions
    );
}

#[test]
fn builtin_simple_exemptions_in_delta_regenerate() {
    // (Pass) An audited entry overlaps a delta and isn't needed
    // Should emit an empty exemptions file

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            full_audit(ver(3), SAFE_TO_DEPLOY),
            delta_audit(ver(3), ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    config.exemptions.insert(
        "third-party1".to_string(),
        vec![exemptions(ver(5), SAFE_TO_DEPLOY)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_exemptions(&cfg, &mut store, None).unwrap();

    let exemptions = get_exemptions(&store);
    insta::assert_snapshot!("builtin-simple-unaudited-in-delta-regenerate", exemptions);
}

#[test]
fn builtin_simple_exemptions_in_full_regenerate() {
    // (Pass) An audited entry overlaps a full audit and isn't needed
    // Should emit an empty exemptions file

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            full_audit(ver(3), SAFE_TO_DEPLOY),
            delta_audit(ver(3), ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    config.exemptions.insert(
        "third-party1".to_string(),
        vec![exemptions(ver(3), SAFE_TO_DEPLOY)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_exemptions(&cfg, &mut store, None).unwrap();

    let exemptions = get_exemptions(&store);
    insta::assert_snapshot!("builtin-simple-unaudited-in-full-regenerate", exemptions);
}

#[test]
fn builtin_simple_deps_exemptions_adds_uneeded_criteria_regenerate() {
    // (Pass) An audited entry overlaps a full audit which is the cur version and isn't needed
    // Should produce an empty exemptions

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple_deps();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "dev".to_string(),
        vec![
            full_audit(ver(5), SAFE_TO_RUN),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    config
        .exemptions
        .insert("dev".to_string(), vec![exemptions(ver(5), SAFE_TO_DEPLOY)]);

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_exemptions(&cfg, &mut store, None).unwrap();

    let exemptions = get_exemptions(&store);
    insta::assert_snapshot!(
        "builtin-simple-deps-unaudited-adds-uneeded-criteria-regenerate",
        exemptions
    );
}

#[test]
fn builtin_dev_detection_exemptions_adds_uneeded_criteria_indirect_regenerate() {
    // (Pass) An audited entry overlaps a full audit which is the cur version and isn't needed
    // Should result in an empty exemptions file

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::dev_detection();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_minimal_audited(&metadata);

    audits.audits.insert(
        "simple-dev-indirect".to_string(),
        vec![
            full_audit(ver(5), SAFE_TO_RUN),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_RUN),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    config.exemptions.insert(
        "simple-dev-indirect".to_string(),
        vec![exemptions(ver(5), SAFE_TO_DEPLOY)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_exemptions(&cfg, &mut store, None).unwrap();

    let exemptions = get_exemptions(&store);
    insta::assert_snapshot!(
        "builtin-dev-detection-unaudited-adds-uneeded-criteria-indirect-regenerate",
        exemptions
    );
}

#[test]
fn builtin_simple_exemptions_extra_regenerate() {
    // (Pass) there's an extra unused exemptions entry, but the other is needed.
    // Should result in only the v10 exemptions entry remaining.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert("third-party1".to_string(), vec![]);

    config.exemptions.insert(
        "third-party1".to_string(),
        vec![
            exemptions(ver(5), SAFE_TO_DEPLOY),
            exemptions(ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_exemptions(&cfg, &mut store, None).unwrap();

    let exemptions = get_exemptions(&store);
    insta::assert_snapshot!("builtin-simple-unaudited-extra-regenerate", exemptions);
}

#[test]
fn builtin_simple_exemptions_in_direct_full_regenerate() {
    // (Pass) An audited entry overlaps a full audit which is the cur version and isn't needed
    // Should produce an empty exemptions

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );

    config.exemptions.insert(
        "third-party1".to_string(),
        vec![exemptions(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_exemptions(&cfg, &mut store, None).unwrap();

    let exemptions = get_exemptions(&store);
    insta::assert_snapshot!(
        "builtin-simple-unaudited-in-direct-full-regenerate",
        exemptions
    );
}

#[test]
fn builtin_simple_exemptions_nested_weaker_req_regenerate() {
    // (Pass) A dep that has weaker requirements on its dep
    // BUSTED: doesn't emit dependency-criteria for third-party1's 'exemptions'

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            delta_audit_dep(
                ver(3),
                ver(6),
                SAFE_TO_DEPLOY,
                [("transitive-third-party1", [SAFE_TO_RUN])],
            ),
            delta_audit_dep(
                ver(6),
                ver(DEFAULT_VER),
                SAFE_TO_DEPLOY,
                [("transitive-third-party1", [SAFE_TO_RUN])],
            ),
        ],
    );
    audits.audits.insert(
        "transitive-third-party1".to_string(),
        vec![
            delta_audit(ver(4), ver(8), SAFE_TO_RUN),
            delta_audit(ver(8), ver(DEFAULT_VER), SAFE_TO_RUN),
        ],
    );

    config.exemptions.insert(
        "third-party1".to_string(),
        vec![exemptions_dep(
            ver(3),
            SAFE_TO_DEPLOY,
            [("transitive-third-party1", [SAFE_TO_RUN])],
        )],
    );

    config.exemptions.insert(
        "transitive-third-party1".to_string(),
        vec![exemptions(ver(4), SAFE_TO_RUN)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_exemptions(&cfg, &mut store, None).unwrap();

    let exemptions = get_exemptions(&store);
    insta::assert_snapshot!(
        "builtin-simple-unaudited-nested-weaker-req-regenerate",
        exemptions
    );
}

#[test]
fn builtin_simple_exemptions_nested_stronger_req_regenerate() {
    // (Pass) A dep that has stronger requirements on its dep
    // BUSTED: should emit safe-to-deploy for transitive-third-party1

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    config.policy.insert(
        "first-party".to_string(),
        dep_policy([("third-party1", [SAFE_TO_RUN])]),
    );

    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            delta_audit_dep(
                ver(3),
                ver(6),
                SAFE_TO_RUN,
                [("transitive-third-party1", [SAFE_TO_DEPLOY])],
            ),
            delta_audit_dep(
                ver(6),
                ver(DEFAULT_VER),
                SAFE_TO_RUN,
                [("transitive-third-party1", [SAFE_TO_DEPLOY])],
            ),
        ],
    );
    audits.audits.insert(
        "transitive-third-party1".to_string(),
        vec![
            delta_audit(ver(4), ver(8), SAFE_TO_DEPLOY),
            delta_audit(ver(8), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    config.exemptions.insert(
        "third-party1".to_string(),
        vec![exemptions(ver(3), SAFE_TO_RUN)],
    );

    config.exemptions.insert(
        "transitive-third-party1".to_string(),
        vec![exemptions(ver(4), SAFE_TO_DEPLOY)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_exemptions(&cfg, &mut store, None).unwrap();

    let exemptions = get_exemptions(&store);
    insta::assert_snapshot!(
        "builtin-simple-unaudited-nested-stronger-req-regenerate",
        exemptions
    );
}

#[test]
fn builtin_simple_audit_as_default_root_regenerate() {
    // (Pass) the root is audit-as-crates-io with a default root policy

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_inited(&metadata);

    config
        .policy
        .insert("root-package".to_string(), audit_as_policy(Some(true)));
    config.exemptions.insert(
        "root-package".to_string(),
        vec![exemptions(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_exemptions(&cfg, &mut store, None).unwrap();

    let exemptions = get_exemptions(&store);
    insta::assert_snapshot!(
        "builtin-simple-audit-as-default-root-regenerate",
        exemptions
    );
}

#[test]
fn builtin_simple_audit_as_weaker_root_regenerate() {
    // (Pass) the root is audit-as-crates-io with an explicit root policy

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_inited(&metadata);

    config.policy.insert(
        "root-package".to_string(),
        PolicyEntry {
            criteria: Some(vec![SAFE_TO_RUN.to_string().into()]),
            ..audit_as_policy(Some(true))
        },
    );
    config.exemptions.insert(
        "root-package".to_string(),
        vec![exemptions(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );

    let mut store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);
    crate::minimize_exemptions(&cfg, &mut store, None).unwrap();

    let exemptions = get_exemptions(&store);
    insta::assert_snapshot!("builtin-simple-audit-as-weaker-root-regenerate", exemptions);
}
