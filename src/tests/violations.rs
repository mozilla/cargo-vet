use super::*;

#[test]
fn mock_simple_violation_cur_exemptions() {
    // (Fail) All marked 'exemptions' but a 'violation' entry matches a current version.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_inited(&metadata);

    let violation_ver = VersionReq::parse(&format!("={DEFAULT_VER}")).unwrap();
    audits
        .audits
        .entry("third-party1".to_string())
        .or_default()
        .push(violation(violation_ver, "weak-reviewed"));

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, ResolveDepth::Shallow);

    assert_report_snapshot!("mock-simple-violation-cur-unaudited", &metadata, report);
}

#[test]
fn mock_simple_violation_cur_full_audit() {
    // (Fail) All full audited but a 'violation' entry matches a current version.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let violation = VersionReq::parse(&format!("={DEFAULT_VER}")).unwrap();
    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            violation_hard(violation),
            full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, ResolveDepth::Shallow);

    assert_report_snapshot!("mock-simple-violation-cur-full-audit", &metadata, report);
}

#[test]
fn mock_simple_violation_delta() {
    // (Fail) A 'violation' matches a delta but not the cur version

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let violation = VersionReq::parse("=5.0.0").unwrap();
    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            violation_hard(violation),
            full_audit(ver(3), SAFE_TO_DEPLOY),
            delta_audit(ver(3), ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, ResolveDepth::Shallow);

    assert_report_snapshot!("mock-simple-violation-delta", &metadata, report);
}

#[test]
fn mock_simple_violation_full_audit() {
    // (Fail) A 'violation' matches a full audit but not the cur version

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let violation = VersionReq::parse("=3.0.0").unwrap();
    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            violation_hard(violation),
            full_audit(ver(3), SAFE_TO_DEPLOY),
            delta_audit(ver(3), ver(5), SAFE_TO_DEPLOY),
            delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, ResolveDepth::Shallow);

    assert_report_snapshot!("mock-simple-violation-full-audit", &metadata, report);
}

#[test]
fn mock_simple_violation_wildcard() {
    // (Fail) A 'violation' matches a full audit but not the cur version

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let violation = VersionReq::parse("*").unwrap();
    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            violation_hard(violation),
            full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, ResolveDepth::Shallow);

    assert_report_snapshot!("mock-simple-violation-wildcard", &metadata, report);
}

#[test]
fn builtin_simple_deps_violation_dodged() {
    // (Pass) A 'violation' matches a full audit but we only audit for weaker so it's fine

    let mock = MockMetadata::simple_deps();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_full_audited(&metadata);

    let violation_ver = VersionReq::parse("*").unwrap();
    audits.audits.insert(
        "dev".to_string(),
        vec![
            violation(violation_ver, SAFE_TO_DEPLOY),
            full_audit(ver(DEFAULT_VER), SAFE_TO_RUN),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, ResolveDepth::Shallow);

    assert_report_snapshot!("builtin-simple-deps-violation-dodged", &metadata, report);
}

#[test]
fn builtin_simple_deps_violation_low_hit() {
    // (Fail) A 'violation' matches a full audit and both are safe-to-run

    let mock = MockMetadata::simple_deps();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_full_audited(&metadata);

    let violation_ver = VersionReq::parse("*").unwrap();
    audits.audits.insert(
        "dev".to_string(),
        vec![
            violation(violation_ver, SAFE_TO_RUN),
            full_audit(ver(DEFAULT_VER), SAFE_TO_RUN),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, ResolveDepth::Shallow);

    assert_report_snapshot!("builtin-simple-deps-violation-low-hit", &metadata, report);
}

#[test]
fn builtin_simple_deps_violation_high_hit() {
    // (Fail) A 'violation' matches a full audit and both are safe-to-deploy

    let mock = MockMetadata::simple_deps();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_full_audited(&metadata);

    let violation_ver = VersionReq::parse("*").unwrap();
    audits.audits.insert(
        "dev".to_string(),
        vec![
            violation(violation_ver, SAFE_TO_DEPLOY),
            full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, ResolveDepth::Shallow);

    assert_report_snapshot!("builtin-simple-deps-violation-high-hit", &metadata, report);
}

#[test]
fn builtin_simple_deps_violation_imply_hit() {
    // (Fail) A safe-to-run 'violation' matches a safe-to-deploy full audit

    let mock = MockMetadata::simple_deps();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_full_audited(&metadata);

    let violation_ver = VersionReq::parse("*").unwrap();
    audits.audits.insert(
        "dev".to_string(),
        vec![
            violation(violation_ver, SAFE_TO_RUN),
            full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, ResolveDepth::Shallow);

    assert_report_snapshot!("builtin-simple-deps-violation-imply-hit", &metadata, report);
}

#[test]
fn builtin_simple_deps_violation_redundant_low_hit() {
    // (Fail) A [safe-to-run, safe-to-deploy] 'violation' matches a safe-to-run full audit

    let mock = MockMetadata::simple_deps();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_full_audited(&metadata);

    let violation_ver = VersionReq::parse("*").unwrap();
    audits.audits.insert(
        "dev".to_string(),
        vec![
            violation_m(violation_ver, [SAFE_TO_RUN, SAFE_TO_DEPLOY]),
            full_audit(ver(DEFAULT_VER), SAFE_TO_RUN),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, ResolveDepth::Shallow);

    assert_report_snapshot!(
        "builtin-simple-deps-violation-redundant-low-hit",
        &metadata,
        report
    );
}

#[test]
fn mock_simple_violation_hit_with_extra_junk() {
    // (Fail) A [safe-to-run, fuzzed] 'violation' matches a safe-to-run full audit

    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = files_full_audited(&metadata);

    let violation_ver = VersionReq::parse("*").unwrap();
    audits.audits.insert(
        "third-party1".to_string(),
        vec![
            violation_m(violation_ver, [SAFE_TO_RUN, "fuzzed"]),
            full_audit(ver(DEFAULT_VER), SAFE_TO_RUN),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, ResolveDepth::Shallow);

    assert_report_snapshot!(
        "mock-simple-violation-hit-with-extra-junk",
        &metadata,
        report
    );
}
