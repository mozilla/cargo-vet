use super::*;

use crate::errors::{
    CratePolicyError, CratePolicyErrors, NeedsPolicyVersionErrors, PackageError,
    UnusedPolicyVersionErrors,
};

/// Checks that if a third-party crate is present, and an unversioned policy is used, an error
/// occurs indicating that versions need to be specified.
#[test]
fn simple_crate_policies_third_party_crates_imply_versions() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::overlapping();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_full_audited(&metadata);
    config.policy.insert(
        "third-party".into(),
        PackagePolicyEntry::Unversioned(Default::default()),
    );
    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let result = crate::check_crate_policies(&cfg, &store);
    assert_eq!(
        result,
        Err(CratePolicyErrors {
            errors: vec![CratePolicyError::NeedsVersion(NeedsPolicyVersionErrors {
                errors: vec![
                    PackageError {
                        package: "third-party".into(),
                        version: Some(ver(1))
                    },
                    PackageError {
                        package: "third-party".into(),
                        version: Some(ver(2))
                    }
                ]
            })]
        })
    );
}

/// Checks that if a third-party crate is present and a versioned policy is used for one version,
/// an error occurs indicating that versions are needed for other versions (regardless of whether
/// they are considered first- or third-party).
#[test]
fn simple_crate_policies_third_party_crates_need_all_versions() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::overlapping();
    let metadata = mock.metadata();

    for (a, b) in [(1, 2), (2, 1)] {
        let (mut config, audits, imports) = builtin_files_full_audited(&metadata);
        config.policy.insert(
            "third-party".into(),
            PackagePolicyEntry::Versioned {
                version: [(ver(a), Default::default())].into(),
            },
        );
        let store = Store::mock(config, audits, imports);
        let cfg = mock_cfg(&metadata);

        let result = crate::check_crate_policies(&cfg, &store);
        assert_eq!(
            result,
            Err(CratePolicyErrors {
                errors: vec![CratePolicyError::NeedsVersion(NeedsPolicyVersionErrors {
                    errors: vec![PackageError {
                        package: "third-party".into(),
                        version: Some(ver(b))
                    }]
                })]
            })
        );
    }
}

/// If crate policies are provided for versions which aren't present in the graph, an error should
/// occur.
#[test]
fn simple_crate_policies_extraneous_crate_versions() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::overlapping();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_full_audited(&metadata);
    config.policy.insert(
        "third-party".into(),
        PackagePolicyEntry::Versioned {
            version: [
                (ver(1), Default::default()),
                (ver(2), Default::default()),
                (ver(3), Default::default()),
            ]
            .into(),
        },
    );
    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let result = crate::check_crate_policies(&cfg, &store);
    assert_eq!(
        result,
        Err(CratePolicyErrors {
            errors: vec![CratePolicyError::UnusedVersion(UnusedPolicyVersionErrors {
                errors: vec![PackageError {
                    package: "third-party".into(),
                    version: Some(ver(3))
                },]
            })]
        })
    );
}

/// If crate policies are provided for crates which aren't present in the graph, an error should
/// occur.
#[test]
fn simple_crate_policies_extraneous_crates() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::overlapping();
    let metadata = mock.metadata();
    let (mut config, audits, imports) = builtin_files_full_audited(&metadata);
    config.policy.insert(
        "non-existent".into(),
        PackagePolicyEntry::Unversioned(Default::default()),
    );
    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let result = crate::check_crate_policies(&cfg, &store);
    assert_eq!(
        result,
        Err(CratePolicyErrors {
            errors: vec![CratePolicyError::UnusedVersion(UnusedPolicyVersionErrors {
                errors: vec![PackageError {
                    package: "non-existent".into(),
                    version: None
                }]
            })]
        })
    );
}
