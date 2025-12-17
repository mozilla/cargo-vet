use crate::errors::CratePolicyErrors;

use super::*;

struct CratePolicyTest(pub MockMetadata);

impl CratePolicyTest {
    pub fn no_errors<F>(&self, alter_config: F)
    where
        F: FnOnce(&mut ConfigFile),
    {
        self.check_crate_policies(alter_config)
            .expect("crate policy check should succeed");
    }

    pub fn insta_crate_policy_errors<N: AsRef<str>, F>(&self, name: N, alter_config: F)
    where
        F: FnOnce(&mut ConfigFile),
    {
        let e = self
            .check_crate_policies(alter_config)
            .expect_err("crate policy check should have failed");
        insta::assert_snapshot!(name.as_ref(), format!("{:?}", miette::Report::new(e)));
    }

    fn check_crate_policies<F>(&self, alter_config: F) -> Result<(), CratePolicyErrors>
    where
        F: FnOnce(&mut ConfigFile),
    {
        let metadata = self.0.metadata();
        let (mut config, audits, imports) = builtin_files_full_audited(&metadata);
        alter_config(&mut config);
        let store = Store::mock(config, audits, imports);
        let cfg = mock_cfg(&metadata);

        crate::check_crate_policies(&cfg, &store)
    }
}

/// Checks that if a third-party crate is present, and a versioned policy is used _without_
/// `dependency-criteria`, no error occurs.
#[test]
fn simple_crate_policies_third_party_crates_dont_need_versions() {
    let _enter = TEST_RUNTIME.enter();

    CratePolicyTest(MockMetadata::overlapping()).no_errors(|config| {
        config.policy.insert(
            "third-party".into(),
            PackagePolicyEntry::Versioned {
                version: [(ver(1), Default::default())].into(),
            },
        );
    });
}

fn dep_criteria_policy_entry() -> PolicyEntry {
    PolicyEntry {
        dependency_criteria: [("foo".to_owned().into(), vec!["bar".to_owned().into()])].into(),
        ..Default::default()
    }
}

/// Checks that if a third-party crate is present, and an unversioned policy is used with
/// `dependency-criteria`, an error occurs indicating that versions need to be specified.
#[test]
fn simple_crate_policies_third_party_crates_imply_versions() {
    let _enter = TEST_RUNTIME.enter();

    CratePolicyTest(MockMetadata::overlapping()).insta_crate_policy_errors(
        "third_party_crates_imply_versions",
        |config| {
            config.policy.insert(
                "third-party".into(),
                PackagePolicyEntry::Unversioned(dep_criteria_policy_entry()),
            );
        },
    );
}

/// Checks that if a third-party crate is present and a versioned policy with `dependency-criteria`
/// is used for one version, an error occurs indicating that versions are needed for other versions
/// (regardless of whether they are considered first- or third-party).
#[test]
fn simple_crate_policies_third_party_crates_need_all_versions() {
    let _enter = TEST_RUNTIME.enter();

    let test = CratePolicyTest(MockMetadata::overlapping());

    for which in [1, 2] {
        test.insta_crate_policy_errors(
            format!("third_party_crates_need_all_versions_{which}"),
            |config| {
                config.policy.insert(
                    "third-party".into(),
                    PackagePolicyEntry::Versioned {
                        version: [(ver(which), dep_criteria_policy_entry())].into(),
                    },
                );
            },
        );
    }
}

/// Checks that if a third-party crate is present and an unversioned policy is set, an error occurs
/// indicating that the policy should be versioned.
#[test]
fn simple_crate_policies_third_party_crates_require_versioned_policies() {
    let _enter = TEST_RUNTIME.enter();

    let test = CratePolicyTest(MockMetadata::overlapping());

    for which in [1, 2] {
        test.insta_crate_policy_errors(
            format!("third_party_crates_require_versioned_policies_{which}"),
            |config| {
                config.policy.insert(
                    "third-party".into(),
                    PackagePolicyEntry::Unversioned(PolicyEntry::default()),
                );
            },
        );
    }
}

/// If crate policies are provided for versions which aren't present in the graph, an error should
/// occur.
#[test]
fn simple_crate_policies_extraneous_crate_versions() {
    let _enter = TEST_RUNTIME.enter();

    CratePolicyTest(MockMetadata::overlapping()).insta_crate_policy_errors(
        "extraneous_crate_versions",
        |config| {
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
        },
    );
}

/// If crate policies are provided for crates which aren't present in the graph, an error should
/// occur.
#[test]
fn simple_crate_policies_extraneous_crates() {
    let _enter = TEST_RUNTIME.enter();

    CratePolicyTest(MockMetadata::overlapping()).insta_crate_policy_errors(
        "extraneous_crates",
        |config| {
            config.policy.insert(
                "non-existent".into(),
                PackagePolicyEntry::Unversioned(Default::default()),
            );
        },
    );
}
