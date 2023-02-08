use super::*;

struct CratePolicyTest(pub MockMetadata);

impl CratePolicyTest {
    pub fn insta_crate_policy_errors<N: AsRef<str>, F>(&self, name: N, alter_config: F)
    where
        F: FnOnce(&mut ConfigFile),
    {
        let metadata = self.0.metadata();
        let (mut config, audits, imports) = builtin_files_full_audited(&metadata);
        alter_config(&mut config);
        let store = Store::mock(config, audits, imports);
        let cfg = mock_cfg(&metadata);

        let e = crate::check_crate_policies(&cfg, &store)
            .expect_err("crate policy check should have failed");
        insta::assert_snapshot!(name.as_ref(), format!("{:?}", miette::Report::new(e)));
    }
}

/// Checks that if a third-party crate is present, and an unversioned policy is used, an error
/// occurs indicating that versions need to be specified.
#[test]
fn simple_crate_policies_third_party_crates_imply_versions() {
    let _enter = TEST_RUNTIME.enter();

    CratePolicyTest(MockMetadata::overlapping()).insta_crate_policy_errors(
        "third_party_crates_imply_versions",
        |config| {
            config.policy.insert(
                "third-party".into(),
                PackagePolicyEntry::Unversioned(Default::default()),
            );
        },
    );
}

/// Checks that if a third-party crate is present and a versioned policy is used for one version,
/// an error occurs indicating that versions are needed for other versions (regardless of whether
/// they are considered first- or third-party).
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
                        version: [(ver(which), Default::default())].into(),
                    },
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
