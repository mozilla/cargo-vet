use crate::format::{RegistryEntry, RegistryFile};

use super::*;

#[test]
fn test_registry_parse_error() {
    // Check that we can recover from an invalid registry with a useful error.
    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_no_exemptions(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve(
        crate::storage::REGISTRY_URL,
        r#"
[registry.remote]
url = 10 # invalid!
"#,
    );

    let cfg = mock_cfg(&metadata);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, false).unwrap();

    let report = crate::resolver::resolve(&metadata, None, &store);
    let suggest = report
        .compute_suggest(&cfg, &store, Some(&network))
        .unwrap();

    let human_output = BasicTestOutput::new();
    report
        .print_human(&human_output.clone().as_dyn(), &cfg, suggest.as_ref())
        .unwrap();

    insta::assert_snapshot!(human_output.to_string());
}

#[test]
fn test_registry_suggestions_locked() {
    // Check that we don't suggest registry imports when locked, as we don't
    // fetch new imported audits in that case.
    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_no_exemptions(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(
        crate::storage::REGISTRY_URL,
        &RegistryFile {
            registry: [(
                FOREIGN.to_owned(),
                RegistryEntry {
                    url: vec![FOREIGN_URL.to_owned()],
                },
            )]
            .into_iter()
            .collect(),
        },
    );
    network.mock_serve_toml(
        FOREIGN_URL,
        &AuditsFile {
            criteria: SortedMap::new(),
            wildcard_audits: SortedMap::new(),
            audits: [(
                "third-party1".to_owned(),
                vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
            )]
            .into_iter()
            .collect(),
            trusted: SortedMap::new(),
        },
    );

    let cfg = mock_cfg_args(&metadata, ["cargo", "vet", "suggest", "--locked"]);

    // When locked, the store has no live imports.
    let store = Store::mock(config, audits, imports);

    let report = crate::resolver::resolve(&metadata, None, &store);
    let suggest = report
        .compute_suggest(&cfg, &store, Some(&network))
        .unwrap();

    let human_output = BasicTestOutput::new();
    report
        .print_suggest_human(&human_output.clone().as_dyn(), &cfg, suggest.as_ref())
        .unwrap();

    insta::assert_snapshot!(human_output.to_string());
}
