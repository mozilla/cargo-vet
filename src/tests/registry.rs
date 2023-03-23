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
