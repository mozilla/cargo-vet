use crate::network::Network;

use super::*;

// Helper function for imports tests. Performs a vet and updates imports based
// on it, returning a diff of the two.
fn get_imports_file_changes(metadata: &Metadata, store: &Store) -> String {
    // Run the resolver before calling `get_imports_file` to compute the new
    // imports file.
    let report = crate::resolver::resolve(metadata, None, store);
    let new_imports = store.get_updated_imports_file(&report.graph, &report.results);

    // Format the old and new files as TOML, and write out a diff using `similar`.
    let old_imports = crate::serialization::to_formatted_toml(&store.imports)
        .unwrap()
        .to_string();
    let new_imports = crate::serialization::to_formatted_toml(new_imports)
        .unwrap()
        .to_string();

    generate_diff(&old_imports, &new_imports)
}

// Test cases:

#[test]
fn new_peer_import() {
    // (Pass) We don't import any audits from a brand-new peer as we're fully
    // audited, however we do add an entry to the table for it.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, audits, mut imports) = builtin_files_full_audited(&metadata);

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [
            (
                "third-party2".to_owned(),
                vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
            ),
            (
                "unused-package".to_owned(),
                vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
            ),
        ]
        .into_iter()
        .collect(),
    };

    let old_other_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: SortedMap::new(),
    };

    let new_other_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
    };

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );

    imports
        .audits
        .insert(OTHER_FOREIGN.to_owned(), old_other_foreign_audits);

    config.imports.insert(
        OTHER_FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: OTHER_FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);
    network.mock_serve_toml(OTHER_FOREIGN_URL, &new_other_foreign_audits);

    let store = Store::mock_online(config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn existing_peer_skip_import() {
    // (Pass) If we've previously imported from a peer, we don't import
    // audits for a package unless it's useful.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, audits, mut imports) = builtin_files_full_audited(&metadata);

    let old_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: SortedMap::new(),
    };

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [
            (
                "third-party2".to_owned(),
                vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
            ),
            (
                "unused-package".to_owned(),
                vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
            ),
        ]
        .into_iter()
        .collect(),
    };

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn existing_peer_remove_unused() {
    // (Pass) We'll remove unused audits when unlocked, even if our peer hasn't
    // changed.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party2");

    let old_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [
            (
                "third-party2".to_owned(),
                vec![
                    full_audit(ver(5), SAFE_TO_DEPLOY),
                    delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
                    delta_audit(ver(100), ver(200), SAFE_TO_DEPLOY),
                    full_audit(ver(10), SAFE_TO_RUN),
                ],
            ),
            (
                "unused-package".to_owned(),
                vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
            ),
        ]
        .into_iter()
        .collect(),
    };

    let new_foreign_audits = old_foreign_audits.clone();

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn existing_peer_import_delta_audit() {
    // (Pass) If a new delta audit from a peer is useful, we'll import it and
    // all other audits for that crate, including from other peers.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party2");

    let old_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![full_audit(ver(9), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
    };

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [
            // A new audit for third-party2 should fix our audit, so we should
            // import it, but not other useless audits.
            (
                "third-party2".to_owned(),
                vec![
                    full_audit(ver(9), SAFE_TO_DEPLOY),
                    delta_audit(ver(9), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
                    delta_audit(ver(100), ver(200), SAFE_TO_DEPLOY),
                ],
            ),
            // This audit won't change things for us, so we won't import it to
            // avoid churn.
            (
                "third-party1".to_owned(),
                vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
            ),
        ]
        .into_iter()
        .collect(),
    };

    let old_other_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: SortedMap::new(),
    };

    let new_other_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        // We won't import unrelated audits from other sources.
        audits: [(
            "third-party2".to_owned(),
            vec![delta_audit(ver(200), ver(300), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
    };

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );

    imports
        .audits
        .insert(OTHER_FOREIGN.to_owned(), old_other_foreign_audits);

    config.imports.insert(
        OTHER_FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: OTHER_FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);
    network.mock_serve_toml(OTHER_FOREIGN_URL, &new_other_foreign_audits);

    let store = Store::mock_online(config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn existing_peer_import_custom_criteria() {
    // (Pass) We'll immediately import criteria changes when unlocked, even if
    // our peer hasn't changed or we aren't mapping them locally. This doesn't
    // force an import of other crates.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party2");

    let old_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
    };

    let new_foreign_audits = AuditsFile {
        criteria: [("fuzzed".to_string(), criteria("fuzzed"))]
            .into_iter()
            .collect(),
        audits: [(
            "third-party2".to_owned(),
            vec![
                full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY),
                delta_audit(ver(DEFAULT_VER), ver(11), SAFE_TO_DEPLOY),
            ],
        )]
        .into_iter()
        .collect(),
    };

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes(&metadata, &store);

    insta::assert_snapshot!(output);
}

#[test]
fn new_audit_for_unused_criteria_basic() {
    // (Pass) If a peer adds an audit for an unused criteria, we shouldn't
    // vendor in the changes unnecessarily.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party2");

    let old_foreign_audits = AuditsFile {
        criteria: [("fuzzed".to_string(), criteria("fuzzed"))]
            .into_iter()
            .collect(),
        audits: [(
            "third-party2".to_owned(),
            vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
    };

    let mut new_foreign_audits = old_foreign_audits.clone();
    new_foreign_audits
        .audits
        .get_mut("third-party2")
        .unwrap()
        .push(full_audit(ver(DEFAULT_VER), "fuzzed"));

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes(&metadata, &store);

    insta::assert_snapshot!(output);
}

#[test]
fn new_audit_for_unused_criteria_transitive() {
    // (Pass) If a peer adds an audit for an unused criteria of a transitive
    // dependency, we shouldn't vendor in the changes unnecessarily.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party1");

    let old_foreign_audits = AuditsFile {
        criteria: [("fuzzed".to_string(), criteria("fuzzed"))]
            .into_iter()
            .collect(),
        audits: [(
            "third-party1".to_owned(),
            vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
    };

    let mut new_foreign_audits = old_foreign_audits.clone();
    new_foreign_audits
        .audits
        .get_mut("third-party1")
        .unwrap()
        .push(full_audit(ver(DEFAULT_VER), "fuzzed"));
    new_foreign_audits.audits.insert(
        "transitive-third-party1".to_owned(),
        vec![full_audit(ver(DEFAULT_VER), "fuzzed")],
    );

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes(&metadata, &store);

    insta::assert_snapshot!(output);
}

#[test]
fn existing_peer_revoked_audit() {
    // (Pass) If a previously-imported audit is removed, we should also remove
    // it locally, even if doing so would cause vet to fail.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party2");

    let old_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
    };

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: SortedMap::new(),
    };

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn existing_peer_add_violation() {
    // (Pass) If a peer adds a violation for any version of a crate we use, we
    // should immediately import it. We won't immediately import other audits
    // added for that crate, however.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party2");

    let old_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
    };

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![
                full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY),
                delta_audit(ver(DEFAULT_VER), ver(20), SAFE_TO_DEPLOY),
                violation(VersionReq::parse("99.*").unwrap(), SAFE_TO_DEPLOY),
            ],
        )]
        .into_iter()
        .collect(),
    };

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn peer_audits_exemption_no_minimize() {
    // (Pass) We don't import audits for a package which would replace an
    // exemption unless we're regenerating exemptions.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, audits, mut imports) = builtin_files_inited(&metadata);

    let old_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: SortedMap::new(),
    };

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
    };

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn peer_audits_exemption_minimize() {
    // (Pass) We do import audits for a package which would replace an exemption
    // when we're regenerating exemptions.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, audits, mut imports) = builtin_files_inited(&metadata);

    let old_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: SortedMap::new(),
    };

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
    };

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let mut store = Store::mock_online(config, audits, imports, &network, true).unwrap();

    // Capture the old imports before minimizing exemptions
    let old = store.mock_commit();

    crate::resolver::regenerate_exemptions(&mock_cfg(&metadata), &mut store, true).unwrap();

    // Capture after minimizing exemptions, and generate a diff.
    let new = store.mock_commit();

    let output = diff_store_commits(&old, &new);
    insta::assert_snapshot!(output);
}

#[test]
fn peer_audits_import_exclusion() {
    // (Pass) Exclusions in the config should make a crate's audits and
    // violations appear to be revoked upstream, but audits for other crates
    // shouldn't be impacted.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("transitive-third-party1");

    let old_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [
            (
                "third-party2".to_owned(),
                vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
            ),
            (
                "third-party1".to_owned(),
                vec![violation("*".parse().unwrap(), SAFE_TO_DEPLOY)],
            ),
            (
                "transitive-third-party1".to_owned(),
                vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
            ),
        ]
        .into_iter()
        .collect(),
    };

    let new_foreign_audits = old_foreign_audits.clone();

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: FOREIGN_URL.to_owned(),
            exclude: vec!["third-party1".to_owned(), "third-party2".to_owned()],
            ..Default::default()
        },
    );

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(config, audits, imports, &network, true).unwrap();

    let imported = store
        .imported_audits()
        .get(FOREIGN)
        .expect("The remote should be present in `imported_audits`");

    assert!(
        !imported.audits.contains_key("third-party1"),
        "The `third-party1` crate should be completely missing from `imported_audits`"
    );
    assert!(
        !imported.audits.contains_key("third-party2"),
        "The `third-party2` crate should be completely missing from `imported_audits`"
    );
    assert!(
        imported.audits.contains_key("transitive-third-party1"),
        "The `transitive-third-party1` crate should still be present in `imported_audits`"
    );

    let output = get_imports_file_changes(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn existing_peer_updated_description() {
    // (Pass) If we've previously imported from a peer, and a criteria
    // description changed, we get an error with details.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, audits, mut imports) = builtin_files_full_audited(&metadata);

    let old_foreign_audits = AuditsFile {
        criteria: [(
            "example".to_string(),
            criteria(
                "Example criteria description\n\
                First line\n\
                Second line\n\
                Third line\n",
            ),
        )]
        .into_iter()
        .collect(),
        audits: SortedMap::new(),
    };

    let new_foreign_audits = AuditsFile {
        criteria: [(
            "example".to_string(),
            criteria(
                "Example criteria description\n\
                First new line\n\
                Third line\n\
                Fourth line\n",
            ),
        )]
        .into_iter()
        .collect(),
        audits: SortedMap::new(),
    };

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let error = match Store::mock_online(config, audits, imports, &network, false) {
        Ok(_) => panic!("expected store creation to fail due to updated criteria"),
        Err(err) => miette::Report::from(err),
    };
    insta::assert_snapshot!("existing_peer_updated_description", format!("{error:?}"));
}

#[test]
fn fresh_import_preferred_audits() {
    // (Pass) We prefer shorter audit chains over longer ones.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party2");

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![
                full_audit(ver(5), SAFE_TO_DEPLOY),
                delta_audit(ver(5), ver(6), SAFE_TO_DEPLOY),
                delta_audit(ver(6), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
            ],
        )]
        .into_iter()
        .collect(),
    };

    let new_other_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
    };

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );
    config.imports.insert(
        OTHER_FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: OTHER_FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);
    network.mock_serve_toml(OTHER_FOREIGN_URL, &new_other_foreign_audits);

    let store = Store::mock_online(config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn old_import_preferred_audits() {
    // (Pass) we don't switch to a shorter audit path if we already have a longer one imported.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party2");

    let old_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![
                full_audit(ver(5), SAFE_TO_DEPLOY),
                delta_audit(ver(5), ver(6), SAFE_TO_DEPLOY),
                delta_audit(ver(6), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
            ],
        )]
        .into_iter()
        .collect(),
    };

    let new_foreign_audits = old_foreign_audits.clone();

    let new_other_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
    };

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );
    config.imports.insert(
        OTHER_FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: OTHER_FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);
    network.mock_serve_toml(OTHER_FOREIGN_URL, &new_other_foreign_audits);

    let store = Store::mock_online(config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn equal_length_preferred_audits() {
    // (Pass) Between two audit paths of the same length, we prefer one
    // arbitrarily (the output of this test documents our preference, which is
    // based on how quickly the edges approach the start node).

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party2");

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![
                full_audit(ver(2), SAFE_TO_DEPLOY),
                full_audit(ver(8), SAFE_TO_DEPLOY),
                delta_audit(ver(2), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
                delta_audit(ver(8), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
            ],
        )]
        .into_iter()
        .collect(),
    };

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: FOREIGN_URL.to_owned(),
            ..Default::default()
        },
    );

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn foreign_audit_file_to_local() {
    let _enter = TEST_RUNTIME.enter();

    let foreign_audit_file = crate::format::ForeignAuditsFile {
        criteria: [
            (
                "example".to_string(),
                toml::toml! {
                    description = "Example criteria description"
                },
            ),
            (
                "example2".to_string(),
                toml::toml! {
                    implies = "unknown-criteria"
                    description = "example2"
                },
            ),
            (
                "example3".to_string(),
                toml::toml! {
                    description = "example2"
                    implies = ["safe-to-deploy", "will-not-parse"]
                },
            ),
            (
                "will-not-parse".to_string(),
                toml::toml! {
                    implies = [{ not = "a string" }]
                    description = "will be ignored"
                },
            ),
            (
                "will-not-parse2".to_string(),
                toml::toml! {
                    description = "example2"
                    implies = "safe-to-deploy"
                    unknown = "invalid unknown field"
                },
            ),
        ]
        .into_iter()
        .collect(),
        audits: [
            (
                "crate-a".to_string(),
                vec![
                    toml::toml! {
                        criteria = "safe-to-deploy"
                        version = "10.0.0"
                        notes = "should parse correctly"
                    },
                    toml::toml! {
                        criteria = "unknown-criteria"
                        version = "10.0.0"
                        notes = "will be removed"
                    },
                    toml::toml! {
                        criteria = "example"
                        version = "invalid"
                        notes = "will be removed"
                    },
                    toml::toml! {
                        criteria = "will-not-parse"
                        version = "10.0.0"
                        notes = "will be removed"
                    },
                    toml::toml! {
                        criteria = "safe-to-deploy"
                        violation = "invalid"
                        notes = "will be removed"
                    },
                    toml::toml! {
                        criteria = "safe-to-deploy"
                        version = "20.0.0"
                        unknown = "invalid unknown field"
                    },
                ],
            ),
            (
                "crate-b".to_string(),
                vec![toml::toml! {
                    criteria = "example"
                    version = "invalid"
                    notes = "will be removed, along with the entire crate"
                }],
            ),
            (
                "crate-c".to_string(),
                vec![
                    toml::toml! {
                        criteria = "example2"
                        version = "10.0.0"
                        notes = "will not be removed"
                    },
                    toml::toml! {
                        criteria = ["example2", "example3"]
                        version = "10.0.0"
                        notes = "will not be removed"
                    },
                    toml::toml! {
                        criteria = "example2"
                        delta = "1.0.0 -> 10.0.0"
                        notes = "will not be removed"
                    },
                    toml::toml! {
                        criteria = "safe-to-deploy"
                        violation = "=5.0.0"
                        notes = "will not be removed"
                    },
                ],
            ),
        ]
        .into_iter()
        .collect(),
    };

    let mut result = crate::storage::foreign_audit_file_to_local(foreign_audit_file);
    result.ignored_criteria.sort();
    result.ignored_audits.sort();

    assert_eq!(
        result.ignored_criteria,
        &["will-not-parse", "will-not-parse2"]
    );
    assert_eq!(
        result.ignored_audits,
        &["crate-a", "crate-a", "crate-a", "crate-a", "crate-a", "crate-b"]
    );

    insta::assert_snapshot!(
        "foreign_audit_file_to_local",
        crate::serialization::to_formatted_toml(&result.audit_file)
            .unwrap()
            .to_string()
    );
}
