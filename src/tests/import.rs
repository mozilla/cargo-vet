use super::*;

// Helper function for imports tests. Performs a vet and updates imports based
// on it, returning a diff of the two.
fn get_imports_file_changes(
    metadata: &Metadata,
    store: &Store,
    mode: impl FnMut(PackageStr<'_>) -> crate::resolver::UpdateMode,
) -> String {
    let updates = crate::resolver::get_store_updates(&mock_cfg(metadata), store, mode);

    // Format the old and new files as TOML, and write out a diff using `similar`.
    let old_imports = crate::serialization::to_formatted_toml(
        &store.imports,
        Some(&crate::storage::user_info_map(&store.imports)),
    )
    .unwrap()
    .to_string();
    let new_imports = crate::serialization::to_formatted_toml(
        &updates.imports,
        Some(&crate::storage::user_info_map(&updates.imports)),
    )
    .unwrap()
    .to_string();

    generate_diff(&old_imports, &new_imports)
}

fn get_imports_file_changes_prune(metadata: &Metadata, store: &Store) -> String {
    get_imports_file_changes(metadata, store, |_| crate::resolver::UpdateMode {
        search_mode: crate::resolver::SearchMode::PreferExemptions,
        prune_exemptions: false,
        prune_non_importable_audits: false,
        prune_imports: true,
    })
}

fn get_imports_file_changes_noprune(metadata: &Metadata, store: &Store) -> String {
    get_imports_file_changes(metadata, store, |_| crate::resolver::UpdateMode {
        search_mode: crate::resolver::SearchMode::PreferExemptions,
        prune_exemptions: false,
        prune_non_importable_audits: false,
        prune_imports: false,
    })
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
        wildcard_audits: SortedMap::new(),
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
        trusted: SortedMap::new(),
    };

    let old_other_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        wildcard_audits: SortedMap::new(),
        audits: SortedMap::new(),
        trusted: SortedMap::new(),
    };

    let new_other_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        wildcard_audits: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
        trusted: SortedMap::new(),
    };

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    imports
        .audits
        .insert(OTHER_FOREIGN.to_owned(), old_other_foreign_audits);

    config.imports.insert(
        OTHER_FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![OTHER_FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);
    network.mock_serve_toml(OTHER_FOREIGN_URL, &new_other_foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);
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
        wildcard_audits: SortedMap::new(),
        audits: SortedMap::new(),
        trusted: SortedMap::new(),
    };

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        wildcard_audits: [
            (
                "third-party2".to_owned(),
                vec![wildcard_audit(1, SAFE_TO_DEPLOY)],
            ),
            (
                "unused-package".to_owned(),
                vec![wildcard_audit(1, SAFE_TO_DEPLOY)],
            ),
        ]
        .into_iter()
        .collect(),
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
        trusted: SortedMap::new(),
    };

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);
    MockRegistryBuilder::new()
        .user(1, "user1", "User One")
        .package(
            "third-party2",
            &[reg_published_by(
                ver(DEFAULT_VER),
                Some(1),
                mock_weeks_ago(2),
            )],
        )
        .serve(&mut network);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);
    insta::assert_snapshot!("existing_peer_skip_import", output);

    let output = get_imports_file_changes_noprune(&metadata, &store);
    insta::assert_snapshot!("existing_peer_skip_import_noprune", output);
}

#[test]
fn existing_peer_remove_unused() {
    // (Pass) When pruning, we'll remove unused audits (including violations)
    // when unlocked, even if our peer hasn't changed. These audits will be
    // preserved when not pruning.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party2");

    let old_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        wildcard_audits: SortedMap::new(),
        audits: [
            (
                "third-party2".to_owned(),
                vec![
                    full_audit(ver(5), SAFE_TO_DEPLOY),
                    full_audit(ver(10), SAFE_TO_RUN),
                    delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY),
                    delta_audit(ver(100), ver(200), SAFE_TO_DEPLOY),
                ],
            ),
            (
                "unused-package".to_owned(),
                vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
            ),
            (
                "unused-violation".to_owned(),
                vec![violation(VersionReq::parse("1.*").unwrap(), SAFE_TO_DEPLOY)],
            ),
        ]
        .into_iter()
        .collect(),
        trusted: SortedMap::new(),
    };

    let new_foreign_audits = old_foreign_audits.clone();

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);
    insta::assert_snapshot!("existing_peer_remove_unused", output);

    let output = get_imports_file_changes_noprune(&metadata, &store);
    insta::assert_snapshot!("existing_peer_remove_unused_noprune", output);
}

#[test]
fn existing_peer_import_delta_audit() {
    // (Pass) If a new delta audit from a peer is useful, we'll import only that
    // audit.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party2");

    let old_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        wildcard_audits: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![full_audit(ver(9), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
        trusted: SortedMap::new(),
    };

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        wildcard_audits: SortedMap::new(),
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
        trusted: SortedMap::new(),
    };

    let old_other_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        wildcard_audits: SortedMap::new(),
        audits: SortedMap::new(),
        trusted: SortedMap::new(),
    };

    let new_other_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        wildcard_audits: SortedMap::new(),
        // We won't import unrelated audits from other sources.
        audits: [(
            "third-party2".to_owned(),
            vec![delta_audit(ver(200), ver(300), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
        trusted: SortedMap::new(),
    };

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    imports
        .audits
        .insert(OTHER_FOREIGN.to_owned(), old_other_foreign_audits);

    config.imports.insert(
        OTHER_FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![OTHER_FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);
    network.mock_serve_toml(OTHER_FOREIGN_URL, &new_other_foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn existing_peer_import_custom_criteria() {
    // (Pass) We'll immediately import criteria changes for mapped criteria when
    // unlocked, even if our peer hasn't changed or we aren't mapping them
    // locally. Only the criteria will be updated.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party2");

    let old_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        wildcard_audits: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
        trusted: SortedMap::new(),
    };

    let new_foreign_audits = AuditsFile {
        criteria: [
            ("fuzzed".to_string(), criteria("fuzzed")),
            (
                "super-fuzzed".to_string(),
                criteria_implies("super-fuzzed", ["fuzzed"]),
            ),
        ]
        .into_iter()
        .collect(),
        wildcard_audits: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![
                full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY),
                delta_audit(ver(DEFAULT_VER), ver(11), SAFE_TO_DEPLOY),
            ],
        )]
        .into_iter()
        .collect(),
        trusted: SortedMap::new(),
    };

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            criteria_map: [(
                "fuzzed".to_string().into(),
                vec![SAFE_TO_RUN.to_string().into()],
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);

    insta::assert_snapshot!(output);
}

#[test]
fn new_audit_for_unused_criteria_basic() {
    // (Pass) If a peer adds an audit for an unused criteria, we shouldn't
    // vendor in the changes unnecessarily, even if the criteria is mapped.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party2");

    let old_foreign_audits = AuditsFile {
        criteria: [("fuzzed".to_string(), criteria("fuzzed"))]
            .into_iter()
            .collect(),
        wildcard_audits: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
        trusted: SortedMap::new(),
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
            url: vec![FOREIGN_URL.to_owned()],
            criteria_map: [(
                "fuzzed".to_string().into(),
                vec![SAFE_TO_RUN.to_string().into()],
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);

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
        wildcard_audits: SortedMap::new(),
        audits: [(
            "third-party1".to_owned(),
            vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
        trusted: SortedMap::new(),
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
            url: vec![FOREIGN_URL.to_owned()],
            criteria_map: [(
                "fuzzed".to_string().into(),
                vec![SAFE_TO_RUN.to_string().into()],
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);

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
        wildcard_audits: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
        trusted: SortedMap::new(),
    };

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        wildcard_audits: SortedMap::new(),
        audits: SortedMap::new(),
        trusted: SortedMap::new(),
    };

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);
    insta::assert_snapshot!("existing_peer_revoked_audit", output);

    let output = get_imports_file_changes_noprune(&metadata, &store);
    insta::assert_snapshot!("existing_peer_revoked_audit_noprune", output);
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
        wildcard_audits: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
        trusted: SortedMap::new(),
    };

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        wildcard_audits: SortedMap::new(),
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
        trusted: SortedMap::new(),
    };

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn new_audit_needed_violation() {
    // (Pass) If a peer provides a violation for a crate we use (even if there are no related
    // audits), we should import it.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party2");

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        wildcard_audits: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![violation(
                VersionReq::parse("10.*").unwrap(),
                SAFE_TO_DEPLOY,
            )],
        )]
        .into_iter()
        .collect(),
        trusted: SortedMap::new(),
    };

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn new_audit_unneeded_violation() {
    // (Pass) If a peer provides a violation for a crate we don't use, we should not import it.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party2");

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        wildcard_audits: SortedMap::new(),
        audits: [
            (
                "third-party2".to_owned(),
                vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
            ),
            (
                "third-party3".to_owned(),
                vec![violation(
                    VersionReq::parse("10.*").unwrap(),
                    SAFE_TO_DEPLOY,
                )],
            ),
        ]
        .into_iter()
        .collect(),
        trusted: SortedMap::new(),
    };

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);
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
        wildcard_audits: SortedMap::new(),
        audits: SortedMap::new(),
        trusted: SortedMap::new(),
    };

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        wildcard_audits: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
        trusted: SortedMap::new(),
    };

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn peer_audits_exemption_minimize() {
    // (Pass) We do import audits for a package which would replace an exemption
    // when we're regenerating exemptions.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_inited(&metadata);

    audits.audits.insert(
        "transitive-third-party1".to_owned(),
        vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );

    let old_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        wildcard_audits: SortedMap::new(),
        audits: [
            (
                "unused-crate".to_owned(),
                vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
            ),
            (
                "third-party1".to_owned(),
                vec![delta_audit(ver(DEFAULT_VER), ver(100), SAFE_TO_DEPLOY)],
            ),
        ]
        .into_iter()
        .collect(),
        trusted: SortedMap::new(),
    };

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        wildcard_audits: SortedMap::new(),
        audits: [
            (
                "unused-crate".to_owned(),
                vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
            ),
            (
                "third-party1".to_owned(),
                vec![
                    full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY),
                    delta_audit(ver(DEFAULT_VER), ver(100), SAFE_TO_DEPLOY),
                ],
            ),
            (
                "third-party2".to_owned(),
                vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
            ),
        ]
        .into_iter()
        .collect(),
        trusted: SortedMap::new(),
    };

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    #[allow(clippy::type_complexity)]
    let configs: [(&str, fn(&str) -> crate::resolver::UpdateMode); 3] = [
        ("prune", |_| crate::resolver::UpdateMode {
            search_mode: crate::resolver::SearchMode::PreferFreshImports,
            prune_exemptions: true,
            prune_non_importable_audits: true,
            prune_imports: true,
        }),
        ("certify", |name| {
            if name == "third-party2" {
                crate::resolver::UpdateMode {
                    search_mode: crate::resolver::SearchMode::PreferFreshImports,
                    prune_exemptions: true,
                    prune_non_importable_audits: true,
                    prune_imports: false,
                }
            } else {
                crate::resolver::UpdateMode {
                    search_mode: crate::resolver::SearchMode::PreferExemptions,
                    prune_exemptions: false,
                    prune_non_importable_audits: false,
                    prune_imports: false,
                }
            }
        }),
        ("vet", |_| crate::resolver::UpdateMode {
            search_mode: crate::resolver::SearchMode::PreferExemptions,
            prune_exemptions: false,
            prune_non_importable_audits: false,
            prune_imports: false,
        }),
    ];

    for (name, mode) in configs {
        let mut store = Store::mock_online(
            &cfg,
            config.clone(),
            audits.clone(),
            imports.clone(),
            &network,
            true,
        )
        .unwrap();

        // Capture the old imports before minimizing exemptions
        let old = store.mock_commit();

        crate::resolver::update_store(&mock_cfg(&metadata), &mut store, mode);

        // Capture after minimizing exemptions, and generate a diff.
        let new = store.mock_commit();

        let output = diff_store_commits(&old, &new);
        insta::assert_snapshot!(format!("peer_audits_exemption_minimize_{name}"), output);
    }
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
        wildcard_audits: SortedMap::new(),
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
        trusted: SortedMap::new(),
    };

    let new_foreign_audits = old_foreign_audits.clone();

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            exclude: vec!["third-party1".to_owned(), "third-party2".to_owned()],
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

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

    let output = get_imports_file_changes_noprune(&metadata, &store);
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
        wildcard_audits: SortedMap::new(),
        audits: SortedMap::new(),
        trusted: SortedMap::new(),
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
        wildcard_audits: SortedMap::new(),
        audits: SortedMap::new(),
        trusted: SortedMap::new(),
    };

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            criteria_map: [(
                "example".to_string().into(),
                vec![SAFE_TO_DEPLOY.to_string().into()],
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let error = match Store::mock_online(&cfg, config, audits, imports, &network, false) {
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
        wildcard_audits: SortedMap::new(),
        trusted: SortedMap::new(),
    };

    let new_other_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
        wildcard_audits: SortedMap::new(),
        trusted: SortedMap::new(),
    };

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );
    config.imports.insert(
        OTHER_FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![OTHER_FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);
    network.mock_serve_toml(OTHER_FOREIGN_URL, &new_other_foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);
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
        wildcard_audits: SortedMap::new(),
        trusted: SortedMap::new(),
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
        wildcard_audits: SortedMap::new(),
        trusted: SortedMap::new(),
    };

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );
    config.imports.insert(
        OTHER_FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![OTHER_FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);
    network.mock_serve_toml(OTHER_FOREIGN_URL, &new_other_foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);
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
        wildcard_audits: SortedMap::new(),
        trusted: SortedMap::new(),
    };

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn import_multiple_versions() {
    // (Pass) If multiple versions of a crate in the graph need to import
    // audits, we need to import the required audits for all versions, not just
    // one of them.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::complex();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-core");

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [(
            "third-core".to_owned(),
            vec![
                full_audit(ver(5), "safe-to-deploy"),
                full_audit(ver(DEFAULT_VER), "safe-to-deploy"),
            ],
        )]
        .into_iter()
        .collect(),
        wildcard_audits: SortedMap::new(),
        trusted: SortedMap::new(),
    };

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);
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
        wildcard_audits: [
            (
                "crate-a".to_string(),
                vec![toml::toml! {
                    criteria = "safe-to-deploy"
                    user-id = 1
                    start = "2022-12-25"
                    end = "2023-12-25"
                    notes = "should parse correctly"
                }],
            ),
            (
                "crate-b".to_string(),
                vec![toml::toml! {
                    criteria = "example"
                    user-id = "invalid"
                    start = "2022-12-25"
                    end = "2023-12-25"
                    notes = "will be removed, along with the entire crate"
                }],
            ),
            (
                "crate-c".to_string(),
                vec![
                    toml::toml! {
                        criteria = "example2"
                        user-id = 1
                        start = "2022-12-25"
                        end = "2023-12-25"
                        notes = "will not be removed"
                    },
                    toml::toml! {
                        criteria = ["example2", "example3"]
                        user-id = 1
                        start = "2022-12-25"
                        end = "2023-12-25"
                        notes = "will not be removed"
                    },
                ],
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
                    toml::toml! {
                        criteria = "safe-to-deploy"
                        version = "10.0.0"
                        importable = false
                        notes = "parses correctly, but will be ignored"
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
            (
                "crate-d".to_string(),
                vec![toml::toml! {
                    criteria = "safe-to-deploy"
                    version = "10.0.0"
                    importable = false
                    notes = "parses correctly, but will be ignored, along with the entire crate"
                }],
            ),
        ]
        .into_iter()
        .collect(),
        trusted: SortedMap::new(),
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
        &["crate-a", "crate-a", "crate-a", "crate-a", "crate-a", "crate-b", "crate-b"]
    );

    insta::assert_snapshot!(
        "foreign_audit_file_to_local",
        crate::serialization::to_formatted_toml(&result.audit_file, None)
            .unwrap()
            .to_string()
    );
}

#[test]
fn import_wildcard_audit_publisher() {
    // (Pass) We should fetch information from the crates.io API about crates
    // with wildcard audits both locally and from peers, though preferring local
    // wildcard audits if they are sufficient.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party2");
    audits.audits.remove("third-party1");

    audits.wildcard_audits.insert(
        "third-party2".to_owned(),
        vec![wildcard_audit(1, SAFE_TO_DEPLOY)],
    );

    let old_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: SortedMap::new(),
        wildcard_audits: SortedMap::new(),
        trusted: SortedMap::new(),
    };

    let mut new_foreign_audits = old_foreign_audits.clone();
    new_foreign_audits.wildcard_audits.insert(
        "third-party2".to_owned(),
        vec![wildcard_audit(1, SAFE_TO_DEPLOY)],
    );
    new_foreign_audits.wildcard_audits.insert(
        "third-party1".to_owned(),
        vec![wildcard_audit(2, SAFE_TO_DEPLOY)],
    );

    imports
        .audits
        .insert(FOREIGN.to_owned(), old_foreign_audits);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    MockRegistryBuilder::new()
        .user(1, "user1", "User One")
        .user(2, "user2", "User Two")
        .package(
            "third-party1",
            &[
                reg_published_by(ver(DEFAULT_VER), Some(2), mock_weeks_ago(2)),
                reg_published_by(ver(5), Some(2), mock_weeks_ago(2)),
            ],
        )
        .package(
            "third-party2",
            &[
                reg_published_by(ver(DEFAULT_VER), Some(1), mock_weeks_ago(2)),
                reg_published_by(ver(5), Some(2), mock_weeks_ago(2)),
            ],
        )
        .serve(&mut network);
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn import_criteria_map() {
    // (Pass)

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, audits, imports) = files_no_exemptions(&metadata);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            criteria_map: [
                (
                    "foreign-reviewed".to_owned().into(),
                    vec!["reviewed".to_owned().into()],
                ),
                (
                    "safe-to-deploy".to_owned().into(),
                    vec!["strong-reviewed".to_owned().into()],
                ),
                (
                    "safe-to-run".to_owned().into(),
                    vec!["weak-reviewed".to_owned().into()],
                ),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        },
    );

    config.policy.package.insert(
        "first-party".to_owned(),
        PackagePolicyEntry::Unversioned(PolicyEntry {
            dependency_criteria: [
                (
                    "third-party1".to_owned().into(),
                    vec!["reviewed".to_owned().into()],
                ),
                (
                    "third-party2".to_owned().into(),
                    vec!["weak-reviewed".to_owned().into()],
                ),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        }),
    );
    config.policy.package.insert(
        "third-party1".to_owned(),
        PackagePolicyEntry::Versioned {
            version: [(
                ver(DEFAULT_VER),
                PolicyEntry {
                    dependency_criteria: [
                        (
                            "third-party1".to_owned().into(),
                            vec!["strong-reviewed".to_owned().into()],
                        ),
                        (
                            "third-party2".to_owned().into(),
                            vec!["weak-reviewed".to_owned().into()],
                        ),
                    ]
                    .into_iter()
                    .collect(),
                    ..Default::default()
                },
            )]
            .into_iter()
            .collect(),
        },
    );

    let new_foreign_audits = AuditsFile {
        criteria: [
            (
                "foreign-strong-reviewed".to_string(),
                criteria_implies("foreign strongly reviewed", ["foreign-reviewed"]),
            ),
            (
                "foreign-reviewed".to_string(),
                criteria_implies("foreign reviewed", ["foreign-weak-reviewed"]),
            ),
            (
                "foreign-weak-reviewed".to_string(),
                criteria("foreign weakly reviewed"),
            ),
        ]
        .into_iter()
        .collect(),
        audits: [
            (
                "third-party1".to_owned(),
                vec![full_audit(ver(DEFAULT_VER), "foreign-strong-reviewed")],
            ),
            (
                "transitive-third-party1".to_owned(),
                vec![full_audit(ver(DEFAULT_VER), "safe-to-deploy")],
            ),
            (
                "third-party2".to_owned(),
                vec![full_audit(ver(DEFAULT_VER), "safe-to-run")],
            ),
        ]
        .into_iter()
        .collect(),
        wildcard_audits: SortedMap::new(),
        trusted: SortedMap::new(),
    };

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn import_criteria_map_aggregated() {
    // (Pass) When importing multiple sources, they should be aggregated using
    // independent mapping of criteria. Because the foreign-criteria audit isn't
    // mapped, there is no criteria mapping error.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned(), OTHER_FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    audits.audits.remove("third-party1");

    let new_foreign_audits = AuditsFile {
        criteria: [(
            "foreign-reviewed".to_string(),
            criteria_implies("foreign reviewed A", [SAFE_TO_DEPLOY]),
        )]
        .into_iter()
        .collect(),
        audits: [(
            "third-party1".to_owned(),
            vec![full_audit(ver(9), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    };

    let new_other_foreign_audits = AuditsFile {
        criteria: [(
            "foreign-reviewed".to_string(),
            criteria_implies("foreign reviewed B", [SAFE_TO_DEPLOY]),
        )]
        .into_iter()
        .collect(),
        audits: [(
            "third-party1".to_owned(),
            vec![delta_audit(ver(9), ver(DEFAULT_VER), "foreign-reviewed")],
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    };

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);
    network.mock_serve_toml(OTHER_FOREIGN_URL, &new_other_foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn import_criteria_map_aggregated_error() {
    // (Pass) If a foreign criteria is mapped, and has different descriptions it
    // should produce an error when importing.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = files_full_audited(&metadata);

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned(), OTHER_FOREIGN_URL.to_owned()],
            criteria_map: [(
                "foreign-reviewed".to_owned().into(),
                vec!["reviewed".to_owned().into()],
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        },
    );

    audits.audits.remove("third-party1");

    let new_foreign_audits = AuditsFile {
        criteria: [(
            "foreign-reviewed".to_string(),
            criteria_implies("foreign reviewed A", [SAFE_TO_DEPLOY]),
        )]
        .into_iter()
        .collect(),
        audits: [(
            "third-party1".to_owned(),
            vec![full_audit(ver(9), SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    };

    let new_other_foreign_audits = AuditsFile {
        criteria: [(
            "foreign-reviewed".to_string(),
            criteria_implies("foreign reviewed B", [SAFE_TO_DEPLOY]),
        )]
        .into_iter()
        .collect(),
        audits: [(
            "third-party1".to_owned(),
            vec![delta_audit(ver(9), ver(DEFAULT_VER), "foreign-reviewed")],
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    };

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);
    network.mock_serve_toml(OTHER_FOREIGN_URL, &new_other_foreign_audits);

    let output = match Store::mock_online(&cfg, config, audits, imports, &network, true) {
        Ok(_) => panic!("unexpected success"),
        Err(err) => format!("{:?}", miette::Report::new(err)),
    };

    insta::assert_snapshot!(output);
}

#[test]
fn existing_import_kept_despite_local_wildcard_audit() {
    // (Pass) An existing imported audit is still kept if a local wildcard audit accounts for a
    // crate.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party2");

    audits.wildcard_audits.insert(
        "third-party2".to_owned(),
        vec![wildcard_audit(1, SAFE_TO_DEPLOY)],
    );

    let foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into(),
        wildcard_audits: SortedMap::new(),
        trusted: SortedMap::new(),
    };

    imports
        .audits
        .insert(FOREIGN.to_owned(), foreign_audits.clone());

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    MockRegistryBuilder::new()
        .user(1, "user1", "User One")
        .package(
            "third-party2",
            &[reg_published_by(
                ver(DEFAULT_VER),
                Some(1),
                mock_weeks_ago(2),
            )],
        )
        .serve(&mut network);
    network.mock_serve_toml(FOREIGN_URL, &foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_prune(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn local_wildcard_audit_preferred_to_fresh_import() {
    // (Pass) If a local wildcard audit accounts for a crate, a freshly imported audit should not
    // be preferred.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party2");

    audits.wildcard_audits.insert(
        "third-party2".to_owned(),
        vec![wildcard_audit(1, SAFE_TO_DEPLOY)],
    );

    let foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: [(
            "third-party2".to_owned(),
            vec![full_audit(ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
        )]
        .into(),
        // This isn't necessary (and overlaps with the imported audit), but we have it to also show
        // that local wildcard audits are preferred to remote ones.
        wildcard_audits: [(
            "third-party2".to_owned(),
            vec![wildcard_audit(1, SAFE_TO_DEPLOY)],
        )]
        .into(),
        trusted: SortedMap::new(),
    };

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    MockRegistryBuilder::new()
        .user(1, "user1", "User One")
        .package(
            "third-party2",
            &[reg_published_by(
                ver(DEFAULT_VER),
                Some(1),
                mock_weeks_ago(2),
            )],
        )
        .serve(&mut network);
    network.mock_serve_toml(FOREIGN_URL, &foreign_audits);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_noprune(&metadata, &store);
    insta::assert_snapshot!(output);
}

#[test]
fn wildcard_audit_trustpub_import() {
    // (Pass) If we have a wildcard audit for a crate using a trusted publisher,
    // it should be correctly fetched from the API.

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_full_audited(&metadata);

    audits.audits.remove("third-party2");

    audits.wildcard_audits.insert(
        "third-party2".to_owned(),
        vec![wildcard_audit_trustpub(
            "github:testing/third-party2",
            SAFE_TO_DEPLOY,
        )],
    );

    let cfg = mock_cfg(&metadata);

    let mut network = Network::new_mock();
    MockRegistryBuilder::new()
        .package(
            "third-party2",
            &[reg_trustpub_by(
                ver(DEFAULT_VER),
                "github:testing/third-party2",
                mock_weeks_ago(2),
            )],
        )
        .serve(&mut network);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    let output = get_imports_file_changes_noprune(&metadata, &store);
    insta::assert_snapshot!(output);
}
