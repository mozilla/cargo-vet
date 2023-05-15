use super::*;

#[test]
fn trusted_full_audit_locked() {
    // (Pass) A a trusted entry for a crate when locked

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, mut imports) = builtin_files_full_audited(&metadata);
    audits.audits.remove("transitive-third-party1");
    audits.trusted.insert(
        "transitive-third-party1".to_owned(),
        vec![trusted_entry(1, SAFE_TO_DEPLOY)],
    );

    imports.publisher.insert(
        "transitive-third-party1".to_owned(),
        vec![publisher_entry(ver(DEFAULT_VER), 1)],
    );

    let store = Store::mock(config, audits, imports);

    assert_report_snapshot!("trusted_full_audit_locked", metadata, store);
}

#[test]
fn trusted_wrong_user_id_locked() {
    // (Fail) A trusted entry for a crate with the wrong user when locked

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, mut imports) = builtin_files_full_audited(&metadata);
    audits.audits.remove("transitive-third-party1");
    audits.trusted.insert(
        "transitive-third-party1".to_owned(),
        vec![trusted_entry(2, SAFE_TO_DEPLOY)],
    );

    imports.publisher.insert(
        "transitive-third-party1".to_owned(),
        vec![publisher_entry(ver(DEFAULT_VER), 1)],
    );

    let store = Store::mock(config, audits, imports);

    assert_report_snapshot!("trusted_wrong_user_id_locked", metadata, store);
}

#[test]
fn trusted_delta_audit_locked() {
    // (Pass) A trusted entry plus delta-audit for a crate when locked

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, mut imports) = builtin_files_full_audited(&metadata);
    audits.audits.insert(
        "transitive-third-party1".to_owned(),
        vec![delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );
    audits.trusted.insert(
        "transitive-third-party1".to_owned(),
        vec![trusted_entry(1, SAFE_TO_DEPLOY)],
    );

    imports.publisher.insert(
        "transitive-third-party1".to_owned(),
        vec![publisher_entry(ver(5), 1)],
    );

    let store = Store::mock(config, audits, imports);

    assert_report_snapshot!("trusted_delta_audit_locked", metadata, store);
}

#[test]
fn trusted_delta_audit_wrong_user_id_locked() {
    // (Fail) A trusted entry plus delta-audit for a crate with the wrong user when locked

    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, mut imports) = builtin_files_full_audited(&metadata);
    audits.audits.insert(
        "transitive-third-party1".to_owned(),
        vec![delta_audit(ver(5), ver(DEFAULT_VER), SAFE_TO_DEPLOY)],
    );
    audits.trusted.insert(
        "transitive-third-party1".to_owned(),
        vec![trusted_entry(2, SAFE_TO_DEPLOY)],
    );

    imports.publisher.insert(
        "transitive-third-party1".to_owned(),
        vec![publisher_entry(ver(5), 1)],
    );

    let store = Store::mock(config, audits, imports);

    assert_report_snapshot!("trusted_delta_audit_wrong_user_id_locked", metadata, store);
}

#[test]
fn trusted_suggest_local() {
    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_full_audited(&metadata);
    audits.audits.remove("transitive-third-party1");
    audits.trusted.insert(
        "other-crate".to_owned(),
        vec![trusted_entry(1, SAFE_TO_DEPLOY)],
    );

    let mut network = Network::new_mock();
    network.mock_serve_json(
        "https://crates.io/api/v1/crates/transitive-third-party1",
        &serde_json::json!({
            "crate": { "description": "description" },
            "versions": [
                {
                    "crate": "transitive-third-party1",
                    "created_at": "2022-12-12T04:51:37.251648+00:00",
                    "num": "10.0.0",
                    "published_by": {
                        "id": 1,
                        "login": "testuser",
                        "name": "Test user",
                        "url": "https://github.com/testuser"
                    }
                },
            ]
        }),
    );
    network_mock_index(&mut network, "transitive-third-party1", &["10.0.0"]);

    let cfg = mock_cfg(&metadata);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    assert_report_snapshot!("trusted_suggest_local", metadata, store, Some(&network));
}

#[test]
fn trusted_suggest_import() {
    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);
    audits.audits.remove("transitive-third-party1");

    config.imports.insert(
        FOREIGN.to_owned(),
        crate::format::RemoteImport {
            url: vec![FOREIGN_URL.to_owned()],
            ..Default::default()
        },
    );

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: SortedMap::new(),
        wildcard_audits: SortedMap::new(),
        trusted: [(
            "other-crate".to_owned(),
            vec![trusted_entry(1, SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
    };

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);
    network.mock_serve_json(
        "https://crates.io/api/v1/crates/transitive-third-party1",
        &serde_json::json!({
            "crate": { "description": "description" },
            "versions": [
                {
                    "crate": "transitive-third-party1",
                    "created_at": "2022-12-12T04:51:37.251648+00:00",
                    "num": "10.0.0",
                    "published_by": {
                        "id": 1,
                        "login": "testuser",
                        "name": "Test user",
                        "url": "https://github.com/testuser"
                    }
                },
            ]
        }),
    );
    network_mock_index(&mut network, "transitive-third-party1", &["10.0.0"]);

    let cfg = mock_cfg(&metadata);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    assert_report_snapshot!("trusted_suggest_import", metadata, store, Some(&network));
}

#[test]
fn trusted_suggest_import_multiple() {
    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (mut config, mut audits, imports) = builtin_files_full_audited(&metadata);
    audits.audits.remove("transitive-third-party1");

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

    let new_foreign_audits = AuditsFile {
        criteria: SortedMap::new(),
        audits: SortedMap::new(),
        wildcard_audits: SortedMap::new(),
        trusted: [(
            "other-crate".to_owned(),
            vec![trusted_entry(1, SAFE_TO_DEPLOY)],
        )]
        .into_iter()
        .collect(),
    };

    let mut network = Network::new_mock();
    network.mock_serve_toml(FOREIGN_URL, &new_foreign_audits);
    network.mock_serve_toml(OTHER_FOREIGN_URL, &new_foreign_audits);
    network.mock_serve_json(
        "https://crates.io/api/v1/crates/transitive-third-party1",
        &serde_json::json!({
            "crate": { "description": "description" },
            "versions": [
                {
                    "crate": "transitive-third-party1",
                    "created_at": "2022-12-12T04:51:37.251648+00:00",
                    "num": "10.0.0",
                    "published_by": {
                        "id": 1,
                        "login": "testuser",
                        "name": "Test user",
                        "url": "https://github.com/testuser"
                    }
                },
            ]
        }),
    );
    network_mock_index(&mut network, "transitive-third-party1", &["10.0.0"]);

    let cfg = mock_cfg(&metadata);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    assert_report_snapshot!(
        "trusted_suggest_import_multiple",
        metadata,
        store,
        Some(&network)
    );
}

#[test]
fn trusted_suggest_local_ambiguous() {
    let _enter = TEST_RUNTIME.enter();
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();
    let (config, mut audits, imports) = builtin_files_full_audited(&metadata);
    audits.audits.remove("transitive-third-party1");
    audits.trusted.insert(
        "other-crate".to_owned(),
        vec![trusted_entry(1, SAFE_TO_DEPLOY)],
    );

    let mut network = Network::new_mock();
    network.mock_serve_json(
        "https://crates.io/api/v1/crates/transitive-third-party1",
        &serde_json::json!({
            "crate": { "description": "description" },
            "versions": [
                {
                    "crate": "transitive-third-party1",
                    "created_at": "2022-12-12T04:51:37.251648+00:00",
                    "num": "9.0.0",
                    "published_by": {
                        "id": 2,
                        "login": "otheruser",
                        "name": "Other user",
                        "url": "https://github.com/otheruser"
                    }
                },
                {
                    "crate": "transitive-third-party1",
                    "created_at": "2022-12-12T04:51:37.251648+00:00",
                    "num": "10.0.0",
                    "published_by": {
                        "id": 1,
                        "login": "testuser",
                        "name": "Test user",
                        "url": "https://github.com/testuser"
                    }
                },
            ]
        }),
    );
    network_mock_index(
        &mut network,
        "transitive-third-party1",
        &["9.0.0", "10.0.0"],
    );

    let cfg = mock_cfg(&metadata);

    let store = Store::mock_online(&cfg, config, audits, imports, &network, true).unwrap();

    assert_report_snapshot!(
        "trusted_suggest_local_ambiguous",
        metadata,
        store,
        Some(&network)
    );
}
