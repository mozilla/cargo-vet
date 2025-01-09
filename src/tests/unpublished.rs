use super::*;

#[derive(Copy, Clone, Eq, PartialEq)]
enum UnpublishedInitialState {
    // wildcard audit applies to 8 and 9, unpublished from 8 to 10
    WildcardAudit,
    // full audit applying to 8. unpublished from 8 to 10
    FullAudit,
    // wildcard audit with cached publisher applies to 8. Live publisher applies
    // to 9. No unpublished entry.
    WildcardNoUnpublished,
    // no audits/unpublished entries
    Nothing,
}

/// Helper used by a couple of tests. Runs `update_store` against a common store
/// state with the given update mode.
fn unpublished_basic_regenerate(
    initial: UnpublishedInitialState,
    mode: crate::resolver::UpdateMode,
) -> String {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::descriptive();
    let metadata = mock.metadata();
    let (mut config, mut audits, mut imports) = builtin_files_inited(&metadata);

    config.exemptions.remove("descriptive");
    config
        .policy
        .insert("descriptive".to_owned(), audit_as_policy(Some(true)));
    imports.unpublished.insert(
        "descriptive".to_owned(),
        vec![crate::format::UnpublishedEntry {
            version: ver(DEFAULT_VER),
            audited_as: ver(8),
            still_unpublished: false,
            is_fresh_import: false,
        }],
    );

    match initial {
        UnpublishedInitialState::FullAudit => {
            audits.audits.insert(
                "descriptive".to_owned(),
                vec![full_audit(ver(8), SAFE_TO_DEPLOY)],
            );
        }
        UnpublishedInitialState::WildcardAudit | UnpublishedInitialState::WildcardNoUnpublished => {
            audits.wildcard_audits.insert(
                "descriptive".to_owned(),
                vec![wildcard_audit(1, SAFE_TO_DEPLOY)],
            );
            imports.publisher.insert(
                "descriptive".to_owned(),
                vec![publisher_entry_named(ver(8), 1, "user1", "User One")],
            );
            if initial == UnpublishedInitialState::WildcardNoUnpublished {
                imports.unpublished.remove("descriptive");
            }
        }
        UnpublishedInitialState::Nothing => {
            imports.unpublished.remove("descriptive");
        }
    }

    let mut network = Network::new_mock();
    MockRegistryBuilder::new()
        .user(1, "user1", "User One")
        .package(
            "descriptive",
            &[
                reg_published_by(ver(8), Some(1), mock_weeks_ago(2)),
                reg_published_by(ver(9), Some(1), mock_weeks_ago(2)),
            ],
        )
        .serve(&mut network);

    let cfg = mock_cfg(&metadata);

    let mut store = Store::mock_online(&cfg, config, audits, imports, &network, false).unwrap();

    let old = store.mock_commit();
    crate::resolver::update_store(&mock_cfg(&metadata), &mut store, |_| mode);
    let new = store.mock_commit();

    diff_store_commits(&old, &new)
}

#[test]
fn audit_as_crates_io_unpublished_blank_regenerate_exemptions() {
    let output = unpublished_basic_regenerate(
        UnpublishedInitialState::Nothing,
        crate::resolver::UpdateMode {
            search_mode: crate::resolver::SearchMode::RegenerateExemptions,
            prune_exemptions: true,
            prune_non_importable_audits: true,
            prune_imports: true,
        },
    );
    insta::assert_snapshot!(output);
}

#[test]
fn audit_as_crates_io_unpublished_full_regenerate_exemptions() {
    let output = unpublished_basic_regenerate(
        UnpublishedInitialState::FullAudit,
        crate::resolver::UpdateMode {
            search_mode: crate::resolver::SearchMode::RegenerateExemptions,
            prune_exemptions: true,
            prune_non_importable_audits: true,
            prune_imports: true,
        },
    );
    insta::assert_snapshot!(output);
}

#[test]
fn audit_as_crates_io_unpublished_full_prune() {
    let output = unpublished_basic_regenerate(
        UnpublishedInitialState::FullAudit,
        crate::resolver::UpdateMode {
            search_mode: crate::resolver::SearchMode::PreferFreshImports,
            prune_exemptions: true,
            prune_non_importable_audits: true,
            prune_imports: true,
        },
    );
    insta::assert_snapshot!(output);
}

#[test]
fn audit_as_crates_io_unpublished_full_prefer_exemptions() {
    let output = unpublished_basic_regenerate(
        UnpublishedInitialState::FullAudit,
        crate::resolver::UpdateMode {
            search_mode: crate::resolver::SearchMode::PreferExemptions,
            prune_exemptions: false,
            prune_non_importable_audits: false,
            prune_imports: false,
        },
    );
    insta::assert_snapshot!(output);
}

#[test]
fn audit_as_crates_io_unpublished_wildcard_regenerate_exemptions() {
    let output = unpublished_basic_regenerate(
        UnpublishedInitialState::WildcardAudit,
        crate::resolver::UpdateMode {
            search_mode: crate::resolver::SearchMode::RegenerateExemptions,
            prune_exemptions: true,
            prune_non_importable_audits: true,
            prune_imports: true,
        },
    );
    insta::assert_snapshot!(output);
}

#[test]
fn audit_as_crates_io_unpublished_wildcard_prune() {
    let output = unpublished_basic_regenerate(
        UnpublishedInitialState::WildcardAudit,
        crate::resolver::UpdateMode {
            search_mode: crate::resolver::SearchMode::PreferFreshImports,
            prune_exemptions: true,
            prune_non_importable_audits: true,
            prune_imports: true,
        },
    );
    insta::assert_snapshot!(output);
}

#[test]
fn audit_as_crates_io_unpublished_wildcard_prefer_exemptions() {
    let output = unpublished_basic_regenerate(
        UnpublishedInitialState::WildcardAudit,
        crate::resolver::UpdateMode {
            search_mode: crate::resolver::SearchMode::PreferExemptions,
            prune_exemptions: false,
            prune_non_importable_audits: false,
            prune_imports: false,
        },
    );
    insta::assert_snapshot!(output);
}

#[test]
fn audit_as_crates_io_unpublished_wildcard_nounpublished_regenerate_exemptions() {
    let output = unpublished_basic_regenerate(
        UnpublishedInitialState::WildcardNoUnpublished,
        crate::resolver::UpdateMode {
            search_mode: crate::resolver::SearchMode::RegenerateExemptions,
            prune_exemptions: true,
            prune_non_importable_audits: true,
            prune_imports: true,
        },
    );
    insta::assert_snapshot!(output);
}

#[test]
fn audit_as_crates_io_unpublished_wildcard_nounpublished_prune() {
    let output = unpublished_basic_regenerate(
        UnpublishedInitialState::WildcardNoUnpublished,
        crate::resolver::UpdateMode {
            search_mode: crate::resolver::SearchMode::PreferFreshImports,
            prune_exemptions: true,
            prune_non_importable_audits: true,
            prune_imports: true,
        },
    );
    insta::assert_snapshot!(output);
}

#[test]
fn audit_as_crates_io_unpublished_wildcard_nounpublished_prefer_exemptions() {
    let output = unpublished_basic_regenerate(
        UnpublishedInitialState::WildcardNoUnpublished,
        crate::resolver::UpdateMode {
            search_mode: crate::resolver::SearchMode::PreferExemptions,
            prune_exemptions: false,
            prune_non_importable_audits: false,
            prune_imports: false,
        },
    );
    insta::assert_snapshot!(output);
}
