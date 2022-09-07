use insta::assert_snapshot;

use super::*;

fn mock_aggregate(sources: Vec<(String, AuditsFile)>) -> String {
    match crate::do_aggregate_audits(sources) {
        Ok(merged) => crate::serialization::to_formatted_toml(merged)
            .unwrap()
            .to_string(),
        Err(error) => format!("{:?}", miette::Report::new(error)),
    }
}

#[test]
fn test_merge_audits_files_basic() {
    let _enter = TEST_RUNTIME.enter();

    let audits_files = vec![
        (
            "https://source1.example.com/supply_chain/audits.toml".to_owned(),
            AuditsFile {
                criteria: [].into_iter().collect(),
                audits: [(
                    "package1".to_owned(),
                    vec![full_audit(ver(DEFAULT_VER), "safe-to-deploy")],
                )]
                .into_iter()
                .collect(),
            },
        ),
        (
            "https://source2.example.com/supply_chain/audits.toml".to_owned(),
            AuditsFile {
                criteria: [].into_iter().collect(),
                audits: [
                    (
                        "package1".to_owned(),
                        vec![
                            full_audit(ver(5), "safe-to-deploy"),
                            full_audit(ver(DEFAULT_VER), "safe-to-deploy"),
                        ],
                    ),
                    (
                        "package2".to_owned(),
                        vec![full_audit(ver(DEFAULT_VER), "safe-to-deploy")],
                    ),
                ]
                .into_iter()
                .collect(),
            },
        ),
    ];

    let output = mock_aggregate(audits_files);
    assert_snapshot!(output);
}

#[test]
fn test_merge_audits_files_custom_criteria() {
    let _enter = TEST_RUNTIME.enter();

    let audits_files = vec![
        (
            "https://source1.example.com/supply_chain/audits.toml".to_owned(),
            AuditsFile {
                criteria: [
                    (
                        "criteria1".to_owned(),
                        CriteriaEntry {
                            implies: vec![],
                            description: Some("Criteria 1".to_owned()),
                            description_url: None,
                            aggregated_from: vec!["https://elsewhere.example.com/audits.toml"
                                .to_owned()
                                .into()],
                        },
                    ),
                    (
                        "criteria2".to_owned(),
                        CriteriaEntry {
                            implies: vec![],
                            description: Some("Criteria 2".to_owned()),
                            description_url: None,
                            aggregated_from: vec![],
                        },
                    ),
                ]
                .into_iter()
                .collect(),
                audits: [(
                    "package1".to_owned(),
                    vec![
                        full_audit(ver(DEFAULT_VER), "criteria1"),
                        full_audit(ver(DEFAULT_VER), "criteria2"),
                    ],
                )]
                .into_iter()
                .collect(),
            },
        ),
        (
            "https://source2.example.com/supply_chain/audits.toml".to_owned(),
            AuditsFile {
                criteria: [
                    (
                        "criteria1".to_owned(),
                        CriteriaEntry {
                            implies: vec![],
                            description: Some("Criteria 1".to_owned()),
                            description_url: None,
                            aggregated_from: vec!["https://beyond.example.com/audits.toml"
                                .to_owned()
                                .into()],
                        },
                    ),
                    (
                        "criteria3".to_owned(),
                        CriteriaEntry {
                            implies: vec![],
                            description: Some("Criteria 3".to_owned()),
                            description_url: None,
                            aggregated_from: vec![],
                        },
                    ),
                ]
                .into_iter()
                .collect(),
                audits: [
                    (
                        "package1".to_owned(),
                        vec![full_audit(ver(DEFAULT_VER), "criteria3")],
                    ),
                    (
                        "package2".to_owned(),
                        vec![full_audit(ver(DEFAULT_VER), "criteria1")],
                    ),
                ]
                .into_iter()
                .collect(),
            },
        ),
    ];

    let output = mock_aggregate(audits_files);
    assert_snapshot!(output);
}

#[test]
fn test_merge_audits_files_custom_criteria_conflict() {
    let _enter = TEST_RUNTIME.enter();

    let audits_files = vec![
        (
            "https://source1.example.com/supply_chain/audits.toml".to_owned(),
            AuditsFile {
                criteria: [
                    (
                        "criteria1".to_owned(),
                        CriteriaEntry {
                            implies: vec![],
                            description: Some("Criteria 1".to_owned()),
                            description_url: None,
                            aggregated_from: vec![],
                        },
                    ),
                    (
                        "criteria2".to_owned(),
                        CriteriaEntry {
                            implies: vec!["criteria1".to_owned().into()],
                            description: Some("Criteria 2".to_owned()),
                            description_url: None,
                            aggregated_from: vec![],
                        },
                    ),
                    (
                        "criteria3".to_owned(),
                        CriteriaEntry {
                            implies: vec!["criteria2".to_owned().into()],
                            description: None,
                            description_url: Some("https://criteria3".to_owned()),
                            aggregated_from: vec![],
                        },
                    ),
                ]
                .into_iter()
                .collect(),
                audits: [].into_iter().collect(),
            },
        ),
        (
            "https://source2.example.com/supply_chain/audits.toml".to_owned(),
            AuditsFile {
                criteria: [
                    (
                        "criteria1".to_owned(),
                        CriteriaEntry {
                            implies: vec![],
                            description: Some("Criteria 1 (alt)".to_owned()),
                            description_url: None,
                            aggregated_from: vec![],
                        },
                    ),
                    (
                        "criteria2".to_owned(),
                        CriteriaEntry {
                            implies: vec!["criteria1".to_owned().into()],
                            description: None,
                            description_url: Some("https://criteria2".to_owned()),
                            aggregated_from: vec![],
                        },
                    ),
                    (
                        "criteria3".to_owned(),
                        CriteriaEntry {
                            implies: vec!["criteria1".to_owned().into()],
                            description: None,
                            description_url: Some("https://criteria3.alt".to_owned()),
                            aggregated_from: vec![],
                        },
                    ),
                ]
                .into_iter()
                .collect(),
                audits: [].into_iter().collect(),
            },
        ),
    ];

    let output = mock_aggregate(audits_files);
    assert_snapshot!(output);
}
