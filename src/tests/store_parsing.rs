const EMPTY_CONFIG: &str = "\n";
const EMPTY_AUDITS: &str = "[audits]\n";
const EMPTY_IMPORTS: &str = "[audits]\n";

fn get_valid_store(config: &str, audits: &str, imports: &str) -> String {
    let res = crate::Store::mock_acquire(config, audits, imports);
    match res {
        Ok(_) => String::new(),
        Err(e) => format!("{:?}", miette::Report::new(e)),
    }
}

#[test]
fn test_all_empty() {
    let acquire_errors = get_valid_store("\n", "\n", "\n");
    insta::assert_snapshot!(acquire_errors);
}

#[test]
fn test_all_min() {
    let acquire_errors = get_valid_store(EMPTY_CONFIG, EMPTY_AUDITS, EMPTY_IMPORTS);
    insta::assert_snapshot!(acquire_errors);
}

#[test]
fn test_simple_bad_audit() {
    let audits = r##"
[[audits.serde]]
version = "1.0.0"
criteria = "bad"
"##;

    let acquire_errors = get_valid_store(EMPTY_CONFIG, audits, EMPTY_IMPORTS);
    insta::assert_snapshot!(acquire_errors);
}

#[test]
fn test_many_bad_audits() {
    let audits = r##"
[criteria.good]
description = "great"
implies = ["safe-to-deploy", "bad-imply"]

[[audits.serde]]
version = "1.0.0"
criteria = "bad"
dependency-criteria = { toml = "bad-dep", serde_derive = ["bad1", "good", "bad2"] }

[[audits.serde]]
delta = "1.0.0 -> 1.1.0"
criteria = ["safe-to-run", "dang"]
dependency-criteria = {}

[[audits.serde]]
delta = "1.0.0 -> 1.1.0"
criteria = "oops"
dependency-criteria = { "nope" = "nah" }

[[audits.serde]]
version = "2.0.0"
criteria = "safe-to-jog"
dependency-criteria = { toml = ["unsafe-to-destroy"] }

[[audits.serde]]
violation = "5.0.0 "
criteria = "no-good-bad-bad"
"##;

    let acquire_errors = get_valid_store(EMPTY_CONFIG, audits, EMPTY_IMPORTS);
    insta::assert_snapshot!(acquire_errors);
}

#[test]
fn test_many_bad_config() {
    let config = r##"
[policy.serde]
criteria = "bad"
dev-criteria = "nope"
dependency-criteria = { serde_derive = "nada", clap = ["safe-to-run", "unsafe-for-all", "good"] }

[policy.clap]
criteria = "safe-to-deploy"
dev-criteria = "safe-to-run"
dependency-criteria = { clap_derive = "good" }

[policy.boring]
audit-as-crates-io = true

[[exemptions.clap]]
version = "1.0.0"
criteria = "oops"
dependency-criteria = { clap_derive = "nah", oops = ["no", "safe-to-run"] }

[[exemptions.clap_derive]]
version = "1.0.0"
criteria = "safe-to-run"

"##;

    let audits = r##"
[criteria.good]
description = "great"
implies = ["safe-to-deploy"]

[audits]
"##;

    let acquire_errors = get_valid_store(config, audits, EMPTY_IMPORTS);
    insta::assert_snapshot!(acquire_errors);
}
