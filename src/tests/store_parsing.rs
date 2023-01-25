const EMPTY_CONFIG: &str = r##"
# cargo-vet config file
"##;
const EMPTY_AUDITS: &str = r##"
# cargo-vet audits file

[audits]
"##;
const EMPTY_IMPORTS: &str = r##"
# cargo-vet imports lock

[audits]
"##;

fn get_valid_store(config: &str, audits: &str, imports: &str) -> String {
    let res = crate::Store::mock_acquire(config, audits, imports, true);
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
# cargo-vet audits file

[[audits.serde]]
criteria = "bad"
version = "1.0.0"
"##;

    let acquire_errors = get_valid_store(EMPTY_CONFIG, audits, EMPTY_IMPORTS);
    insta::assert_snapshot!(acquire_errors);
}

#[test]
fn test_many_bad_audits() {
    let audits = r##"
# cargo-vet audits file

[criteria.good]
description = "great"
implies = ["safe-to-deploy", "bad-imply"]

[[audits.serde]]
criteria = "bad"
version = "1.0.0"

[[audits.serde]]
criteria = "safe-to-jog"
version = "2.0.0"

[[audits.serde]]
criteria = "oops"
delta = "1.0.0 -> 1.1.0"

[[audits.serde]]
criteria = ["safe-to-run", "dang"]
delta = "1.0.0 -> 1.1.0"

[[audits.serde]]
criteria = "no-good-bad-bad"
violation = "^5.0.0"
"##;

    let acquire_errors = get_valid_store(EMPTY_CONFIG, audits, EMPTY_IMPORTS);
    insta::assert_snapshot!(acquire_errors);
}

#[test]
fn test_many_bad_config() {
    let config = r##"
# cargo-vet config file

[policy.boring]
audit-as-crates-io = true

[policy.clap]
criteria = "safe-to-deploy"
dev-criteria = "safe-to-run"
dependency-criteria = { clap_derive = "good" }

[policy.serde]
criteria = "bad"
dev-criteria = "nope"
dependency-criteria = { clap = ["safe-to-run", "unsafe-for-all", "good"], serde_derive = "nada" }

[[exemptions.clap]]
version = "1.0.0"
criteria = "oops"

[[exemptions.clap_derive]]
version = "1.0.0"
criteria = "safe-to-run"
"##;

    let audits = r##"
# cargo-vet audits file

[criteria.good]
description = "great"
implies = "safe-to-deploy"

[audits]
"##;

    let acquire_errors = get_valid_store(config, audits, EMPTY_IMPORTS);
    insta::assert_snapshot!(acquire_errors);
}

#[test]
fn test_outdated_imports_lock_extra_peer() {
    let config = r##"
# cargo-vet config file

[imports.peer1]
url = "https://peer1.com"
"##;

    let imports = r##"
# cargo-vet imports lock

[[audits.peer1.audits.third-party1]]
criteria = "safe-to-deploy"
version = "10.0.0"

[[audits.peer2.audits.third-party2]]
criteria = "safe-to-deploy"
version = "10.0.0"
"##;

    let acquire_errors = get_valid_store(config, EMPTY_AUDITS, imports);
    insta::assert_snapshot!(acquire_errors);
}

#[test]
fn test_outdated_imports_lock_missing_peer() {
    let config = r##"
# cargo-vet config file

[imports.peer1]
url = "https://peer1.com"

[imports.peer2]
url = "https://peer2.com"
"##;

    let imports = r##"
# cargo-vet imports lock

[[audits.peer1.audits.third-party1]]
criteria = "safe-to-deploy"
version = "10.0.0"
"##;

    let acquire_errors = get_valid_store(config, EMPTY_AUDITS, imports);
    insta::assert_snapshot!(acquire_errors);
}

#[test]
fn test_outdated_imports_lock_excluded_crate() {
    let config = r##"
# cargo-vet config file

[imports.peer1]
url = "https://peer1.com"
exclude = ["third-party1"]
"##;

    let imports = r##"
# cargo-vet imports lock

[[audits.peer1.audits.third-party1]]
criteria = "safe-to-deploy"
version = "10.0.0"

[[audits.peer1.audits.third-party2]]
criteria = "safe-to-deploy"
version = "10.0.0"
"##;

    let acquire_errors = get_valid_store(config, EMPTY_AUDITS, imports);
    insta::assert_snapshot!(acquire_errors);
}

#[test]
fn test_outdated_imports_lock_ok() {
    let config = r##"
# cargo-vet config file

[imports.peer1]
url = "https://peer1.com"
exclude = ["third-party2"]

[imports.peer2]
url = "https://peer1.com"
"##;

    let imports = r##"
# cargo-vet imports lock

[[audits.peer1.audits.third-party1]]
criteria = "safe-to-deploy"
version = "10.0.0"

[[audits.peer2.audits.third-party2]]
criteria = "safe-to-deploy"
version = "10.0.0"
"##;

    let acquire_errors = get_valid_store(config, EMPTY_AUDITS, imports);
    insta::assert_snapshot!(acquire_errors);
}

#[test]
fn test_unknown_field_config() {
    let config = r##"
# cargo-vet config file

[imports.peer1]
url = "https://peer1.com"
exclude = ["zzz", "aaa"]
unknown-field = "hi"

[[exemptions.zzz]]
version = "1.0.0"
criteria = "safe-to-deploy"
unknown-field = "hi"
"##;

    let imports = r##"
# cargo-vet imports lock

[[audits.peer1.audits.third-party1]]
criteria = "safe-to-deploy"
version = "10.0.0"
"##;

    let acquire_errors = get_valid_store(config, EMPTY_AUDITS, imports);
    insta::assert_snapshot!(acquire_errors);
}

#[test]
fn test_unknown_field_criteria() {
    let audits = r##"
# cargo-vet audits file

[criteria.good]
description = "great"
implies = "safe-to-deploy"
unknown-field = "invalid"

[audits]
"##;

    let acquire_errors = get_valid_store(EMPTY_CONFIG, audits, EMPTY_IMPORTS);
    insta::assert_snapshot!(acquire_errors);
}

#[test]
fn test_unknown_field_audit() {
    let audits = r##"
# cargo-vet audits file

[[audits.zzz]]
criteria = "safe-to-deploy"
version = "2.0.0"
unknown-field = "invalid"
"##;

    let acquire_errors = get_valid_store(EMPTY_CONFIG, audits, EMPTY_IMPORTS);
    insta::assert_snapshot!(acquire_errors);
}

#[test]
fn test_invalid_formatting() {
    let config = r##"
# cargo-vet config file

[imports.peer1]
url = "https://peer1.com"
exclude = ["zzz", "aaa"]

[imports.peer2]
url = "https://peer1.com"

[[exemptions.zzz]]
version = "1.0.0"
criteria = "safe-to-deploy"

[[exemptions.bbb]]
criteria = "safe-to-deploy"
version = "1.0.0"

[[exemptions.aaa]]
version = "1.0.0"
criteria = "safe-to-deploy"
"##;

    let audits = r##"
# cargo-vet audits file

[criteria.good]
description = "great"
implies = "safe-to-deploy"

[[audits.serde]]
criteria = ["safe-to-deploy", "good"]
version = "2.0.0"

[[audits.serde]]
criteria = ["safe-to-deploy", "good"]
version = "1.0.0"
notes = "valid field"
"##;

    let imports = r##"
# cargo-vet imports lock

[[audits.peer1.audits.third-party1]]
criteria = "safe-to-deploy"
version = "10.0.0"

[[audits.peer2.audits.third-party2]]
criteria = "safe-to-deploy"
version = "10.0.0"
"##;

    let acquire_errors = get_valid_store(config, audits, imports);
    insta::assert_snapshot!(acquire_errors);
}
