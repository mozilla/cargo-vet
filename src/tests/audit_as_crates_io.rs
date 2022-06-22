use super::*;

fn get_audit_as_crates_io(cfg: &Config, store: &Store) -> String {
    let res = crate::check_audit_as_crates_io(cfg, store);
    match res {
        Ok(()) => String::new(),
        Err(e) => format!("{:?}", miette::Report::new(e)),
    }
}

#[test]
fn simple_audit_as_crates_io() {
    let _enter = TEST_RUNTIME.enter();

    let mock = MockMetadata::simple();
    let metadata = mock.metadata();
    let (config, audits, imports) = builtin_files_full_audited(&metadata);
    let store = Store::mock(config, audits, imports);
    let cfg = mock_cfg(&metadata);

    let output = get_audit_as_crates_io(&cfg, &store);
    insta::assert_snapshot!("simple-audit-as-crates-io", output);
}
