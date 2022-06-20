use super::*;
use std::fmt::Write;

#[test]
fn mock_simple_suggested_criteria() {
    let mock = MockMetadata::simple();

    let metadata = mock.metadata();

    let (mut config, mut audits, imports) = files_no_unaudited(&metadata);

    config.policy.insert(
        "first-party".to_string(),
        dep_policy([("third-party1", ["strong-reviewed"])]),
    );

    audits.audits.insert(
        "third-party1".to_owned(),
        vec![
            full_audit(ver(2), "weak-reviewed"),
            full_audit(ver(3), "reviewed"),
            full_audit(ver(4), "strong-reviewed"),
            delta_audit(ver(6), ver(DEFAULT_VER), "strong-reviewed"),
            delta_audit(ver(7), ver(DEFAULT_VER), "reviewed"),
            delta_audit(ver(8), ver(DEFAULT_VER), "weak-reviewed"),
        ],
    );
    audits.audits.insert(
        "third-party2".to_owned(),
        vec![
            full_audit(ver(2), "weak-reviewed"),
            full_audit(ver(3), "reviewed"),
            full_audit(ver(4), "strong-reviewed"),
            delta_audit(ver(6), ver(DEFAULT_VER), "strong-reviewed"),
            delta_audit(ver(7), ver(DEFAULT_VER), "reviewed"),
            delta_audit(ver(8), ver(DEFAULT_VER), "weak-reviewed"),
        ],
    );

    let store = Store::mock(config, audits, imports);
    let report = crate::resolver::resolve(&metadata, None, &store, ResolveDepth::Deep);

    let mut output = String::new();
    for (from, to, descr) in [
        (0, DEFAULT_VER, "full audit"),
        // from existing audit
        (2, DEFAULT_VER, "from weak-reviewed"),
        (3, DEFAULT_VER, "from reviewed"),
        (4, DEFAULT_VER, "from strong-reviewed"),
        // to existing audit
        (0, 6, "to strong-reviewed"),
        (0, 7, "to reviewed"),
        (0, 8, "to weak-reviewed"),
        // bridge existing audits
        (2, 6, "from weak-reviewed to strong-reviewed"),
        (2, 7, "from weak-reviewed to reviewed"),
        (2, 8, "from weak-reviewed to weak-reviewed"),
        (3, 6, "from reviewed to strong-reviewed"),
        (3, 7, "from reviewed to reviewed"),
        (3, 8, "from reviewed to weak-reviewed"),
        (4, 6, "from strong-reviewed to strong-reviewed"),
        (4, 7, "from strong-reviewed to reviewed"),
        (4, 8, "from strong-reviewed to weak-reviewed"),
    ] {
        let delta = Delta {
            from: ver(from),
            to: ver(to),
        };
        writeln!(output, "{} ({} -> {})", descr, delta.from, delta.to).unwrap();
        writeln!(
            output,
            "  third-party1: {:?}",
            report.compute_suggested_criteria("third-party1", &delta)
        )
        .unwrap();
        writeln!(
            output,
            "  third-party2: {:?}",
            report.compute_suggested_criteria("third-party2", &delta)
        )
        .unwrap();
    }

    insta::assert_snapshot!("mock-simple-suggested-criteria", output);
}
