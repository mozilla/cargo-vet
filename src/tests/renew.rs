use super::*;

use crate::do_cmd_renew;

struct ExpireTest {
    today: chrono::NaiveDate,
    start: chrono::NaiveDate,
    end: chrono::NaiveDate,
}

impl ExpireTest {
    pub fn new(future: chrono::Duration) -> Self {
        let today = mock_today();
        let end = today + future;
        ExpireTest {
            today,
            start: today,
            end,
        }
    }

    pub fn with_start(start: chrono::Duration, end: chrono::Duration) -> Self {
        let today = mock_today();
        let start = today + start;
        let end = today + end;
        ExpireTest { today, start, end }
    }

    pub fn test_complex<'a, F, I>(
        &'a self,
        args: I,
        mock: MockMetadata,
        f: F,
    ) -> (Store, Arc<BasicTestOutput>)
    where
        F: FnOnce(&Self, &mut crate::format::WildcardAudits),
        I: IntoIterator<Item = &'a str>,
    {
        let _enter = TEST_RUNTIME.enter();
        let metadata = mock.metadata();
        let (config, mut audits, imports) = builtin_files_no_exemptions(&metadata);

        f(self, &mut audits.wildcard_audits);

        let mut store = Store::mock(config, audits, imports);

        let cfg = mock_cfg_args(&metadata, ["cargo", "vet", "renew"].into_iter().chain(args));
        let sub_args = if let Some(crate::cli::Commands::Renew(sub_args)) = &cfg.cli.command {
            sub_args
        } else {
            unreachable!();
        };

        let output = BasicTestOutput::new();
        do_cmd_renew(&output.clone().as_dyn(), &cfg, &mut store, sub_args);
        (store, output)
    }

    pub fn test_simple(&self) -> chrono::NaiveDate {
        let (store, _) = self.test_complex(
            ["--expiring"],
            MockMetadata::haunted_tree(),
            |me, audits| {
                audits.insert(
                    "third-normal".into(),
                    vec![WildcardEntry {
                        who: vec!["user".to_owned().into()],
                        criteria: vec!["safe-to-deploy".to_owned().into()],
                        user_id: 1,
                        start: me.start.into(),
                        end: me.end.into(),
                        renew: None,
                        notes: None,
                        aggregated_from: Default::default(),
                        is_fresh_import: false,
                    }],
                );
            },
        );
        *store.audits.wildcard_audits["third-normal"][0].end
    }

    pub fn renew_date(&self) -> chrono::NaiveDate {
        self.today + chrono::Months::new(12)
    }
}

/// The renew command should update an expiring wildcard audit.
#[test]
fn renew_expiring_wildcard_audits() {
    let expire = ExpireTest::new(chrono::Duration::weeks(2));
    let end = expire.test_simple();
    assert!(end >= expire.renew_date());
}

/// The renew command should update an already-expired wildcard audit.
#[test]
fn renew_already_expired_wildcard_audits() {
    let expire = ExpireTest::with_start(chrono::Duration::weeks(-5), chrono::Duration::weeks(-3));
    let end = expire.test_simple();
    assert!(end >= expire.renew_date());
}

/// The renew command should not update anything if end dates are far enough in the future.
#[test]
fn renew_no_expiring_wildcard_audits() {
    let expire = ExpireTest::new(chrono::Duration::weeks(7));
    let end = expire.test_simple();
    assert_eq!(end, expire.end);
}

/// Providing a specific crate name should only renew that crate.
#[test]
fn renew_specific_crate() {
    let expire = ExpireTest::new(chrono::Duration::weeks(3));
    let (store, _) =
        expire.test_complex(["third-dev"], MockMetadata::haunted_tree(), |et, audits| {
            audits.insert(
                "third-normal".into(),
                vec![WildcardEntry {
                    who: vec!["user".to_owned().into()],
                    criteria: vec!["safe-to-deploy".to_owned().into()],
                    user_id: 1,
                    start: et.start.into(),
                    end: et.end.into(),
                    renew: None,
                    notes: None,
                    aggregated_from: Default::default(),
                    is_fresh_import: false,
                }],
            );
            audits.insert(
                "third-dev".into(),
                vec![WildcardEntry {
                    who: vec!["user".to_owned().into()],
                    criteria: vec!["safe-to-deploy".to_owned().into()],
                    user_id: 1,
                    start: et.start.into(),
                    end: et.end.into(),
                    renew: None,
                    notes: None,
                    aggregated_from: Default::default(),
                    is_fresh_import: false,
                }],
            );
        });

    assert_eq!(
        *store.audits.wildcard_audits["third-normal"][0].end,
        expire.end
    );
    assert!(*store.audits.wildcard_audits["third-dev"][0].end >= expire.renew_date());
}

/// A wildcard entry with `renew = false` shouldn't be updated by renew.
#[test]
fn renew_expiring_set_false() {
    let expire = ExpireTest::new(chrono::Duration::weeks(3));
    let (store, _) = expire.test_complex(
        ["--expiring"],
        MockMetadata::haunted_tree(),
        |et, audits| {
            audits.insert(
                "third-normal".into(),
                vec![WildcardEntry {
                    who: vec!["user".to_owned().into()],
                    criteria: vec!["safe-to-deploy".to_owned().into()],
                    user_id: 1,
                    start: et.start.into(),
                    end: et.end.into(),
                    renew: Some(false),
                    notes: None,
                    aggregated_from: Default::default(),
                    is_fresh_import: false,
                }],
            );
            audits.insert(
                "third-dev".into(),
                vec![WildcardEntry {
                    who: vec!["user".to_owned().into()],
                    criteria: vec!["safe-to-deploy".to_owned().into()],
                    user_id: 1,
                    start: et.start.into(),
                    end: et.end.into(),
                    renew: None,
                    notes: None,
                    aggregated_from: Default::default(),
                    is_fresh_import: false,
                }],
            );
        },
    );

    assert_eq!(
        *store.audits.wildcard_audits["third-normal"][0].end,
        expire.end
    );
    assert!(*store.audits.wildcard_audits["third-dev"][0].end >= expire.renew_date());
}
