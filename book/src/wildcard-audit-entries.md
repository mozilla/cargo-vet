# Wildcard Audit Entries

Wildcard audits are a special type of audit intended as a convenience mechanism
for organizations that
[self-certify](curating-your-audit-set.md#self-certification) their own crates.
Using this feature, an organization can publish an audit which applies to all
versions published by a given account, avoiding the need to add a new entry to
`audits.toml` for each new version of the package.

Wildcard audits live at the top of `audits.toml` and look like this:

```
[[wildcard-audits.foo]]
who = ...
criteria = ...
user-id = ...
start = ...
end = ...
renew = ...
notes = ...
```

Whereas a regular audit certifies that the individual has verified that the
crate contents meet the criteria, a wildcard audit certifies that _any_ version
of the crate published by the given account will meet the criteria. In effect,
the author is vouching for the integrity of the entire release process, i.e.
that releases are always cut from a branch for which every change has been
approved by a trusted individual who will enforce the criteria.

Wildcard audits can be added with `cargo vet certify` using the `--wildcard`
option. By default, this sets the `end` date to one year in the future. Once
added (whether manually or by `cargo vet certify --wildcard`), the `end` date
can be updated to one year in the future using the `cargo vet renew CRATE`
command. `cargo vet renew --expiring` can be used to automatically update _all_
audits which would expire in the next six weeks or have already expired, and
don't have `renew = false` specified.

## `user-id`

Specifies the crates.io user-id of the user who's published versions should be
audited. This ID is unfortunately not exposed on the crates.io website, but will
be filled based on username if using the `cargo vet certify --wildcard $USER`
command. This field is required.

## `start`

Earliest day of publication which should be considered certified by the wildcard
audit. Crates published by the user before this date will not be considered as
certified. This field is required.

Note that publication dates use UTC rather than local time.

## `end`

Latest day of publication which should be considered certified by the wildcard
audit. Crates published by the user after this date will not be considered as
certified. This date may be at most 1 year in the future. This field is
required.

Note that publication dates use UTC rather than local time.

## `renew`

Specifies whether `cargo vet check` should suggest renewal for this audit if the
`end` date is going to expire within the next six weeks (or has already
expired), and whether `cargo vet renew --expiring` should renew this audit.

## `criteria`

Specifies the relevant criteria for this wildcard audit. This field is required.

## `who`

A string identifying the auditor. When invoking `cargo vet certify`, the
value is auto-populated from the git config.

See the documentation for [Audit Entries](./audit-entries.md#who) for more
details.

Note that while the `who` user may be different than crates.io user specified by
`user-id`, they should generally either be the same person, or have a close
relationship (e.g. a team lead certifying a shared publishing account).

## `notes`

An optional free-form string containing any information the auditor may wish to
record.
