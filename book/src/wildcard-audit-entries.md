# Wildcard Audit Entries

This section defines the semantics of the various keys that may be specified in
wildcard audit table entries (`[[wildcard-audits.$CRATE]]`).

Wildcard audits are an additional type of audit intended for organizations to
publish self-audits for their crates. Using a wildcard audit, the organization
can publish an audit which applies to all versions published by a trusted
publisher, avoiding the need to add a new audit to audits.toml for each
published version of the package.

These audits can be added with `cargo vet certify` using the `--wildcard`
option.

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
