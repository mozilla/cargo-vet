# Audit Entries

This section defines the semantics of the various keys that may be specified in
audit table entries.

## `version`

Specifies that this audit entry corresponds to an absolute version that was
audited for the relevant criteria in its entirety.

## `delta`

Specifies that this audit entry certifies that the delta between two absolute
versions preserves the relevant criteria. Deltas can go both forward and
backward in the version sequence.

The syntax is `version_a -> version_b`, where the diff between version_a and
version_b was audited.

Note that it's not always possible to conclude that a diff preserves certain
properties without also inspecting some portion of the base version. The
standard here is that the properties are actually preserved, not merely that
that the diff doesn't obviously violate them. It is the responsibility of the
auditor to acquire sufficient context to certify the former.

## `violation`

Specifies that the given versions do not meet the associated criteria. Because a
range of versions is usually required, this field uses Cargo's standard
[VersionReq](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
syntax.

If a `violation` entry exists for a given crate version, `cargo vet` will reject
the dependency even if it's listed in the `exemptions` table.

## `criteria`

Specifies the relevant criteria for this audit. This field is required.

## `who`

A string identifying the auditor. When invoking `cargo vet certify`, the
value is auto-populated from the git config.

This field is optional, but encouraged for two reasons:
* It makes it easier to attribute audits at a glance, particularly for
  remotely-hosted audit files.
* It emphasizes to the author that they are signing off on having performed the
  audit.

## `notes`

An optional free-form string containing any information the auditor may wish to
record.
