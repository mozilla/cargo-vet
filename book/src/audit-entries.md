# Audit Entries

This section defines the semantics of the various keys that may be specified in
audit table entries.

[TODO: finish this]

## `version`

Specifies that this audit entry corresponds to an absolute version that was
audited for the relevant criteria in its entirety.

## `delta`

Specifies that this audit entry certifies that the delta between two absolute
versions preserves the relevant criteria. The syntax is `version_a ->
version_b`, where the diff between version_a and version_b was audited.

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

## `criteria`

Specifies the relevant criteria for this audit. For `version` and `delta`
entries, this defaults to value(s) specified in the top-level `default-criteria`
field. For `violation` entries, this defaults to all defined criteria.

## `targets`

A string or array of strings specifying the targets for which this audit is
valid.

Unless otherwise specified, audit entries are assumed to apply to all platforms.
However, they can optionally be restricted to certain platforms (so that, for
example, an auditor can skim over complicated assembly code for a platform that
their project doesn't target).

## `who`

## `notes`

## `extra`

## `dependency_rules`

### `require_criteria`

### `pin_version`

### `fold_audit`
