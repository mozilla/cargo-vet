# Audit Entries

This section defines the semantics of the various keys that may be specified in
audit table entries.

[TODO: finish this]

## `version`

## `delta`

## `forbidden`

## `who`

## `notes`

## `extra`

## `criteria`

## `targets`

A string or array of strings specifying the targets for which this audit is
valid.

Unless otherwise specified, audit entries are assumed to apply to all platforms.
However, they can optionally be restricted to certain platforms (so that, for
example, an auditor can skim over complicated assembly code for a platform that
their project doesn't target).

## `dependency_rules`

### `require_criteria`

### `pin_version`

### `fold_audit`
