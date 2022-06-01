# Configuration

This section describes the structure and semantics of the various configuration
files used by `cargo vet`.

## Location

By default, `cargo vet` data lives in a `supply-chain` directory next to
`Cargo.lock`. This location is configurable via the `[package.metadata.vet]`
directive in Cargo.toml, as well as via `[workspace.metadata.vet]` when using a
workspace with a virtual root.

The default configuration is equivalent to the following:

```toml
[package.metadata.vet]
store = { path = './supply-chain' }
```

## `audits.toml`

This file contains the audits performed by the project members and descriptions
of the audit criteria. The information in this file can be imported by other
projects.

### The `criteria` Table

This table defines different sets of custom criteria. Entries have several
potential fields:

#### `description`

A concise description of the criteria. This field (or `description-url`) is
required.

#### `description-url`

An alternative to `description` which locates the criteria text at a
publicly-accessible URL. This can be useful for sharing criteria descriptions
across multiple repositories.

#### `implies`

An optional string or array of other criteria that are subsumed by this entry.
Audit entries that are certified with these criteria are also implicitly
certified with any implied criteria.

For example, specifying the [built-in criteria](built-in-criteria.md) as custom
criteria would look like this:

```
[criteria.safe-to-run]
description = '...'

[criteria.safe-to-deploy]
description = '...'
implies = 'safe-to-run'
```

### The `audits` Table

This table contains the audit entries, indexed by crate name. Because there are
often multiple audits per crate (different versions, delta audits, etc), audit
entries are specified as table arrays, i.e. `[[audits.foo]]`.

The semantics of the various audit entries keys are described
[here](audit-entries.md).

## `config.toml`

This file contains configuration information for this specific project. This
file cannot be imported by other projects.

### `default-criteria`

This top-level key specifies the default criteria that `cargo vet certify` will
use when recording audits. If unspecified, this defaults to `safe-to-deploy`.

### The `imports` Table

This table enumerates the external audit sets that are imported into this
project. The key is a user-defined nickname, so entries are specified as
`[imports.foo]`.

#### `url`

Specifies an HTTPS url from which the remote `audits.toml` can be fetched. This
field is required.

#### `criteria-map`

An inline table or array of inline tables specifying one or more mappings
between the audit criteria of the imported and local sets. Each imported audit
is matched against each mapping. If the imported audit certifies all of the
criteria listed in the `theirs` key, it is associated with the local criteria
specified in the `ours` key.

This will generally be a 1:1 mapping:

```
criteria-map = { theirs: "a", ours: "x" }
```

But can also be more complex:

```
criteria-map = [ { theirs: "b", ours: ["y", "z"] },
                 { theirs: ["c", "d"], ours: "z" } ]
```

#### `exclude`

A list of crates whose audit entries should not be imported from this source.
This can be used as a last resort to resolve disagreements over the suitability
of a given crate.

### the `policy` Table

This table maps first-party crates to the audit requirements that `cargo vet`
should enforce on their dependencies. When unspecified, non-top-level
first-party crates inherit policy attributes from their parents, whereas
top-level first-party crates get the defaults described below.

#### `criteria`

A string or array of strings specifying the criteria that should be enforced for
this crate and its dependency tree.

For top-level crates, defaults to `safe-to-deploy`.

#### `dev-criteria`

Same as the above, but applied to dev-dependencies.

For top-level crates, defaults to `safe-to-run`.

#### `dependency-criteria`

Allows overriding the above values on a per-dependency basis. Similar in format
to the [equivalent field](audit-entries.md#dependency-criteria) in audit
entries.

Defaults to the empty set and is not inherited.

#### `targets`

A string or array of target specifiers for the platforms of interest for this
top-level crate. These are the platforms that `cargo vet` will require audits
for when traversing the subtree (audits can optionally [restrict their
validity](audit-entries.md#targets) to a set of targets).

For top-level crates, defaults to all platforms.

#### `dev-targets`

Same as the above, but applied to dev-dependencies.

For top-level crates, defaults to all platforms.

#### `notes`

Free-form string for recording rationale or other relevant information.

### The `unaudited` Table

This table enumerates the set of crates which are being used despite missing the
required audits. It has a similar structure to the `audits` table in
`audits.toml`, but each entry has fewer supported fields.

#### `version`

Specifies the exact version which should be exempted.

#### `criteria`

Specifies the criteria covered by the exemption.

#### `notes`

Free-form string for recording rationale or other relevant information.

#### `suggest`

A boolean indicating whether this entry is eligible to be surfaced by `cargo vet
suggest`.

Defaults to true. This exists to allow you silence certain suggestions that, for
whatever reason, you don't plan to act on in the immediate future.

## `imports.lock`

This file is auto-generated by `cargo vet` and its format should be treated as
an implementation detail.
