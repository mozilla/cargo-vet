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

### The `trusted` Table

This table contains the trusted publisher entries, indexed by crate name. Because there may be
multiple publishers per crate, trusted entries are specified as table arrays, i.e.
`[[trusted.foo]]`.

The semantics of the various trusted entries keys are described [here](trusted-entries.md).

## `config.toml`

This file contains configuration information for this specific project. This
file cannot be imported by other projects.

### `default-criteria`

This top-level key specifies the default criteria that `cargo vet certify` will
use when recording audits. If unspecified, this defaults to `safe-to-deploy`.

### The `cargo-vet` Table

This table contains metadata used to track the version of cargo-vet used to
create the store, and may be used in the future to allow other global
configuration details to be specified.

### The `imports` Table

This table enumerates the external audit sets that are imported into this
project. The key is a user-defined nickname, so entries are specified as
`[imports.foo]`.

#### `url`

Specifies an HTTPS url from which the remote `audits.toml` can be fetched. This
field is required.

#### `criteria-map`

A table specifying mappings from the imported audit set to local criteria. Each
imported audit's criteria is mapped through these import maps, considering the
peer's `implies` relationships, and transformed into a set of local criteria
when importing.

```
[imports.peer.criteria-map]
peer-criteria = "local-criteria"
their-super-audited = ["safe-to-deploy", "audited"]
```

Unless otherwise specified, the peer's `safe-to-run` and `safe-to-deploy`
criteria will be implicitly mapped to the local `safe-to-run` and
`safe-to-deploy` criteria. This can be overridden by specifying the mapping for
`safe-to-run` or `safe-to-deploy` in the criteria map.

```
[imports.peer.criteria-map]
safe-to-run = []
safe-to-deploy = "safe-to-run"
```

Other unmapped criteria will be discarded when importing.

#### `exclude`

A list of crates whose audit entries should not be imported from this source.
This can be used as a last resort to resolve disagreements over the suitability
of a given crate.

### The `policy` Table

This table allows projects to configure the audit requirements that `cargo vet`
should enforce on various dependencies. When unspecified, non-top-level crates
inherit most policy attributes from their parents, whereas top-level crates get
the defaults described below.

In this context, "top-level" generally refers to crates with no
reverse-dependencies — except when evaluating dev-dependencies, in which case
every workspace member is considered a root.

Keys of this table can be crate names (in which case the policy is applied to
_all_ versions of the crate) or strings of the form `"CRATE:VERSION"` (you'll
more than likely need to add quotes in TOML because the version string will have
periods). If you specify versions, they may only refer to crate versions which
are in the graph.

#### `criteria`

A string or array of strings specifying the criteria that should be enforced for
this crate and its dependency subtree.

This may only be specified for first-party crates. Requirements for third-party
crates should be applied via inheritance or `dependency-criteria`.

For top-level crates, defaults to `safe-to-deploy`.

#### `dev-criteria`

Same as the above, but applied to dev-dependencies.

For top-level crates, defaults to `safe-to-run`.

#### `dependency-criteria`

Allows overriding the above values on a per-dependency basis.

```
[policy.foo]
dependency-criteria = { bar = [] }
notes = "bar is only used to implement a foo feature we never plan to enable."
```

Unlike `criteria` and `dev-criteria`, `dependency-criteria` may apply directly
to third-party crates (both `foo` and `bar` may be third-party in the above
example). Specifying `criteria` is disallowed for third-party crates because a
given third-party crate can often be used in multiple unrelated places in a
project's dependency graph. So in the above example, we want to exempt `bar`
from auditing insofar as it's used by `foo`, but not necessarily if it crops up
somewhere else.

Third-party crates with `dependency-criteria` must be associated with specific
versions in the policy table (see the description of policy table keys above).
Additionally, if a crate has any `dependency-criteria` specified and any version
exists as a third-party crate in the graph, all versions of the crate must be
explicitly specified in the policy table keys.

Defaults to the empty set and is not inherited.

#### `audit-as-crates-io`

Specifies whether first-party packages with this crate name should receive audit
enforcement as if they were fetched from crates.io. See [First-Party
Code](first-party-code.md) for more details.

#### `notes`

Free-form string for recording rationale or other relevant information.

### The `exemptions` Table

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
