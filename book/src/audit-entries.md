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
the dependency even if it's listed in the `unaudited` table.

## `criteria`

Specifies the relevant criteria for this audit. This field is required.

## `targets`

A string or array of strings specifying the targets for which this audit is
valid.

Unless otherwise specified, audit entries are assumed to apply to all platforms.
However, they can optionally be restricted to certain platforms (so that, for
example, an auditor can skim over complicated assembly code for a platform that
their project doesn't target).

The syntax for this field mirrors Cargo's syntax for [platform-specific
dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#platform-specific-dependencies).

## `who`

A string identifying the auditor. When invoking `cargo vet certify`, the
value is auto-populated from the global git config.

This field is optional, but encouraged for two reasons:
* It makes it easier to attribute audits at a glance, particularly for
  remotely-hosted audit files.
* It emphasizes to the author that they are signing off on having performed the
  audit.

## `notes`

An optional free-form string containing any information the auditor may wish to
record.

## `dependency_criteria`

An optional inline table specifying the criteria the vetting algorithm should
check for in a dependency subtree.

Ordinarily, when vetting a crate for criteria `foo`, `cargo vet` will
recursively vet each direct dependency for `foo` as well. This is usually what
you want, but occasionally you may wish to add or remove criteria for certain
subtrees.

For example, a dependency used to encrypt sensitive data might need review from
cryptography experts:

```
[audit.mynetworkingcrate]
version = '2.3.4'
dependency_criteria = { hmac: ['safe_to_deploy', 'crypto_reviewed'] }
```

Alternatively, a dependency might be used in a very limited way that allows you
to reduce the level of scrutiny. For example, a crate might import a sprawling
platform binding crate just to invoke one or two native functions:

```
[audit.foo]
version = '1.5.2'
dependency_criteria = { winapi: 'safe_to_run' }
notes = '''
  The winapi dependency is only used in a few places, and I have directly audited
  the parts of it that are used. As long as we ensure that minor updates don't
  include blatantly malicious code in the build script we should be fine.
  '''

```

This field only has an effect when the associated audit entry is actually used
in the recursive vetting algorithm. In the case where multiple entries are used
for a single crate, their `dependency_criteria` are unioned together.

These criteria propagate through the entire subtree unless inner branches
specify their own `dependency_criteria`.
