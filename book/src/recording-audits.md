# Recording Audits

Audits of your project's dependencies performed by you or your teammates are
recorded in `audits.toml`. Note that these dependencies may have their own
`audits.toml` files if they also happen to use `cargo vet`, but these have no
effect on your project unless you explicitly import them in `config.toml`.

## `audits.toml`

Listing a crate in `audits.toml` means that the you've inspected it and
determined that it meets the specified criteria.

Each crate can have one or more audit entries, which support various fields.
Specifying a `version` means that the owner has audited that version in its
entirety. Specifying a `delta` means that the owner has audited the diff between
the two versions, and determined that the changes preserve the relevant
properties.

If, in the course of your auditing, you find a crate that does _not_ meet the
criteria, you can note this as well with `violation`.

A sample `audits.toml` looks like this:
```
[criteria]

...

[[audits.bar]]
version = "1.2.3"
who = "Alice Foo <alicefoo@example.com>"
criteria = "safe-to-deploy"

[[audits.bar]]
delta = "1.2.3 -> 1.2.4"
who = "Bob Bar <bobbar@example.com>""
criteria = "safe-to-deploy"

[[audits.bar]]
version = "2.1.3"
who = "Alice Foo <alicefoo@example.com>"
criteria = "safe-to-deploy"

[[audits.bar]]
delta = "2.1.3 -> 2.1.1"
who = "Alice Foo <alicefoo@example.com>"
criteria = "safe-to-deploy"

[[audits.baz]]
version = "0.2"
who = "Alice Foo <alicefoo@example.com>"
criteria = "safe-to-run"

[[audits.foo]]
version = "0.2.1 -> 0.3.1"
who = "Bob Bar <bobbar@example.com>"
criteria = "safe-to-deploy"

[[audits.malicious_crate]]
violation = "*"
who = "Bob Bar <bobbar@example.com>""
criteria = "safe-to-run"

[[audits.partially_vulnerable_crate]]
violation = ">=2.0, <2.3"
who = "Bob Bar <bobbar@example.com>"
criteria = "safe-to-deploy"
```

Exactly one of `version`, `delta`, or `violation` must be specified for each
entry.

The expectation is that this file should never be pruned unless a
previously-recorded entry is determined to have been erroneous. Even if the
owner no longer uses the specified crates, the audit records can still prove
useful to others in the ecosystem.

## The `exemptions` table in `config.toml`

This table enumerates the dependencies that have not been audited, but which the
project is nonetheless using. The structure is generally the same as the
`audits` table, with a [few differences](config.md#the-exemptions-table).
