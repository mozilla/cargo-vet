# Importing Audits

The fastest way to shrink the `unaudited` list is to pull in the audit sets from
other projects that you trust via the `imports` directive in `config.toml`.

## The `imports` directive

This directive allows you to virtually merge audit lists from other
projects into your own. This may or may not be a reciprocal relationship,
since it's fine to import audits from another party with a stricter audit policy,
but not the other way around.

For example:
```
imports = [
  "https://raw.githubusercontent.com/rust-lang/cargo-trust-store/audits.toml",
  "https://hg.example.org/example/raw-file/tip/audits.toml"
]
```

Upon invocation, `cargo vet` will fetch these audit files, merge them, and store
the resulting data in `imports.lock`. Similar to `cargo vendor`, passing
`--locked` will skip the fetch.

Note that this mechanism is not transitive — you can't directly import someone
else's list of imports. This is an intentional limitation which keeps trust
relationships direct and easy to reason about. That said, you can always inspect
the `config.toml` of other projects for inspiration, and explicitly adopt any
`imports` entries that meet your requirements.

## Multiple Repositories

The `imports` directive can also be used to coordinate audits across a single
organization with multiple repositories. There are two primary approaches:
* Record audits in a central repository, and have each repository reference that
  central audit set in its `config.toml`.
* Record audits in the repository where they're first needed, and have each
  repository reference each other repository.
