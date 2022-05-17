# Importing Audits

The fastest way to shrink the `unaudited` list is to pull in the audit sets from
other projects that you trust via `imports` directives in `config.toml`.  This
directive allows you to virtually merge audit lists from other projects into
your own:

```
[imports.foo]
url = "https://raw.githubusercontent.com/foo-team/foo/main/supply-chain/audits.toml"

[imports.bar]
url = "https://hg.bar.org/repo/raw-file/tip/supply-chain/audits.toml"
```
Upon invocation, `cargo vet` will fetch each url, extract the relevant data, and
store the information in `imports.lock`. Similar to `cargo vendor`, passing
`--locked` will skip the fetch.

Note that this mechanism is not transitive — you can't directly import someone
else's list of imports. This is an intentional limitation which keeps trust
relationships direct and easy to reason about. That said, you can always inspect
the `config.toml` of other projects for inspiration, and explicitly adopt any
`imports` entries that meet your requirements.

The [built-in criteria](built-in-criteria.md) have the same meaning across all
projects, so importing an audit for `safe-to-run` has the same effect as
appending that same audit to your own `audits.toml`. By default, custom criteria
defined in a foreign audit file exist in a private namespace and have no meaning
in the local project. However, they can be [mapped](config.md#criteria-map) as
desired to locally-defined criteria.
