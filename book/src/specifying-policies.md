# Specifying Policies

By default, `cargo vet` checks all transitive dependencies of all top-level
crates against the following criteria on all-platforms:
* For regular dependencies: `safe-to-deploy`
* For dev-dependencies: `safe-to-run`
* For build-dependencies[^1]: `safe-to-deploy`

In some situations, you may be able to reduce your workload by encoding your
requirements more precisely. For example, your workspace might contain both a
production product and an internal tool, and you might decide that the
dependencies of the latter need only be `safe-to-run`.

If the default behavior works for you, there's no need to specify anything. If
you wish to encode policies such as the above, you can do so in
[config.toml](config.md#the-policy-table).

## Footnotes

[^1]: Strictly speaking, we want the build-dependencies themselves to be `safe-to-run`
and their contribution to the build (e.g., generated code) to be safe-to-deploy.
Rather than introduce separate criteria to handle this nuance explicitly,
cargo-vet bundles it into the [definition](built-in-criteria.md#safe-to-deploy)
of `safe-to-deploy`. This keeps things more simple and intuitive without
sacrificing much precision, since in practice it's generally quite clear whether
a crate is intended to operate at build time or at run time.
